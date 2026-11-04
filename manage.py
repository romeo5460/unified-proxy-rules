#!/usr/bin/env python3
"""Offline-first authoring; never writes to a client's configuration directory."""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

import yaml

ROOT = Path(__file__).resolve().parent
PRIVATE = ROOT / "private"
CACHE = ROOT / "cache"
BUILD = ROOT / "build"
APP = Path.home() / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev"


def stamp():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def private_dir(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def write(path, data, sensitive=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = data.encode() if isinstance(data, str) else data
    if path.exists():
        if path.read_bytes() == raw:
            return
        dest = PRIVATE / "generated-backups" / stamp() / path.relative_to(ROOT)
        private_dir(dest.parent)
        shutil.copyfile(path, dest)
        dest.chmod(0o600)
    fd, temp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        os.chmod(temp, 0o600 if sensitive else 0o644)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def dump(value):
    return yaml.safe_dump(value, allow_unicode=True, sort_keys=False)


def load_policy():
    p = json.loads((ROOT / "policy.json").read_text())
    stages = {"local", "media", "custom-proxy", "ai", "foreign", "custom-direct", "cn", "cn-ip", "final"}
    if len(p["order"]) != len(stages) or set(p["order"]) != stages:
        raise ValueError("order must contain every stage once")
    if p["order"][0] != "local" or p["order"][-1] != "final":
        raise ValueError("local must be first and final must be last")
    if p["order"].index("custom-proxy") > p["order"].index("cn"):
        raise ValueError("explicit proxy must precede China domains")
    for key in ["proxy_domains", "direct_domains", "local_domains"]:
        values = p[key]
        if len(values) != len(set(values)):
            raise ValueError("duplicate domains in " + key)
        for d in values:
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", d) or ".." in d:
                raise ValueError("invalid domain in " + key)
    if set(p["proxy_domains"]) & set(p["direct_domains"]):
        raise ValueError("identical domains in proxy and direct lists")
    for cidr in p["local_cidrs"]:
        ipaddress.ip_network(cidr)
    base = p["publish_base"]
    if base:
        u = urllib.parse.urlsplit(base)
        if u.scheme != "https" or not u.hostname or u.username or u.password or u.query or u.fragment:
            raise ValueError("publish_base must be a credential-free HTTPS directory URL")
    if not isinstance(p["interval"], int) or p["interval"] < 3600:
        raise ValueError("interval must be at least 3600 seconds")
    for source in p["upstreams"].values():
        u = urllib.parse.urlsplit(source["url"])
        if u.scheme != "https" or u.hostname != "raw.githubusercontent.com" or not u.path.startswith("/MetaCubeX/meta-rules-dat/") or u.query:
            raise ValueError("unexpected upstream source")
    return p


def import_mac():
    private_dir(PRIVATE)
    # Backup configuration and all enhancement files before extracting any nodes.
    backup = PRIVATE / "client-backups" / stamp()
    private_dir(backup)
    for name in ["profiles.yaml", "verge.yaml", "config.yaml", "clash-verge.yaml", "dns_config.yaml"]:
        src = APP / name
        if src.exists():
            shutil.copyfile(src, backup / name)
            (backup / name).chmod(0o600)
    shutil.copytree(APP / "profiles", backup / "profiles")
    for item in (backup / "profiles").rglob("*"):
        item.chmod(0o700 if item.is_dir() else 0o600)
    profiles = yaml.safe_load((backup / "profiles.yaml").read_text())
    current = next(x for x in profiles["items"] if x["uid"] == profiles["current"])
    config = yaml.safe_load((backup / "clash-verge.yaml").read_text())
    nodes = config.get("proxies", [])
    if not nodes or any(n.get("type") != "vless" for n in nodes):
        raise ValueError("expected existing VLESS nodes; inspect before import")
    local = {"source_profile": current["uid"], "proxies": nodes,
             "media_ip_rules": [x for x in config.get("rules", []) if x.startswith("IP-CIDR,") and x.endswith("/32,DIRECT,no-resolve")]}
    write(PRIVATE / "nodes.json", json.dumps(local, ensure_ascii=False, indent=2) + "\n", True)
    print("Client backup and local node extraction complete; nodes:", len(nodes))


def validate_payload(raw, behavior):
    if len(raw) > 20_000_000:
        raise ValueError("oversized rule set")
    d = yaml.safe_load(raw)
    if not isinstance(d, dict) or set(d) != {"payload"} or not isinstance(d["payload"], list) or not d["payload"]:
        raise ValueError("invalid rule-set payload")
    for item in d["payload"]:
        if not isinstance(item, str) or any(x in item for x in ["\n", ",", "http://", "https://"]):
            raise ValueError("unexpected rule entry")
        if behavior == "ipcidr":
            ipaddress.ip_network(item, strict=False)
        elif not re.fullmatch(r"[a-zA-Z0-9_.*+!\-]+", item):
            raise ValueError("unsupported domain-set syntax")
    return d


def fetch():
    p = load_policy()
    CACHE.mkdir(exist_ok=True)
    pending = {}
    lock = {"fetched_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "sources": {}}
    for name, spec in p["upstreams"].items():
        request = urllib.request.Request(spec["url"], headers={"User-Agent": "unified-proxy/1"})
        with urllib.request.urlopen(request, timeout=60) as r:
            raw = r.read(20_000_001)
        parsed = validate_payload(raw, spec["behavior"])
        pending[name] = raw
        lock["sources"][name] = {"url": spec["url"], "sha256": hashlib.sha256(raw).hexdigest(), "entries": len(parsed["payload"])}
        print("Fetched", name, "entries:", len(parsed["payload"]))
    # Commit only when every upstream has downloaded and validated.
    for name, raw in pending.items():
        write(CACHE / (name + ".yaml"), raw)
    write(CACHE / "sources.lock.json", json.dumps(lock, indent=2) + "\n")


def payloads(p):
    result = {"custom-proxy": {"payload": ["+." + x for x in p["proxy_domains"]]},
              "custom-direct": {"payload": ["+." + x for x in p["direct_domains"]]}}
    lock = json.loads((CACHE / "sources.lock.json").read_text())
    for name, spec in p["upstreams"].items():
        raw = (CACHE / (name + ".yaml")).read_bytes()
        if hashlib.sha256(raw).hexdigest() != lock["sources"][name]["sha256"] or spec["url"] != lock["sources"][name]["url"]:
            raise ValueError("cached source differs from lock; run fetch")
        result[name] = validate_payload(raw, spec["behavior"])
    return result


def local_rules(p):
    return (["DOMAIN-SUFFIX," + d + ",DIRECT" for d in p["local_domains"]] +
            [("IP-CIDR6," if ":" in c else "IP-CIDR,") + c + ",DIRECT,no-resolve" for c in p["local_cidrs"]])


def build(public_only=False):
    p = load_policy()
    sets = payloads(p)
    public = BUILD / "public"
    for name, content in sets.items():
        write(public / (name + ".yaml"), dump(content))
        # Shadowrocket-compatible domain/ip rule lists; activation awaits iPhone audit.
        lines = []
        for item in content["payload"]:
            if name == "cn-ip":
                lines.append(("IP-CIDR6," if ":" in item else "IP-CIDR,") + item + ",no-resolve")
            elif item.startswith("+."):
                lines.append("DOMAIN-SUFFIX," + item[2:])
            elif "*" in item or item.startswith("."):
                raise ValueError("unsupported Shadowrocket conversion; inspect upstream syntax")
            else:
                lines.append("DOMAIN," + item)
        write(public / (name + ".list"), "\n".join(lines) + "\n")
    manifest = {"version": p["version"], "files": {x.name: hashlib.sha256(x.read_bytes()).hexdigest() for x in sorted(public.iterdir()) if x.suffix in [".yaml", ".list"]}}
    write(public / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    write(public / "sources.lock.json", (CACHE / "sources.lock.json").read_bytes())
    if p['publish_base']:
        from shadowrocket import build as build_shadowrocket
        build_shadowrocket()
    if public_only:
        print("Credential-free rule artifacts generated.")
        return
    private_dir(PRIVATE)
    nodes = json.loads((PRIVATE / "nodes.json").read_text())
    names = [x["name"] for x in nodes["proxies"]]
    if p["default_node"] not in names:
        raise ValueError("default node is not present")
    names = [p["default_node"]] + [n for n in names if n != p["default_node"]]
    mac = BUILD / "mac"
    private_dir(mac)
    providers = {}
    for name, content in sets.items():
        path = mac / "rules" / (name + ".yaml")
        write(path, dump(content))
        entry = {"type": "inline", "behavior": "ipcidr" if name == "cn-ip" else "domain", "format": "yaml", "payload": content['payload']}
        # Default: download established upstream rules. Custom rules stay local until published.
        if name in p["upstreams"] or p["publish_base"]:
            entry.pop('payload')
            entry.update({"type": "http", "url": p["publish_base"].rstrip("/") + "/" + name + ".yaml" if p["publish_base"] else p["upstreams"][name]["url"], "interval": p["interval"], "proxy": "PROXY"})
            entry['path'] = './rule-providers/unified/' + name + '.yaml'
        providers[name] = entry
    stages = {"local": local_rules(p),
              "media": ["PROCESS-PATH," + x + ",DIRECT" for x in p["mac_direct_paths"]] + ["PROCESS-NAME," + x + ",DIRECT" for x in p["mac_direct_processes"]] + nodes["media_ip_rules"],
              "final": ["MATCH,PROXY"]}
    for name in sets:
        stages[name] = ["RULE-SET," + name + (",PROXY" if name in ["custom-proxy", "ai", "foreign"] else ",DIRECT") + (",no-resolve" if name == "cn-ip" else "")]
    dns_direct = ["https://dns.alidns.com/dns-query#DIRECT", "https://doh.pub/dns-query#DIRECT"]
    dns_proxy = ["https://1.1.1.1/dns-query#PROXY", "https://8.8.8.8/dns-query#PROXY"]
    dns_policy = {"+." + domain: "system" for domain in p["local_domains"]}
    for stage in p['order']:
        if stage in sets and stage != 'cn-ip':
            dns_policy['rule-set:' + stage] = dns_proxy if stage in ['custom-proxy', 'ai', 'foreign'] else dns_direct
    config = {"mode": "rule", "mixed-port": 7897, "allow-lan": False, "bind-address": "127.0.0.1", "log-level": "warning", "ipv6": False,
              "unified-delay": True, "tcp-concurrent": True, "find-process-mode": "always", "profile": {"store-selected": True},
              "tun": {"enable": False, "stack": "gvisor", "auto-route": True, "auto-detect-interface": True, "dns-hijack": ["any:53", "tcp://any:53"], "strict-route": False},
              "dns": {"enable": True, "listen": "127.0.0.1:1053", "ipv6": False, "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
                      "fake-ip-filter": ["localhost", "+.local", "+.lan", "+.home.arpa", "+.in-addr.arpa", "+.ip6.arpa", "+.msftconnecttest.com", "+.msftncsi.com"],
                      "respect-rules": True, "default-nameserver": ["223.5.5.5", "119.29.29.29"], "nameserver": dns_proxy,
                      "proxy-server-nameserver": dns_direct, "direct-nameserver": dns_direct, "direct-nameserver-follow-policy": True, "nameserver-policy": dns_policy},
              "proxies": nodes["proxies"], "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": names}],
              "rule-providers": providers, "rules": [r for name in p["order"] for r in stages[name]]}
    write(mac / "unified-mac.yaml", "# PRIVATE: contains node credentials. Do not upload.\n" + dump(config), True)
    config["tun"]["enable"] = True
    write(mac / "unified-mac-tun.yaml", "# PRIVATE: TUN candidate; application override may take precedence.\n" + dump(config), True)
    print("macOS profiles generated; nodes:", len(names), "; TUN activation has not been performed.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["import-mac", "fetch", "build", "public", "check"])
    args = parser.parse_args()
    if args.command == "import-mac": import_mac()
    elif args.command == "fetch": fetch()
    elif args.command in ["build", "public"]: build(args.command == "public")
    else:
        p = load_policy()
        payloads(p)
        print("Policy schema and cached source hashes verified.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Avoid exception text/tracebacks: parser and network errors may contain secrets.
        print("Operation failed (" + type(e).__name__ + "); no client configuration was overwritten.", file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
"""Build a rule-only native Shadowrocket config; never exports proxy credentials."""
import json
import manage as m


def build():
    p = m.load_policy()
    base = p['publish_base'].rstrip('/')
    if not base:
        raise ValueError('a real public rule-only HTTPS base is required')
    lines = ['# Unified routing; version ' + p['version'],
             '# Rules only. Uses the selected existing Shadowrocket node.',
             '[General]',
             'skip-proxy = localhost, *.local, *.lan, *.home.arpa, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16',
             'dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query',
             'direct-dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query',
             'fallback-dns-server = https://doh.pub/dns-query',
             'private-ip-answer = true', 'ipv6 = false', 'prefer-ipv6 = false', '', '[Rule]']
    for stage in p['order']:
        if stage == 'local': lines.extend(m.local_rules(p))
        elif stage == 'media':
            lines.append('# macOS process rules cannot identify iOS application traffic; no process rules copied.')
        elif stage == 'final': lines.append('FINAL,PROXY')
        else:
            action = 'PROXY' if stage in ['custom-proxy', 'ai', 'foreign'] else 'DIRECT'
            lines.append('RULE-SET,' + base + '/' + stage + '.list,' + action)
    lines += ['', '[Host]', 'localhost = 127.0.0.1', '*.local = server:system', '*.lan = server:system', '*.home.arpa = server:system']
    raw = '\n'.join(lines) + '\n'
    assert '[Proxy]' not in raw and '[Proxy Group]' not in raw
    m.write(m.BUILD / 'public/Unified-Shadowrocket.conf', raw)
    manifest_path = m.BUILD / 'public/manifest.json'
    manifest = json.loads(manifest_path.read_text())
    manifest['files']['Unified-Shadowrocket.conf'] = m.hashlib.sha256(raw.encode()).hexdigest()
    m.write(manifest_path, json.dumps(manifest, indent=2) + '\n')
    print('Rule-only Shadowrocket configuration generated; no nodes included.')


if __name__ == '__main__':
    try: build()
    except Exception as e:
        print('Shadowrocket build failed:', type(e).__name__)
        raise SystemExit(1)

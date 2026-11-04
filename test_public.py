"""CI checks requiring neither credentials nor a client installation."""
import hashlib
import json
import unittest
import manage as m


class PublicTests(unittest.TestCase):
    def test_confirmed_app_routes_in_phone_config(self):
        # Evaluate the actual published Shadowrocket rule order and complete sets.
        p = m.load_policy()
        sets = m.payloads(p)
        text = (m.BUILD / 'public/Unified-Shadowrocket.conf').read_text()
        section = text.split('[Rule]\n')[1].split('[Host]')[0]
        def matches(host, value):
            if value.startswith('+.'):
                return host == value[2:] or host.endswith('.' + value[2:])
            return host == value
        def route(host):
            for line in section.splitlines():
                if not line or line.startswith('#'): continue
                kind, *fields = line.split(',')
                if kind == 'FINAL': return fields[0]
                if kind == 'RULE-SET':
                    name = fields[0].rsplit('/', 1)[-1][:-5]
                    if name != 'cn-ip' and any(matches(host, v) for v in sets[name]['payload']): return fields[1]
                elif kind == 'DOMAIN-SUFFIX' and matches(host, '+.' + fields[0]): return fields[1]
            raise AssertionError('missing final policy')
        proxy = ['api.openai.com', 'gemini.google.com', 'api.x.ai', 'www.sigstick.com', 'api.vsco.co',
                 'www.facetuneapp.com', 'api.lightricks.com', 'www.upwork.com', 'store.steampowered.com',
                 'steamcommunity.com', 'dl.steam.clngaa.com', 'www.linkedin.com', 'mega.nz', 'www.notion.so',
                 'www.muse.ai', 'x.com', 'notebooklm.google.com']
        direct = ['music.apple.com', 'amp-api.music.apple.com', 'audio-ssl.itunes.apple.com',
                  'www.quark.cn', 'www.pixcakes.com', 'www.pixcookie.com', 'www.crossyroad.com',
                  'www.duolingo.com', 'sync.goodnotescloud.com', 'www.starbucks.com', 'weixin.qq.com', 'www.taobao.com']
        for host in proxy:
            with self.subTest(host=host): self.assertEqual(route(host), 'PROXY')
        for host in direct:
            with self.subTest(host=host): self.assertEqual(route(host), 'DIRECT')
        self.assertLess(section.index('/custom-direct.list,'), section.index('/foreign.list,'))

    def test_manifest_and_formats(self):
        p = m.load_policy()
        data = m.payloads(p)
        manifest = json.loads((m.BUILD / 'public/manifest.json').read_text())
        self.assertEqual(manifest['version'], p['version'])
        self.assertEqual(len(manifest['files']), 12 + bool(p['publish_base']))
        for name, digest in manifest['files'].items():
            raw = (m.BUILD / 'public' / name).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
            if name.endswith('.yaml'):
                key = name[:-5]
                m.validate_payload(raw, 'ipcidr' if key == 'cn-ip' else 'domain')
            elif name.endswith('.list'):
                for line in raw.decode().splitlines():
                    self.assertIn(line.split(',')[0], ['DOMAIN', 'DOMAIN-SUFFIX', 'IP-CIDR', 'IP-CIDR6'])
            else:
                text = raw.decode()
                self.assertNotIn('[Proxy]', text)
                self.assertNotIn('[Proxy Group]', text)
                self.assertIn('FINAL,PROXY', text)
                for stage in ['custom-proxy', 'ai', 'foreign', 'custom-direct', 'cn', 'cn-ip']:
                    self.assertIn('/' + stage + '.list,', text)
        self.assertGreater(len(data['cn']['payload']), 1000)
        self.assertGreater(len(data['ai']['payload']), 20)


if __name__ == '__main__': unittest.main(verbosity=2)

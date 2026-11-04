"""CI checks requiring neither credentials nor a client installation."""
import hashlib
import json
import unittest
import manage as m


class PublicTests(unittest.TestCase):
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

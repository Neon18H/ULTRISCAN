from django.test import SimpleTestCase

from integrations.parsers.nmap_parser import NmapXmlParser


class NmapParserTests(SimpleTestCase):
    def test_parse_basic_xml_with_scripts(self):
        xml = """<nmaprun><host><status state='up'/><address addr='10.0.0.1' addrtype='ipv4'/><ports><port protocol='tcp' portid='22'><state state='open'/><service name='ssh' product='OpenSSH' version='8.9' extrainfo='Ubuntu'/><script id='ssh-hostkey' output='2048 SHA256:abc'/></port></ports></host></nmaprun>"""
        parsed = NmapXmlParser().parse(xml)
        self.assertEqual(parsed.hosts[0].ip, '10.0.0.1')
        self.assertEqual(parsed.hosts[0].state, 'up')
        self.assertEqual(parsed.hosts[0].ports[0].service, 'ssh')
        self.assertEqual(parsed.hosts[0].ports[0].scripts[0].script_id, 'ssh-hostkey')

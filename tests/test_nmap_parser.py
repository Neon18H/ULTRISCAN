from django.test import SimpleTestCase

from integrations.nmap.parser import NmapXmlParser


class NmapParserTests(SimpleTestCase):
    def test_parse_basic_xml(self):
        xml = """<nmaprun><host><address addr='10.0.0.1'/><ports><port protocol='tcp' portid='22'><state state='open'/><service name='ssh' product='OpenSSH' version='8.9' extrainfo='Ubuntu'/></port></ports></host></nmaprun>"""
        parsed = NmapXmlParser().parse(xml)
        self.assertEqual(parsed.hosts[0].services[0].name, 'ssh')

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
        self.assertEqual(parsed.hosts[0].ports[0].product, 'OpenSSH')
        self.assertEqual(parsed.hosts[0].ports[0].version, '8.9')
        self.assertEqual(parsed.hosts[0].ports[0].extrainfo, 'Ubuntu')

    def test_parse_service_cpe_for_downstream_cve_correlation(self):
        xml = """<nmaprun><host><status state='up'/><address addr='10.0.0.5' addrtype='ipv4'/><ports><port protocol='tcp' portid='21'><state state='open'/><service name='ftp' product='vsftpd' version='3.0.5' cpe='cpe:/a:vsftpd:vsftpd:3.0.5'/></port></ports></host></nmaprun>"""
        parsed = NmapXmlParser().parse(xml)
        self.assertEqual(parsed.hosts[0].ports[0].cpe, 'cpe:/a:vsftpd:vsftpd:3.0.5')

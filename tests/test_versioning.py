from django.test import SimpleTestCase

from scans.services.versioning import normalize_version, parse_comparable_version


class VersioningTests(SimpleTestCase):
    def test_normalize_real_nmap_versions(self):
        self.assertEqual(normalize_version('9.6p1 Ubuntu 3ubuntu13.15'), '9.6.1')
        self.assertEqual(normalize_version('1.18.0-6ubuntu14.4'), '1.18.0')
        self.assertEqual(normalize_version('2.4.41 Ubuntu'), '2.4.41')

    def test_parse_comparable_version_handles_noise(self):
        self.assertEqual(parse_comparable_version('OpenSSH_9.6p1 Ubuntu 3ubuntu13.15'), (9, 6, 1))
        self.assertIsNone(parse_comparable_version('unknown-build'))

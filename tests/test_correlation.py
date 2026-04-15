from django.test import TestCase

from findings.services import _version_in_range


class CorrelationTests(TestCase):
    def test_version_range(self):
        self.assertTrue(_version_in_range('8.5', '7.0', '9.0'))
        self.assertFalse(_version_in_range('9.5', '7.0', '9.0'))

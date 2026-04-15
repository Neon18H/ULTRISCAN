from django.test import TestCase
from django.utils import timezone

from knowledge_base.integrations.nvd_sync import sync_nvd_vulnerabilities
from knowledge_base.models import ExternalAdvisory, ExternalAdvisoryReference


class NVDSyncTests(TestCase):
    def _payload(self):
        return {
            'cve': {
                'id': 'CVE-2099-0001',
                'published': '2026-04-14T10:00:00',
                'lastModified': '2026-04-14T11:00:00Z',
                'descriptions': [{'lang': 'en', 'value': 'Sample advisory'}],
                'references': [
                    {'url': ' https://example.com/a ', 'source': 'NVD', 'tags': ['Patch']},
                    {'url': 'https://example.com/a', 'source': 'NVD', 'tags': ['Patch']},
                    {'url': ''},
                    {'url': 'https://example.com/b', 'source': 'Vendor', 'tags': ['Vendor Advisory']},
                ],
                'weaknesses': [],
                'configurations': [],
                'metrics': {},
            }
        }

    def test_sync_nvd_is_idempotent_and_deduplicates_references(self):
        payload = self._payload()

        first_job = sync_nvd_vulnerabilities(command='sync_nvd_sample', vulnerabilities=[payload])
        second_job = sync_nvd_vulnerabilities(command='sync_nvd_sample', vulnerabilities=[payload])

        advisory = ExternalAdvisory.objects.get(cve_id='CVE-2099-0001')
        refs = ExternalAdvisoryReference.objects.filter(advisory=advisory).order_by('url')

        self.assertEqual(first_job.total_created, 1)
        self.assertEqual(first_job.total_updated, 0)
        self.assertEqual(second_job.total_created, 0)
        self.assertEqual(second_job.total_updated, 1)

        self.assertEqual(ExternalAdvisory.objects.count(), 1)
        self.assertEqual(refs.count(), 2)
        self.assertEqual(list(refs.values_list('url', flat=True)), ['https://example.com/a', 'https://example.com/b'])

    def test_sync_nvd_parses_datetimes_as_timezone_aware_utc(self):
        payload = self._payload()
        sync_nvd_vulnerabilities(command='sync_nvd_sample', vulnerabilities=[payload])

        advisory = ExternalAdvisory.objects.get(cve_id='CVE-2099-0001')

        self.assertTrue(timezone.is_aware(advisory.published_at))
        self.assertTrue(timezone.is_aware(advisory.last_modified_at))
        self.assertEqual(advisory.published_at.utcoffset().total_seconds(), 0)
        self.assertEqual(advisory.last_modified_at.utcoffset().total_seconds(), 0)

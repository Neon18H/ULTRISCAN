from django.test import TestCase
from django.utils import timezone
from django.core.management import call_command
from unittest.mock import patch

from knowledge_base.integrations.nvd_sync import sync_nvd_vulnerabilities
from knowledge_base.models import (
    AdvisorySyncJob,
    ExternalAdvisory,
    ExternalAdvisoryMetric,
    ExternalAdvisoryReference,
    ExternalAdvisoryWeakness,
)


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
                'metrics': {
                    'cvssMetricV31': [
                        {
                            'source': 'nvd@nist.gov',
                            'type': 'Primary',
                            'cvssData': {
                                'version': '3.1',
                                'baseScore': 7.5,
                                'baseSeverity': 'HIGH',
                                'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                            },
                            'exploitabilityScore': 3.9,
                            'impactScore': 3.6,
                        }
                    ]
                },
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

    def test_sync_nvd_deduplicates_weaknesses_and_metrics(self):
        payload = self._payload()
        payload['cve']['weaknesses'] = [
            {
                'source': 'NVD',
                'description': [
                    {'lang': 'en', 'value': 'CWE-79'},
                    {'lang': 'es', 'value': 'CWE-79'},
                ],
            }
        ]
        payload['cve']['metrics']['cvssMetricV31'].append(payload['cve']['metrics']['cvssMetricV31'][0])

        sync_nvd_vulnerabilities(command='sync_nvd_sample', vulnerabilities=[payload])
        advisory = ExternalAdvisory.objects.get(cve_id='CVE-2099-0001')

        self.assertEqual(ExternalAdvisoryWeakness.objects.filter(advisory=advisory).count(), 1)
        self.assertEqual(ExternalAdvisoryMetric.objects.filter(advisory=advisory).count(), 1)


    def test_sync_nvd_removes_preexisting_duplicate_weakness_rows(self):
        payload = self._payload()
        payload['cve']['weaknesses'] = [
            {
                'source': 'NVD',
                'description': [
                    {'lang': 'en', 'value': 'CWE-120'},
                ],
            }
        ]

        sync_nvd_vulnerabilities(command='sync_nvd_sample', vulnerabilities=[payload])
        advisory = ExternalAdvisory.objects.get(cve_id='CVE-2099-0001')

        ExternalAdvisoryWeakness.objects.create(
            advisory=advisory,
            source='legacy',
            cwe_id='CWE-120',
            description='legacy duplicate',
        )
        self.assertEqual(
            ExternalAdvisoryWeakness.objects.filter(advisory=advisory, cwe_id='CWE-120').count(),
            2,
        )

        sync_nvd_vulnerabilities(command='sync_nvd_sample', vulnerabilities=[payload])

        weaknesses = ExternalAdvisoryWeakness.objects.filter(advisory=advisory, cwe_id='CWE-120')
        self.assertEqual(weaknesses.count(), 1)
        self.assertEqual(weaknesses.first().source, 'NVD')

    @patch('knowledge_base.management.commands.sync_nvd_recent.sync_nvd_vulnerabilities')
    @patch('knowledge_base.management.commands.sync_nvd_recent.NVDClient.iter_cves')
    def test_sync_nvd_recent_reuses_last_successful_window(self, mock_iter_cves, mock_sync):
        now = timezone.now()
        AdvisorySyncJob.objects.create(
            source=ExternalAdvisory.Source.NVD,
            command='sync_nvd_recent',
            status=AdvisorySyncJob.Status.SUCCEEDED,
            finished_at=now,
            filters={'lastModStartDate': '2026-04-10T10:00:00Z'},
        )
        mock_iter_cves.return_value = []
        mock_sync.return_value = AdvisorySyncJob(
            total_fetched=0,
            total_created=0,
            total_updated=0,
        )

        call_command('sync_nvd_recent', hours=48)

        called_filters = mock_iter_cves.call_args.kwargs
        self.assertEqual(called_filters['lastModStartDate'], now.isoformat(timespec='seconds').replace('+00:00', 'Z'))
        self.assertIn('lastModEndDate', called_filters)

    @patch('knowledge_base.management.commands.sync_nvd_recent.sync_nvd_vulnerabilities')
    @patch('knowledge_base.management.commands.sync_nvd_recent.NVDClient.iter_cves')
    def test_sync_nvd_recent_can_force_hours_window(self, mock_iter_cves, mock_sync):
        now = timezone.now()
        AdvisorySyncJob.objects.create(
            source=ExternalAdvisory.Source.NVD,
            command='sync_nvd_recent',
            status=AdvisorySyncJob.Status.SUCCEEDED,
            finished_at=now,
        )
        mock_iter_cves.return_value = []
        mock_sync.return_value = AdvisorySyncJob(total_fetched=0, total_created=0, total_updated=0)

        call_command('sync_nvd_recent', hours=24, force_hours_window=True)

        called_filters = mock_iter_cves.call_args.kwargs
        self.assertNotEqual(called_filters['lastModStartDate'], now.isoformat(timespec='seconds').replace('+00:00', 'Z'))

    def test_sync_nvd_parses_datetimes_as_timezone_aware_utc(self):
        payload = self._payload()
        sync_nvd_vulnerabilities(command='sync_nvd_sample', vulnerabilities=[payload])

        advisory = ExternalAdvisory.objects.get(cve_id='CVE-2099-0001')

        self.assertTrue(timezone.is_aware(advisory.published_at))
        self.assertTrue(timezone.is_aware(advisory.last_modified_at))
        self.assertEqual(advisory.published_at.utcoffset().total_seconds(), 0)
        self.assertEqual(advisory.last_modified_at.utcoffset().total_seconds(), 0)

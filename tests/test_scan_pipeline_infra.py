from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from accounts.models import Organization
from assets.models import Asset
from integrations.runners.nmap_runner import NmapRunResult
from scan_profiles.models import ScanProfile
from scans.models import ScanExecution
from scans.services.scan_pipeline import ScanPipelineExecutionError, ScanPipelineService


class InfraScanPipelineTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(username='infra-pipeline', email='infra-pipeline@example.com', password='test12345')
        self.org = Organization.objects.create(name='Infra Pipeline Org', slug='infra-pipeline-org')
        self.asset = Asset.objects.create(organization=self.org, name='Infra Host', asset_type='ip', value='10.0.0.8')
        self.profile = ScanProfile.objects.create(organization=self.org, name='discovery')

    @patch('scans.services.scan_pipeline.NmapRunner.run')
    def test_timeout_with_partial_xml_is_persisted(self, mocked_run):
        mocked_run.return_value = NmapRunResult(
            command='nmap -oX - -sT -Pn -n --top-ports 1000 10.0.0.8',
            return_code=124,
            stdout=(
                '<nmaprun><host><status state="up"/>'
                '<address addr="10.0.0.8" addrtype="ipv4"/>'
                '<ports><port protocol="tcp" portid="80"><state state="open"/>'
                '<service name="http" product="nginx" version="1.24"/></port></ports>'
                '</host>'
            ),
            stderr='Nmap scan timed out after 120 seconds and output may be truncated.',
            xml_output=(
                '<nmaprun><host><status state="up"/>'
                '<address addr="10.0.0.8" addrtype="ipv4"/>'
                '<ports><port protocol="tcp" portid="80"><state state="open"/>'
                '<service name="http" product="nginx" version="1.24"/></port></ports>'
                '</host>'
            ),
            metadata={'timed_out': True, 'timeout_seconds': 120, 'profile': 'discovery'},
        )
        scan = ScanExecution.objects.create(
            organization=self.org,
            asset=self.asset,
            profile=self.profile,
            launched_by=self.user,
            engine_metadata={'requested_scan_type': 'nmap_discovery'},
        )

        result = ScanPipelineService().execute(scan)

        self.assertEqual(result.summary['hosts'], 1)
        self.assertTrue(result.summary['partial_result'])
        self.assertEqual(scan.raw_evidences.count(), 1)
        self.assertEqual(scan.service_findings.count(), 1)
        self.assertTrue(result.engine_metadata['modules']['nmap']['parse']['recovered_partial_xml'])

    @patch('scans.services.scan_pipeline.NmapRunner.run')
    def test_timeout_without_partial_xml_raises_non_retryable(self, mocked_run):
        mocked_run.return_value = NmapRunResult(
            command='nmap -oX - -sT -Pn -n --top-ports 1000 10.0.0.8',
            return_code=124,
            stdout='',
            stderr='Nmap scan timed out after 120 seconds and output may be truncated.',
            xml_output='',
            metadata={'timed_out': True, 'timeout_seconds': 120, 'profile': 'discovery'},
        )
        scan = ScanExecution.objects.create(
            organization=self.org,
            asset=self.asset,
            profile=self.profile,
            launched_by=self.user,
            engine_metadata={'requested_scan_type': 'nmap_discovery'},
        )

        with self.assertRaises(ScanPipelineExecutionError) as exc:
            ScanPipelineService().execute(scan)

        self.assertFalse(exc.exception.retryable)
        self.assertEqual(exc.exception.reason, 'nmap_timeout')

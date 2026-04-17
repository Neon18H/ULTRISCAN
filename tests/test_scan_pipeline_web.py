from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from accounts.models import Organization
from assets.models import Asset
from scan_profiles.models import ScanProfile
from scans.engines.tooling import ToolExecutionResult
from scans.models import ScanExecution
from scans.services.scan_pipeline import ScanPipelineExecutionError, ScanPipelineService


class WebScanPipelineTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(username='web-pipeline', email='web-pipeline@example.com', password='test12345')
        self.org = Organization.objects.create(name='Web Pipeline Org', slug='web-pipeline-org')
        self.asset = Asset.objects.create(organization=self.org, name='Web Target', asset_type='url', value='https://example.com')
        self.profile = ScanProfile.objects.create(organization=self.org, name='web_basic')

    @patch('scans.services.scan_pipeline.ExternalToolRunner.run')
    def test_web_basic_degrades_when_nuclei_is_missing(self, mocked_run):
        def tool_result(tool, args, timeout=None):
            if tool == 'whatweb':
                return ToolExecutionResult(
                    tool=tool,
                    command='whatweb --log-json=- https://example.com',
                    return_code=0,
                    stdout='[{"plugins":{"WordPress":{},"HTTPServer":{"Server":"nginx"}}}]',
                    stderr='',
                )
            if tool == 'gobuster':
                return ToolExecutionResult(
                    tool=tool,
                    command='gobuster dir -u https://example.com ...',
                    return_code=0,
                    stdout='{"path":"/admin","status":200}\n',
                    stderr='',
                )
            if tool == 'nuclei':
                return ToolExecutionResult(
                    tool=tool,
                    command='nuclei -u https://example.com -jsonl -silent',
                    return_code=127,
                    stdout='',
                    stderr='Binary nuclei not found in PATH',
                    missing_binary=True,
                )
            if tool == 'nikto':
                return ToolExecutionResult(
                    tool=tool,
                    command='nikto -h https://example.com -Format txt',
                    return_code=0,
                    stdout='+ Server may leak x-powered-by header',
                    stderr='',
                )
            return ToolExecutionResult(tool=tool, command=tool, return_code=127, stdout='', stderr='missing', missing_binary=True)

        mocked_run.side_effect = tool_result
        scan = ScanExecution.objects.create(
            organization=self.org,
            asset=self.asset,
            profile=self.profile,
            launched_by=self.user,
            engine_metadata={'requested_scan_type': 'web_basic'},
        )

        result = ScanPipelineService().execute(scan)

        self.assertEqual(result.summary['category'], 'web')
        self.assertIn('Binary nuclei no disponible en worker.', result.summary['warnings'])
        self.assertIn('nikto', result.summary['tools_executed'])
        self.assertEqual(result.summary['endpoints_count'], 1)
        self.assertGreaterEqual(result.summary['vulnerabilities_count'], 1)
        self.assertTrue(result.summary['partial_result'])
        self.assertEqual(scan.raw_evidences.filter(source='whatweb').count(), 1)

    @patch('scans.services.scan_pipeline.ExternalToolRunner.run')
    def test_scan_fails_without_any_available_web_tool(self, mocked_run):
        mocked_run.return_value = ToolExecutionResult(
            tool='missing',
            command='missing',
            return_code=127,
            stdout='',
            stderr='Binary not found',
            missing_binary=True,
        )
        scan = ScanExecution.objects.create(
            organization=self.org,
            asset=self.asset,
            profile=self.profile,
            launched_by=self.user,
            engine_metadata={'requested_scan_type': 'web_basic'},
        )

        with self.assertRaises(ScanPipelineExecutionError) as exc:
            ScanPipelineService().execute(scan)

        self.assertFalse(exc.exception.retryable)
        self.assertEqual(exc.exception.reason, 'web_no_tools_available')

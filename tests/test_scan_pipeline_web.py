from unittest.mock import patch
from pathlib import Path

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
        self._target_patch = patch(
            'scans.services.scan_pipeline.ScanPipelineService._resolve_web_target',
            return_value=(
                'https://example.com',
                {'ok': True, 'status_code': 200, 'headers': {'Server': 'nginx'}, 'command': 'HTTP GET https://example.com'},
            ),
        )
        self._templates_patch = patch(
            'scans.services.scan_pipeline.ScanPipelineService._resolve_nuclei_templates',
            return_value=Path('/tmp/nuclei-templates'),
        )
        self._wordlist_patch = patch(
            'scans.services.scan_pipeline.ScanPipelineService._resolve_wordlist',
            return_value=('/tmp/common.txt', ''),
        )
        self._target_patch.start()
        self._templates_patch.start()
        self._wordlist_patch.start()

    def tearDown(self):
        self._wordlist_patch.stop()
        self._templates_patch.stop()
        self._target_patch.stop()
        super().tearDown()

    @patch('scans.services.scan_pipeline.ExternalToolRunner.run')
    @patch('scans.services.scan_pipeline.ExternalToolRunner.is_available')
    def test_web_basic_degrades_when_nuclei_is_missing(self, mocked_is_available, mocked_run):
        def tool_available(tool):
            return tool != 'nuclei'

        mocked_is_available.side_effect = tool_available

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
        self.assertTrue(result.summary['dependency_checks']['whatweb']['available'])
        self.assertFalse(result.summary['dependency_checks']['nuclei']['available'])
        self.assertTrue(result.summary['dependency_checks']['nikto']['available'])
        self.assertEqual(result.summary['endpoints_count'], 1)
        self.assertGreaterEqual(result.summary['vulnerabilities_count'], 1)
        self.assertTrue(result.summary['partial_result'])
        self.assertEqual(scan.raw_evidences.filter(source='whatweb').count(), 1)

    @patch('scans.services.scan_pipeline.ExternalToolRunner.run')
    @patch('scans.services.scan_pipeline.ExternalToolRunner.is_available')
    def test_scan_returns_partial_result_without_any_available_web_tool(self, mocked_is_available, mocked_run):
        mocked_is_available.return_value = False
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

        result = ScanPipelineService().execute(scan)
        self.assertEqual(result.summary['category'], 'web')
        self.assertIn(
            'No hubo herramientas externas exitosas; se devuelve resultado parcial usando HTTP probe/headers.',
            result.summary['warnings'],
        )
        self.assertTrue(result.summary['partial_result'])

    @patch('scans.services.scan_pipeline.ExternalToolRunner.run')
    @patch('scans.services.scan_pipeline.ExternalToolRunner.is_available')
    def test_web_basic_warns_but_continues_when_nikto_missing(self, mocked_is_available, mocked_run):
        def tool_available(tool):
            return tool != 'nikto'

        mocked_is_available.side_effect = tool_available

        def tool_result(tool, args, timeout=None):
            if tool == 'whatweb':
                return ToolExecutionResult(
                    tool=tool,
                    command='whatweb --log-json=- https://example.com',
                    return_code=0,
                    stdout='[{"plugins":{"HTTPServer":{"Server":"nginx"}}}]',
                    stderr='',
                )
            if tool == 'gobuster':
                return ToolExecutionResult(
                    tool=tool,
                    command='gobuster dir -u https://example.com ...',
                    return_code=0,
                    stdout='{"path":"/health","status":200}\n',
                    stderr='',
                )
            if tool == 'nuclei':
                return ToolExecutionResult(
                    tool=tool,
                    command='nuclei -u https://example.com -jsonl -silent',
                    return_code=0,
                    stdout='',
                    stderr='',
                )
            if tool == 'nikto':
                return ToolExecutionResult(
                    tool=tool,
                    command='nikto -h https://example.com -Format txt',
                    return_code=127,
                    stdout='',
                    stderr='Binary nikto not found in PATH',
                    missing_binary=True,
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
        self.assertIn('Nikto no disponible: se omite escaneo nikto (opcional).', result.summary['warnings'])
        self.assertIn('Binary nikto no disponible en worker.', result.summary['warnings'])
        self.assertNotIn('nikto', result.summary['tools_executed'])
        self.assertIn({'tool': 'nikto', 'reason': 'missing_binary', 'required': False}, result.summary['tools_skipped'])
        self.assertFalse(result.summary['dependency_checks']['nikto']['available'])
        self.assertGreaterEqual(result.summary['endpoints_count'], 1)

    @patch('scans.services.scan_pipeline.ExternalToolRunner.run')
    @patch('scans.services.scan_pipeline.ExternalToolRunner.is_available')
    def test_web_wordpress_continues_without_wpscan_binary(self, mocked_is_available, mocked_run):
        def tool_available(tool):
            return tool != 'wpscan'

        mocked_is_available.side_effect = tool_available

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
                    stdout='{"path":"/wp-admin","status":200}\n',
                    stderr='',
                )
            if tool == 'nuclei':
                return ToolExecutionResult(
                    tool=tool,
                    command='nuclei -u https://example.com -jsonl -silent',
                    return_code=0,
                    stdout='',
                    stderr='',
                )
            if tool == 'nikto':
                return ToolExecutionResult(
                    tool=tool,
                    command='nikto -h https://example.com -Format txt',
                    return_code=0,
                    stdout='',
                    stderr='',
                )
            if tool == 'wpscan':
                return ToolExecutionResult(
                    tool=tool,
                    command='wpscan --url https://example.com --format json --no-update',
                    return_code=127,
                    stdout='',
                    stderr='Binary wpscan not found in PATH',
                    missing_binary=True,
                )
            return ToolExecutionResult(tool=tool, command=tool, return_code=127, stdout='', stderr='missing', missing_binary=True)

        mocked_run.side_effect = tool_result
        scan = ScanExecution.objects.create(
            organization=self.org,
            asset=self.asset,
            profile=self.profile,
            launched_by=self.user,
            engine_metadata={'requested_scan_type': 'web_wordpress'},
        )

        result = ScanPipelineService().execute(scan)

        self.assertEqual(result.summary['category'], 'web')
        self.assertEqual(result.summary['cms'], 'wordpress')
        self.assertIn('WordPress detectado, pero WPScan no está disponible; se omite el escaneo específico de WordPress.', result.summary['warnings'])
        self.assertIn('Binary wpscan no disponible en worker.', result.summary['warnings'])
        self.assertIn({'tool': 'wpscan', 'reason': 'missing_binary', 'required': True}, result.summary['tools_skipped'])
        self.assertNotIn('wpscan', result.summary['tools_executed'])
        self.assertIn('whatweb', result.summary['tools_available'])
        self.assertNotIn('wpscan', result.summary['tools_available'])

    @patch('scans.services.scan_pipeline.ScanPipelineService._probe_http_target')
    def test_target_normalization_without_scheme_prefers_https(self, mocked_probe):
        mocked_probe.side_effect = [
            {'ok': True, 'status_code': 200, 'headers': {'Server': 'nginx'}, 'command': 'HTTP HEAD https://example.org'},
        ]
        service = ScanPipelineService()

        normalized, probe = service._resolve_web_target('example.org')

        self.assertEqual(normalized, 'https://example.org')
        self.assertTrue(probe['ok'])

    @patch('scans.services.scan_pipeline.ExternalToolRunner.is_available', return_value=True)
    @patch('scans.services.scan_pipeline.ScanPipelineService._resolve_web_target')
    def test_web_scan_fails_early_when_target_is_unreachable(self, mocked_resolve_target, mocked_is_available):
        mocked_resolve_target.return_value = (
            'https://down.example.org',
            {'ok': False, 'status_code': None, 'headers': {}, 'error': 'timeout', 'command': 'HTTP GET'},
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

        self.assertEqual(exc.exception.reason, 'web_target_unreachable')

    @patch('scans.services.scan_pipeline.ScanPipelineService._resolve_wordlist', return_value=(None, 'missing wordlist'))
    @patch('scans.services.scan_pipeline.ExternalToolRunner.run')
    @patch('scans.services.scan_pipeline.ExternalToolRunner.is_available')
    def test_web_scan_skips_gobuster_when_wordlist_missing(self, mocked_is_available, mocked_run, _mocked_wordlist):
        mocked_is_available.return_value = True

        def tool_result(tool, args, timeout=None):
            if tool == 'whatweb':
                return ToolExecutionResult(
                    tool=tool,
                    command='whatweb --log-json=- https://example.com',
                    return_code=0,
                    stdout='[{"plugins":{"HTTPServer":{"Server":"nginx"}}}]',
                    stderr='',
                )
            if tool == 'nuclei':
                return ToolExecutionResult(
                    tool=tool,
                    command='nuclei -u https://example.com -jsonl -silent -t /tmp/nuclei-templates',
                    return_code=0,
                    stdout='',
                    stderr='',
                )
            if tool == 'nikto':
                return ToolExecutionResult(
                    tool=tool,
                    command='nikto -h https://example.com -Format txt',
                    return_code=0,
                    stdout='',
                    stderr='',
                )
            return ToolExecutionResult(tool=tool, command=tool, return_code=0, stdout='', stderr='')

        mocked_run.side_effect = tool_result
        scan = ScanExecution.objects.create(
            organization=self.org,
            asset=self.asset,
            profile=self.profile,
            launched_by=self.user,
            engine_metadata={'requested_scan_type': 'web_basic'},
        )

        result = ScanPipelineService().execute(scan)

        self.assertIn({'tool': 'gobuster', 'reason': 'missing_wordlist', 'required': False}, result.summary['tools_skipped'])
        self.assertIn('Se omite gobuster: no se encontró wordlist para enumeración.', result.summary['warnings'])
        self.assertNotIn('gobuster', result.summary['tools_executed'])

    @patch('scans.services.scan_pipeline.ExternalToolRunner.run')
    @patch('scans.services.scan_pipeline.ExternalToolRunner.is_available')
    def test_web_scan_interprets_http_headers(self, mocked_is_available, mocked_run):
        mocked_is_available.return_value = True

        def tool_result(tool, args, timeout=None):
            if tool == 'whatweb':
                return ToolExecutionResult(
                    tool=tool,
                    command='whatweb --log-json=- https://example.com',
                    return_code=0,
                    stdout='[{"plugins":{"HTTPServer":{"Server":"nginx"},"X-Powered-By":{"string":["PHP/8.2"]}}}]',
                    stderr='',
                )
            if tool == 'gobuster':
                return ToolExecutionResult(
                    tool=tool,
                    command='gobuster dir -u https://example.com ...',
                    return_code=0,
                    stdout='',
                    stderr='',
                )
            if tool == 'nuclei':
                return ToolExecutionResult(
                    tool=tool,
                    command='nuclei -u https://example.com -jsonl -silent',
                    return_code=0,
                    stdout='',
                    stderr='',
                )
            if tool == 'nikto':
                return ToolExecutionResult(
                    tool=tool,
                    command='nikto -h https://example.com -Format txt',
                    return_code=0,
                    stdout='',
                    stderr='',
                )
            return ToolExecutionResult(tool=tool, command=tool, return_code=0, stdout='', stderr='')

        mocked_run.side_effect = tool_result
        scan = ScanExecution.objects.create(
            organization=self.org,
            asset=self.asset,
            profile=self.profile,
            launched_by=self.user,
            engine_metadata={'requested_scan_type': 'web_basic'},
        )

        result = ScanPipelineService().execute(scan)

        interpreted_headers = result.engine_metadata['structured_results']['interpreted_headers']
        lookup = {row['header']: row['status'] for row in interpreted_headers}
        self.assertEqual(lookup.get('server'), 'WARNING')
        self.assertEqual(lookup.get('x-frame-options'), 'WARNING')
        self.assertIn('tools', result.engine_metadata['structured_results'])

    @patch('scans.services.scan_pipeline.ExternalToolRunner.run')
    @patch('scans.services.scan_pipeline.ExternalToolRunner.is_available')
    def test_gobuster_failure_falls_back_to_ffuf(self, mocked_is_available, mocked_run):
        def tool_available(_tool):
            return True

        mocked_is_available.side_effect = tool_available

        def tool_result(tool, args, timeout=None):
            if tool == 'whatweb':
                return ToolExecutionResult(
                    tool=tool,
                    command='whatweb --log-json=- https://example.com',
                    return_code=0,
                    stdout='[{"plugins":{"HTTPServer":{"string":["nginx"]}}}]',
                    stderr='',
                )
            if tool == 'gobuster':
                return ToolExecutionResult(
                    tool=tool,
                    command='gobuster dir -u https://example.com ...',
                    return_code=1,
                    stdout='',
                    stderr='Error: the server returns a status code that matches the provided options',
                )
            if tool == 'ffuf':
                return ToolExecutionResult(
                    tool=tool,
                    command='ffuf -u https://example.com/FUZZ -w /tmp/common.txt -json',
                    return_code=0,
                    stdout='{"url":"https://example.com/admin","status":200}\n',
                    stderr='',
                )
            return ToolExecutionResult(tool=tool, command=tool, return_code=0, stdout='', stderr='')

        mocked_run.side_effect = tool_result
        scan = ScanExecution.objects.create(
            organization=self.org,
            asset=self.asset,
            profile=self.profile,
            launched_by=self.user,
            engine_metadata={'requested_scan_type': 'web_basic'},
        )

        result = ScanPipelineService().execute(scan)

        self.assertIn('gobuster terminó con código 1.', ' '.join(result.summary['warnings']))
        self.assertIn('ffuf', result.summary['tools_executed'])
        self.assertGreaterEqual(result.summary['endpoints_count'], 1)

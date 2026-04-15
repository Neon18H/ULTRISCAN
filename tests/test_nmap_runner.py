from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from integrations.runners.nmap_runner import NmapRunner
from subprocess import TimeoutExpired


class NmapRunnerTests(SimpleTestCase):
    @patch('integrations.runners.nmap_runner.subprocess.run')
    def test_run_builds_unprivileged_discovery_command(self, mocked_run):
        mocked_run.return_value = SimpleNamespace(returncode=0, stdout='<nmaprun></nmaprun>', stderr='')

        result = NmapRunner().run('192.168.1.10', 'discovery')

        self.assertIn('-sT', result.command)
        self.assertIn('-Pn', result.command)
        self.assertIn('-n', result.command)
        self.assertIn('--unprivileged', result.command)
        self.assertIn('192.168.1.10', result.command)
        self.assertFalse(result.metadata['fallback_used'])

    @patch('integrations.runners.nmap_runner.subprocess.run')
    def test_run_fallbacks_on_raw_socket_errors(self, mocked_run):
        mocked_run.side_effect = [
            SimpleNamespace(returncode=1, stdout='', stderr="Couldn't open a raw socket. Error: Operation not permitted (1)"),
            SimpleNamespace(returncode=0, stdout='<nmaprun></nmaprun>', stderr=''),
        ]

        result = NmapRunner().run('10.0.0.8', 'full_tcp_safe')

        self.assertEqual(result.return_code, 0)
        self.assertTrue(result.metadata['fallback_used'])
        self.assertEqual(result.metadata['mode'], 'fallback_unprivileged')
        self.assertIn('initial_command', result.metadata)
        self.assertEqual(mocked_run.call_count, 2)

    @patch('integrations.runners.nmap_runner.subprocess.run')
    def test_full_tcp_safe_uses_top_ports_1000(self, mocked_run):
        mocked_run.return_value = SimpleNamespace(returncode=0, stdout='<nmaprun></nmaprun>', stderr='')

        result = NmapRunner().run('10.0.0.8', 'full_tcp_safe')

        self.assertIn('--top-ports 1000', result.command)
        self.assertNotIn('-p-', result.command)

    @patch('integrations.runners.nmap_runner.subprocess.run')
    def test_timeout_sets_metadata_and_truncation(self, mocked_run):
        mocked_run.side_effect = TimeoutExpired(
            cmd=['nmap'],
            timeout=240,
            output='<nmaprun>',
            stderr='',
        )

        result = NmapRunner().run('10.0.0.8', 'discovery')

        self.assertEqual(result.return_code, 124)
        self.assertTrue(result.metadata['timed_out'])
        self.assertTrue(result.metadata['scan_truncated'])
        self.assertIn('timed out after 240 seconds', result.stderr)

    def test_rejects_invalid_target(self):
        with self.assertRaises(ValueError):
            NmapRunner().run('bad target; rm -rf /', 'discovery')

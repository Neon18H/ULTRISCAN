from unittest.mock import patch

from django.test import SimpleTestCase

from integrations.runners.nmap_runner import NmapRunner


class NmapRunnerTests(SimpleTestCase):
    @patch('integrations.runners.nmap_runner.subprocess.run')
    def test_run_builds_safe_command(self, mocked_run):
        mocked_run.return_value.returncode = 0
        mocked_run.return_value.stdout = '<nmaprun></nmaprun>'
        mocked_run.return_value.stderr = ''

        result = NmapRunner().run('192.168.1.10', 'discovery')

        self.assertIn('-oX -', result.command)
        self.assertIn('192.168.1.10', result.command)

    def test_rejects_invalid_target(self):
        with self.assertRaises(ValueError):
            NmapRunner().run('bad target; rm -rf /', 'discovery')

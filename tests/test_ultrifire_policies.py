from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase, override_settings

from ultrifire.services import handle_command, list_policies, validate_policy


class UltriFirePolicyServiceTests(SimpleTestCase):
    def test_inbound_publish_policy_is_validated_previewed_and_safe_apply_blocked(self):
        payload = {
            'name': 'Publish web app',
            'enabled': True,
            'policy_type': 'inbound_publish',
            'provider': 'aws',
            'cloud_resource': {
                'provider': 'aws',
                'resource_type': 'ec2',
                'name': 'web-app-01',
                'private_ip': '10.0.10.50',
                'public_ip': None,
                'region': 'us-east-1',
                'logo': 'aws',
            },
            'inbound_interface': 'wan',
            'public_address': 'wan_address',
            'public_port': '443',
            'backend_ip': '10.0.10.50',
            'backend_port': '443',
            'protocol': 'tcp',
            'allowed_sources': ['any'],
            'nat_enabled': True,
            'create_firewall_pass_rule': True,
            'description': 'Publicar app web EC2 detrás del firewall',
        }
        with TemporaryDirectory() as temp_dir, override_settings(BASE_DIR=Path(temp_dir)):
            create = handle_command('firewall.policy.create', payload, safe_mode=True)
            self.assertTrue(create['ok'])
            self.assertFalse(create['applied'])
            self.assertEqual(create['policy']['policy_type'], 'inbound_publish')

            policies = handle_command('firewall.policies.list', safe_mode=True)
            self.assertEqual(len(policies['policies']), 1)

            preview = handle_command('firewall.policy.preview', {'policy_id': create['policy']['id']}, safe_mode=True)
            self.assertEqual(preview['preview']['nat']['type'], 'port_forward')
            self.assertIn('Internet', preview['preview']['risks'][0])

            apply = handle_command('firewall.policy.apply', {'policy_id': create['policy']['id']}, safe_mode=True)
            self.assertFalse(apply['applied'])
            self.assertEqual(apply['message'], 'safe_mode activo, aplicación real bloqueada')

    def test_outbound_interzone_and_blocklist_validation(self):
        outbound = validate_policy({
            'name': 'LAN web out',
            'policy_type': 'outbound_allow',
            'inbound_interface': 'lan',
            'source': '10.0.10.0/24',
            'destination': 'any',
            'protocol': 'tcp',
            'destination_port': '443',
        })
        self.assertEqual(outbound['action'], 'pass')

        interzone = validate_policy({
            'name': 'VPN to RDP',
            'policy_type': 'interzone',
            'source_zone': 'vpn',
            'destination_zone': 'lan',
            'source': '10.8.0.0/24',
            'destination': '10.0.10.0/24',
            'protocol': 'tcp',
            'destination_port': '3389',
            'action': 'pass',
        })
        self.assertEqual(interzone['destination_zone'], 'lan')

        blocklist = validate_policy({
            'name': 'Block bad origin',
            'policy_type': 'blocklist',
            'inbound_interface': 'wan',
            'source': '203.0.113.10',
            'destination': 'any',
            'protocol': 'any',
            'reason': 'Abuse source',
        })
        self.assertEqual(blocklist['action'], 'block')

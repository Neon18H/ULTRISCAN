from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from accounts.models import Organization
from assets.models import Asset
from scan_profiles.models import ScanProfile
from scans.models import ScanExecution
from scans.tasks import run_scan_task


class ScanTaskDispatchTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(username='dispatch', email='dispatch@example.com', password='test12345')
        self.org = Organization.objects.create(name='Dispatch Org', slug='dispatch-org')
        self.asset = Asset.objects.create(organization=self.org, name='Web', asset_type='url', value='https://example.com')
        self.profile = ScanProfile.objects.create(organization=self.org, name='web_basic')

    @patch('scans.tasks.scan_wordpress_task.delay')
    @patch('scans.tasks.scan_web_task.delay')
    @patch('scans.tasks.scan_infra_task.delay')
    def test_dispatch_web_wordpress(self, infra_delay, web_delay, wordpress_delay):
        scan = ScanExecution.objects.create(
            organization=self.org,
            asset=self.asset,
            profile=self.profile,
            launched_by=self.user,
            engine_metadata={'requested_scan_type': 'web_wordpress'},
        )

        run_scan_task(scan.id)

        wordpress_delay.assert_called_once_with(scan.id)
        web_delay.assert_not_called()
        infra_delay.assert_not_called()

    @patch('scans.tasks.scan_wordpress_task.delay')
    @patch('scans.tasks.scan_web_task.delay')
    @patch('scans.tasks.scan_infra_task.delay')
    def test_dispatch_infra_default(self, infra_delay, web_delay, wordpress_delay):
        scan = ScanExecution.objects.create(
            organization=self.org,
            asset=self.asset,
            profile=self.profile,
            launched_by=self.user,
            engine_metadata={'requested_scan_type': 'nmap_discovery'},
        )

        run_scan_task(scan.id)

        infra_delay.assert_called_once_with(scan.id)
        web_delay.assert_not_called()
        wordpress_delay.assert_not_called()

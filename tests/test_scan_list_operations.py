from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from accounts.models import Organization, OrganizationMembership
from assets.models import Asset
from scan_profiles.models import ScanProfile
from scans.models import ScanExecution


class ScanListOperationsTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(
            username='scan-list-user',
            email='scan-list@example.com',
            password='test12345',
        )
        self.organization = Organization.objects.create(name='Org Scan List', slug='org-scan-list')
        OrganizationMembership.objects.create(
            user=self.user,
            organization=self.organization,
            role=OrganizationMembership.Role.OWNER,
            is_active=True,
        )
        self.asset_a = Asset.objects.create(
            organization=self.organization,
            name='Public API',
            asset_type='url',
            value='https://api.example.com',
        )
        self.asset_b = Asset.objects.create(
            organization=self.organization,
            name='Core Node',
            asset_type='ip',
            value='10.10.10.20',
        )
        self.profile_web = ScanProfile.objects.create(organization=self.organization, name='web_basic')
        self.profile_infra = ScanProfile.objects.create(organization=self.organization, name='infra_standard')

        self.web_scan = ScanExecution.objects.create(
            organization=self.organization,
            asset=self.asset_a,
            profile=self.profile_web,
            launched_by=self.user,
            status=ScanExecution.Status.RUNNING,
            progress_percent=62,
            progress_stage='endpoint_discovery',
            engine_metadata={'requested_scan_type': 'web_basic'},
        )
        self.infra_scan = ScanExecution.objects.create(
            organization=self.organization,
            asset=self.asset_b,
            profile=self.profile_infra,
            launched_by=self.user,
            status=ScanExecution.Status.COMPLETED,
            duration_seconds=180,
            is_archived=True,
            progress_percent=100,
            progress_stage='completed',
            engine_metadata={'requested_scan_type': 'infra_standard'},
        )

    def test_scan_list_filters_by_asset_and_archive(self):
        self.client.force_login(self.user)

        response = self.client.get(reverse('scans-list'), {'asset': 'Public', 'archived': 'active'})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, f'#{self.web_scan.id}')
        self.assertNotContains(response, f'#{self.infra_scan.id}')

    def test_archive_and_unarchive_actions(self):
        self.client.force_login(self.user)

        archive_response = self.client.post(reverse('scans-archive', args=[self.web_scan.id]))
        self.assertEqual(archive_response.status_code, 302)
        self.web_scan.refresh_from_db()
        self.assertTrue(self.web_scan.is_archived)

        unarchive_response = self.client.post(reverse('scans-unarchive', args=[self.web_scan.id]))
        self.assertEqual(unarchive_response.status_code, 302)
        self.web_scan.refresh_from_db()
        self.assertFalse(self.web_scan.is_archived)

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from accounts.models import Organization, OrganizationMembership
from assets.models import Asset
from scan_profiles.models import ScanProfile
from scans.models import ScanExecution


class ScanDetailViewTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(
            username='scan-detail',
            email='scan-detail@example.com',
            password='test12345',
        )
        self.organization = Organization.objects.create(name='Org Scan Detail', slug='org-scan-detail')
        OrganizationMembership.objects.create(
            user=self.user,
            organization=self.organization,
            role=OrganizationMembership.Role.OWNER,
            is_active=True,
        )
        self.asset = Asset.objects.create(
            organization=self.organization,
            name='Portal',
            asset_type='url',
            value='https://example.com',
        )
        self.profile = ScanProfile.objects.create(organization=self.organization, name='web_basic')

    def test_scan_detail_does_not_fail_with_missing_structured_keys(self):
        scan = ScanExecution.objects.create(
            organization=self.organization,
            asset=self.asset,
            profile=self.profile,
            launched_by=self.user,
            engine_metadata={
                'pipeline': 'web',
                'structured_results': {'target': 'https://example.com'},
            },
            summary={},
        )
        self.client.force_login(self.user)

        response = self.client.get(reverse('scans-detail', args=[scan.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Resultados por módulo')


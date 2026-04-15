from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from accounts.models import Organization, OrganizationMembership
from assets.models import Asset
from findings.models import Finding
from scan_profiles.models import ScanProfile
from scans.models import ScanExecution


class FindingDetailViewTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(
            username='analyst',
            email='analyst@example.com',
            password='test12345',
        )
        self.organization = Organization.objects.create(name='Org A', slug='org-a')
        OrganizationMembership.objects.create(
            user=self.user,
            organization=self.organization,
            role=OrganizationMembership.Role.OWNER,
            is_active=True,
        )
        self.asset = Asset.objects.create(
            organization=self.organization,
            name='Srv',
            asset_type='ip',
            value='10.0.0.10',
        )
        self.profile = ScanProfile.objects.create(organization=self.organization, name='default')
        self.scan = ScanExecution.objects.create(
            organization=self.organization,
            asset=self.asset,
            profile=self.profile,
        )

    def test_detail_view_handles_empty_correlation_context(self):
        finding = Finding.objects.create(
            organization=self.organization,
            scan_execution=self.scan,
            asset=self.asset,
            title='Open SSH',
            description='desc',
            remediation='',
            severity=Finding.Severity.MEDIUM,
            confidence=Finding.Confidence.MEDIUM,
            correlation_trace={},
        )
        self.client.force_login(self.user)

        response = self.client.get(reverse('findings-detail', args=[finding.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            'Este finding no tiene contexto de correlación detallado disponible todavía.',
        )

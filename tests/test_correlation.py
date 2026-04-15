from django.contrib.auth import get_user_model
from django.test import TestCase

from accounts.models import Organization, OrganizationMembership
from assets.models import Asset
from knowledge_base.models import Product, ProductAlias, RemediationTemplate, VulnerabilityRule
from scan_profiles.models import ScanProfile
from scans.models import ScanExecution, ServiceFinding
from scans.services.correlation_service import CorrelationService


class CorrelationTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username='u1', email='u1@example.com', password='test12345')
        self.org = Organization.objects.create(name='Org A', slug='org-a')
        OrganizationMembership.objects.create(user=self.user, organization=self.org, role='owner', is_active=True)

        self.asset = Asset.objects.create(organization=self.org, name='Srv', asset_type='ip', value='10.0.0.10')
        self.profile = ScanProfile.objects.create(organization=self.org, name='discovery')
        self.scan = ScanExecution.objects.create(organization=self.org, asset=self.asset, profile=self.profile)

        product = Product.objects.create(name='Apache HTTP Server')
        ProductAlias.objects.create(product=product, alias='Apache httpd')
        rem = RemediationTemplate.objects.create(title='r1', body='upgrade')
        self.rule = VulnerabilityRule.objects.create(
            title='Apache antiguo',
            product=product,
            min_version='2.0',
            max_version='2.4.49',
            port=80,
            protocol='tcp',
            severity='high',
            confidence='high',
            description='desc',
            remediation_template=rem,
        )

    def test_version_range_and_alias_correlation(self):
        svc = ServiceFinding.objects.create(
            organization=self.org,
            scan_execution=self.scan,
            host='10.0.0.10',
            port=80,
            protocol='tcp',
            state='open',
            service='http',
            product='Apache httpd',
            version='2.4.40',
        )
        findings = CorrelationService().correlate_scan_execution(self.scan)
        self.assertEqual(len(findings), 1)
        svc.refresh_from_db()
        self.assertEqual(svc.normalized_product, 'Apache HTTP Server')

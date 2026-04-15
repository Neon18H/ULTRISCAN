from django.contrib.auth import get_user_model
from django.test import TestCase

from accounts.models import Organization, OrganizationMembership
from assets.models import Asset
from knowledge_base.models import MisconfigurationRule, Product, ProductAlias, RemediationTemplate, VulnerabilityRule
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
            required_state='open',
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

    def test_exposure_rule_matches_without_version(self):
        product = Product.objects.create(name='FTP')
        ProductAlias.objects.create(product=product, alias='ftp')
        rem = RemediationTemplate.objects.create(title='r2', body='restrict')
        MisconfigurationRule.objects.create(
            title='FTP exposed on 21',
            product=product,
            service_name='ftp',
            port=21,
            protocol='tcp',
            required_state='open',
            evidence_type='network_exposure',
            severity='medium',
            confidence='high',
            description='desc',
            remediation_template=rem,
        )

        ServiceFinding.objects.create(
            organization=self.org,
            scan_execution=self.scan,
            host='10.0.0.10',
            port=21,
            protocol='tcp',
            state='open',
            service='ftp',
            product='',
            version='',
        )

        findings = CorrelationService().correlate_scan_execution(self.scan)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, 'FTP exposed on 21')

    def test_exposure_rule_matches_service_alias_with_port(self):
        product = Product.objects.create(name='Generic HTTP Service')
        rem = RemediationTemplate.objects.create(title='r3', body='restrict')
        MisconfigurationRule.objects.create(
            title='Alternate HTTP service exposed',
            product=product,
            port=8088,
            protocol='tcp',
            required_state='open',
            evidence_type='network_exposure',
            severity='medium',
            confidence='high',
            description='desc',
            remediation_template=rem,
        )

        ServiceFinding.objects.create(
            organization=self.org,
            scan_execution=self.scan,
            host='10.0.0.10',
            port=8088,
            protocol='tcp',
            state='open',
            service='radan-http',
            product='',
            version='',
        )

        findings = CorrelationService().correlate_scan_execution(self.scan)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, 'Alternate HTTP service exposed')

    def test_product_mismatch_does_not_block_exposure_rule(self):
        product = Product.objects.create(name='Elasticsearch')
        rem = RemediationTemplate.objects.create(title='r4', body='restrict')
        MisconfigurationRule.objects.create(
            title='Port 9200 exposed',
            product=product,
            port=9200,
            protocol='tcp',
            required_state='open',
            evidence_type='network_exposure',
            severity='high',
            confidence='high',
            description='desc',
            remediation_template=rem,
        )

        ServiceFinding.objects.create(
            organization=self.org,
            scan_execution=self.scan,
            host='10.0.0.10',
            port=9200,
            protocol='tcp',
            state='open',
            service='wap-wsp',
            product='',
            version='',
        )

        findings = CorrelationService().correlate_scan_execution(self.scan)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, 'Port 9200 exposed')

from django.contrib.auth import get_user_model
from django.test import TestCase

from accounts.models import Organization, OrganizationMembership
from assets.models import Asset
from knowledge_base.models import EndOfLifeRule, MisconfigurationRule, Product, ProductAlias, RemediationTemplate, VulnerabilityRule
from scan_profiles.models import ScanProfile
from scans.models import RawEvidence, ScanExecution, ServiceFinding
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


    def test_version_range_accepts_nmap_suffix_versions(self):
        ServiceFinding.objects.create(
            organization=self.org,
            scan_execution=self.scan,
            host='10.0.0.10',
            port=80,
            protocol='tcp',
            state='open',
            service='http',
            product='Apache httpd',
            version='2.4.41 Ubuntu',
            raw_version='2.4.41 Ubuntu',
            normalized_version='2.4.41',
        )

        findings = CorrelationService().correlate_scan_execution(self.scan)
        self.assertEqual(len(findings), 1)

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


    def test_invalid_version_does_not_break_exposure_finding(self):
        product = Product.objects.create(name='FTP Legacy')
        rem = RemediationTemplate.objects.create(title='r5', body='restrict')
        MisconfigurationRule.objects.create(
            title='FTP legacy exposed',
            product=product,
            port=2121,
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
            port=2121,
            protocol='tcp',
            state='open',
            service='ftp',
            product='',
            version='9.6p1 Ubuntu 3ubuntu13.15',
            raw_version='9.6p1 Ubuntu 3ubuntu13.15',
            normalized_version='',
        )

        findings = CorrelationService().correlate_scan_execution(self.scan)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, 'FTP legacy exposed')

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

    def test_does_not_create_php_or_wordpress_findings_without_explicit_evidence(self):
        php = Product.objects.create(name='PHP')
        wordpress = Product.objects.create(name='WordPress')
        rem = RemediationTemplate.objects.create(title='r6', body='upgrade')
        VulnerabilityRule.objects.create(
            title='PHP unsupported or near EOL branch',
            product=php,
            required_state='open',
            version_operator='<=',
            version_value='8.1.99',
            severity='high',
            confidence='medium',
            description='desc',
            remediation_template=rem,
        )
        EndOfLifeRule.objects.create(
            title='WordPress below maintained baseline',
            product=wordpress,
            required_state='open',
            version_operator='<',
            version_value='6.3.0',
            severity='medium',
            confidence='medium',
            description='desc',
            remediation_template=rem,
        )

        ServiceFinding.objects.create(
            organization=self.org,
            scan_execution=self.scan,
            host='10.0.0.10',
            port=3306,
            protocol='tcp',
            state='open',
            service='mysql',
            product='MySQL',
            version='5.7.36',
            raw_version='5.7.36',
            normalized_version='5.7.36',
        )

        findings = CorrelationService().correlate_scan_execution(self.scan)
        finding_titles = {item.title for item in findings}
        self.assertNotIn('PHP unsupported or near EOL branch', finding_titles)
        self.assertNotIn('WordPress below maintained baseline', finding_titles)

    def test_associates_raw_evidence_and_trace_to_matched_service(self):
        raw_evidence = RawEvidence.objects.create(
            organization=self.org,
            scan_execution=self.scan,
            source='nmap',
            host='10.0.0.10',
            payload={
                'host': '10.0.0.10',
                'ports': [
                    {'port': 80, 'protocol': 'tcp', 'service': 'http', 'product': 'Apache httpd', 'version': '2.4.40'}
                ],
            },
            metadata={'collector': 'test'},
        )
        ServiceFinding.objects.create(
            organization=self.org,
            scan_execution=self.scan,
            host='10.0.0.10',
            port=80,
            protocol='tcp',
            state='open',
            service='http',
            product='Apache httpd',
            version='2.4.40',
            raw_version='2.4.40',
            normalized_version='2.4.40',
        )

        findings = CorrelationService().correlate_scan_execution(self.scan)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.raw_evidence_id, raw_evidence.id)
        self.assertEqual(finding.correlation_trace['source_evidence']['port'], 80)
        self.assertEqual(finding.correlation_trace['source_evidence']['source'], 'nmap')
        self.assertEqual(finding.correlation_trace['detected_version']['version_used_for_matching'], '2.4.40')

    def test_version_based_rule_requires_product_match(self):
        mysql = Product.objects.create(name='MySQL', vendor='Oracle')
        rem = RemediationTemplate.objects.create(title='r7', body='upgrade')
        VulnerabilityRule.objects.create(
            title='PHP unsupported branch',
            product=Product.objects.create(name='PHP', vendor='The PHP Group'),
            required_state='open',
            version_operator='<=',
            version_value='8.1.99',
            severity='high',
            confidence='medium',
            description='desc',
            remediation_template=rem,
        )
        VulnerabilityRule.objects.create(
            title='MySQL outdated baseline',
            product=mysql,
            service_name='mysql',
            port=3306,
            protocol='tcp',
            required_state='open',
            version_operator='<',
            version_value='8.0.0',
            severity='medium',
            confidence='medium',
            description='desc',
            remediation_template=rem,
        )
        ServiceFinding.objects.create(
            organization=self.org,
            scan_execution=self.scan,
            host='10.0.0.10',
            port=3306,
            protocol='tcp',
            state='open',
            service='mysql',
            product='MySQL',
            version='5.7.36',
            raw_version='5.7.36',
            normalized_version='5.7.36',
        )

        findings = CorrelationService().correlate_scan_execution(self.scan)
        finding_titles = {item.title for item in findings}
        self.assertIn('MySQL outdated baseline', finding_titles)
        self.assertNotIn('PHP unsupported branch', finding_titles)

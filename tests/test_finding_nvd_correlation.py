from django.contrib.auth import get_user_model
from django.test import TestCase

from accounts.models import Organization, OrganizationMembership
from assets.models import Asset
from findings.models import Finding
from findings.nvd_correlation import FindingNvdCorrelationService
from knowledge_base.models import (
    ExternalAdvisory,
    ExternalAdvisoryCpeMatch,
    MisconfigurationRule,
    Product,
    RemediationTemplate,
    VulnerabilityRule,
)
from scan_profiles.models import ScanProfile
from scans.models import ScanExecution, ServiceFinding


class FindingNvdCorrelationTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username='corr', email='corr@example.com', password='x1234567')
        self.org = Organization.objects.create(name='Corr Org', slug='corr-org')
        OrganizationMembership.objects.create(user=self.user, organization=self.org, role='owner', is_active=True)
        self.asset = Asset.objects.create(organization=self.org, name='srv', asset_type='ip', value='10.1.1.10')
        self.profile = ScanProfile.objects.create(organization=self.org, name='quick')
        self.scan = ScanExecution.objects.create(organization=self.org, asset=self.asset, profile=self.profile)

    def test_returns_exact_match_when_rule_cve_exists_in_nvd(self):
        advisory = ExternalAdvisory.objects.create(
            source=ExternalAdvisory.Source.NVD,
            cve_id='CVE-2026-1000',
            description='Exact advisory',
            severity='high',
        )
        product = Product.objects.create(name='Apache HTTP Server')
        remediation = RemediationTemplate.objects.create(title='upgrade', body='upgrade now')
        vuln_rule = VulnerabilityRule.objects.create(
            title='Apache vulnerability',
            product=product,
            cve='CVE-2026-1000',
            severity='high',
            confidence='high',
            description='desc',
            remediation_template=remediation,
        )
        service = ServiceFinding.objects.create(
            organization=self.org,
            scan_execution=self.scan,
            host='10.1.1.10',
            port=80,
            protocol='tcp',
            state='open',
            service='http',
            product='Apache HTTP Server',
            normalized_product='Apache HTTP Server',
            version='2.4.62',
            normalized_version='2.4.62',
        )
        finding = Finding.objects.create(
            organization=self.org,
            asset=self.asset,
            scan_execution=self.scan,
            service_finding=service,
            vulnerability_rule=vuln_rule,
            title='Apache finding',
            description='desc',
            remediation='r',
            severity='high',
            confidence='high',
            status=Finding.Status.OPEN,
        )

        payload = FindingNvdCorrelationService().correlate(finding)
        self.assertEqual(payload['status'], 'exact')
        self.assertEqual(payload['advisory'].id, advisory.id)

    def test_returns_candidate_when_cpe_and_version_match(self):
        advisory = ExternalAdvisory.objects.create(
            source=ExternalAdvisory.Source.NVD,
            cve_id='CVE-2026-2222',
            description='OpenSSH affected under vulnerable ranges',
            severity='critical',
            has_kev=True,
        )
        ExternalAdvisoryCpeMatch.objects.create(
            advisory=advisory,
            vulnerable=True,
            criteria='cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*',
            version_start_including='8.0',
            version_end_excluding='9.0',
        )
        service = ServiceFinding.objects.create(
            organization=self.org,
            scan_execution=self.scan,
            host='10.1.1.10',
            port=22,
            protocol='tcp',
            state='open',
            service='ssh',
            product='OpenSSH',
            normalized_product='OpenSSH',
            version='8.7',
            normalized_version='8.7',
            banner='OpenSSH 8.7 Ubuntu',
        )
        finding = Finding.objects.create(
            organization=self.org,
            asset=self.asset,
            scan_execution=self.scan,
            service_finding=service,
            title='OpenSSH service exposed',
            description='OpenSSH fingerprint detected',
            remediation='r',
            severity='medium',
            confidence='medium',
            status=Finding.Status.OPEN,
        )

        payload = FindingNvdCorrelationService().correlate(finding)
        self.assertEqual(payload['status'], 'candidate')
        self.assertGreaterEqual(payload['candidates'][0]['score'], 5)

    def test_returns_exposure_message_for_non_cve_exposure_findings(self):
        product = Product.objects.create(name='Generic FTP')
        remediation = RemediationTemplate.objects.create(title='close', body='close')
        misconfiguration_rule = MisconfigurationRule.objects.create(
            title='FTP exposed',
            product=product,
            severity='medium',
            confidence='high',
            description='Exposure finding',
            remediation_template=remediation,
        )
        service = ServiceFinding.objects.create(
            organization=self.org,
            scan_execution=self.scan,
            host='10.1.1.10',
            port=21,
            protocol='tcp',
            state='open',
            service='ftp',
        )
        finding = Finding.objects.create(
            organization=self.org,
            asset=self.asset,
            scan_execution=self.scan,
            service_finding=service,
            misconfiguration_rule=misconfiguration_rule,
            title='FTP exposed',
            description='Exposure finding',
            remediation='r',
            severity='medium',
            confidence='high',
            status=Finding.Status.OPEN,
        )

        payload = FindingNvdCorrelationService()._no_match_payload(finding)
        self.assertEqual(payload['status'], 'exposure')

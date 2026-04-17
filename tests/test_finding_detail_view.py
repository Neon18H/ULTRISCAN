from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from accounts.models import Organization, OrganizationMembership
from assets.models import Asset
from findings.models import Finding
from knowledge_base.models import CVEExploit, Exploit, ExternalAdvisory, Product, RemediationTemplate, VulnerabilityRule
from scans.models import ServiceFinding
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
        self.assertContains(response, 'OpenRouter no configurado.')


    def test_detail_view_renders_exploit_section_when_cve_has_public_exploit(self):
        advisory = ExternalAdvisory.objects.create(
            source=ExternalAdvisory.Source.NVD,
            cve_id='CVE-2026-4242',
            description='x',
        )
        exploit = Exploit.objects.create(
            exploit_id=4242,
            title='Public PoC',
            platform='linux',
            type='remote',
            file_path='exploits/linux/remote/4242.py',
            cve='CVE-2026-4242',
        )
        CVEExploit.objects.create(cve=advisory, exploit=exploit)

        product = Product.objects.create(name='OpenSSH')
        remediation = RemediationTemplate.objects.create(title='Upgrade', body='Upgrade now')
        rule = VulnerabilityRule.objects.create(
            title='OpenSSH CVE',
            product=product,
            cve='CVE-2026-4242',
            severity='high',
            confidence='high',
            description='desc',
            remediation_template=remediation,
        )
        service = ServiceFinding.objects.create(
            organization=self.organization,
            scan_execution=self.scan,
            host='10.0.0.10',
            port=22,
            protocol='tcp',
            state='open',
            service='ssh',
            product='OpenSSH',
            normalized_product='OpenSSH',
        )

        finding = Finding.objects.create(
            organization=self.organization,
            scan_execution=self.scan,
            asset=self.asset,
            service_finding=service,
            vulnerability_rule=rule,
            title='Open SSH vulnerable',
            description='desc',
            remediation='',
            severity=Finding.Severity.HIGH,
            confidence=Finding.Confidence.MEDIUM,
            correlation_trace={},
        )
        self.client.force_login(self.user)

        response = self.client.get(reverse('findings-detail', args=[finding.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Exploit disponible')
        self.assertContains(response, 'EDB-4242')
        self.assertContains(response, 'Exploitable')

    def test_detail_view_renders_ai_enrichment_section(self):
        finding = Finding.objects.create(
            organization=self.organization,
            scan_execution=self.scan,
            asset=self.asset,
            title='Open SSH',
            description='desc',
            remediation='',
            severity=Finding.Severity.MEDIUM,
            confidence=Finding.Confidence.MEDIUM,
            ai_summary='Resumen por IA',
            ai_priority_reason='Tiene exploit público',
            ai_impact='Impacto por IA',
            ai_remediation='Acción por IA',
            ai_owasp_category='A05',
            ai_cwe='CWE-200',
            ai_enrichment={
                'insufficient_evidence': False,
                'exploit_context': 'Public exploit available',
                'confidence': 'medium',
            },
            correlation_trace={},
        )
        self.client.force_login(self.user)

        response = self.client.get(reverse('findings-detail', args=[finding.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Enriquecimiento IA (no fuente primaria)')
        self.assertContains(response, 'Resumen por IA')
        self.assertContains(response, 'Tiene exploit público')

    def test_detail_view_renders_ai_skipped_message(self):
        finding = Finding.objects.create(
            organization=self.organization,
            scan_execution=self.scan,
            asset=self.asset,
            title='Open SSH',
            description='desc',
            remediation='',
            severity=Finding.Severity.MEDIUM,
            confidence=Finding.Confidence.MEDIUM,
            ai_enrichment={
                'status': 'skipped',
                'status_message': 'OpenRouter no configurado. Enriquecimiento IA omitido.',
            },
            correlation_trace={},
        )
        self.client.force_login(self.user)

        response = self.client.get(reverse('findings-detail', args=[finding.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'OpenRouter no configurado. Enriquecimiento IA omitido.')

    def test_detail_view_renders_ai_error_message(self):
        finding = Finding.objects.create(
            organization=self.organization,
            scan_execution=self.scan,
            asset=self.asset,
            title='Open SSH',
            description='desc',
            remediation='',
            severity=Finding.Severity.MEDIUM,
            confidence=Finding.Confidence.MEDIUM,
            ai_enrichment={
                'status': 'error',
                'status_message': 'Error al generar enriquecimiento IA',
            },
            correlation_trace={},
        )
        self.client.force_login(self.user)

        response = self.client.get(reverse('findings-detail', args=[finding.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Error al generar enriquecimiento IA')

    @override_settings(OPENROUTER_API_KEY='test-key')
    def test_detail_view_renders_ai_pending_message_when_not_generated(self):
        finding = Finding.objects.create(
            organization=self.organization,
            scan_execution=self.scan,
            asset=self.asset,
            title='Missing CSP',
            description='desc',
            remediation='',
            severity=Finding.Severity.LOW,
            confidence=Finding.Confidence.MEDIUM,
            correlation_trace={},
        )
        self.client.force_login(self.user)

        response = self.client.get(reverse('findings-detail', args=[finding.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Enriquecimiento IA pendiente.')

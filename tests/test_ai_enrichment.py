from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from accounts.models import Organization, OrganizationMembership
from assets.models import Asset
from findings.ai_enrichment import AIFindingEnrichmentService
from findings.models import Finding
from knowledge_base.models import CVEExploit, Exploit, ExternalAdvisory, Product, RemediationTemplate, VulnerabilityRule
from scan_profiles.models import ScanProfile
from scans.models import RawEvidence, ScanExecution, ServiceFinding


class AIFindingEnrichmentServiceTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user(username='ai-user', email='ai@example.com', password='pass12345')
        self.organization = Organization.objects.create(name='Org AI', slug='org-ai')
        OrganizationMembership.objects.create(
            user=self.user,
            organization=self.organization,
            role=OrganizationMembership.Role.OWNER,
            is_active=True,
        )
        self.asset = Asset.objects.create(
            organization=self.organization,
            name='Web Node',
            asset_type='domain',
            value='app.example.com',
        )
        self.profile = ScanProfile.objects.create(organization=self.organization, name='default')
        self.scan = ScanExecution.objects.create(
            organization=self.organization,
            asset=self.asset,
            profile=self.profile,
            engine_metadata={
                'requested_scan_type': 'web_full',
                'structured_results': {
                    'scan_type': 'web_full',
                    'endpoints': ['https://app.example.com/login'],
                    'interpreted_headers': [{'name': 'server', 'value': 'nginx'}],
                },
            },
        )
        self.service = ServiceFinding.objects.create(
            organization=self.organization,
            scan_execution=self.scan,
            host='app.example.com',
            port=443,
            protocol='tcp',
            state='open',
            service='https',
            product='nginx',
            normalized_product='nginx',
            version='1.18.0',
        )
        self.evidence = RawEvidence.objects.create(
            organization=self.organization,
            scan_execution=self.scan,
            source='http_probe',
            host='app.example.com',
            payload={'ports': [{'port': 443, 'protocol': 'tcp'}]},
            raw_output='Server: nginx/1.18.0',
            metadata={'headers': {'server': 'nginx/1.18.0'}},
        )
        product = Product.objects.create(name='nginx')
        remediation = RemediationTemplate.objects.create(title='Patch', body='Upgrade nginx')
        self.advisory = ExternalAdvisory.objects.create(
            source=ExternalAdvisory.Source.NVD,
            cve_id='CVE-2026-9001',
            description='Nginx vulnerability',
        )
        rule = VulnerabilityRule.objects.create(
            title='Nginx vulnerable',
            product=product,
            cve='CVE-2026-9001',
            severity='high',
            confidence='medium',
            description='desc',
            remediation_template=remediation,
        )
        exploit = Exploit.objects.create(
            exploit_id=9001,
            title='Nginx exploit',
            platform='linux',
            exploit_type='remote',
            cve='CVE-2026-9001',
        )
        CVEExploit.objects.create(cve=self.advisory, exploit=exploit)

        self.finding = Finding.objects.create(
            organization=self.organization,
            scan_execution=self.scan,
            asset=self.asset,
            service_finding=self.service,
            raw_evidence=self.evidence,
            vulnerability_rule=rule,
            title='Base finding',
            description='Technical evidence',
            remediation='Base remediation',
            severity='high',
            confidence='medium',
            correlation_trace={},
        )

    def test_skip_enrichment_when_openrouter_is_not_configured(self):
        service = AIFindingEnrichmentService()
        total = service.enrich_findings([self.finding])
        self.assertEqual(total, 0)
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.ai_enrichment.get('status'), 'skipped')
        self.assertIn('OpenRouter no configurado', self.finding.ai_enrichment.get('status_message', ''))

    @override_settings(
        OPENROUTER_API_KEY='test-key',
        OPENROUTER_MODEL='openai/gpt-4o-mini',
        OPENROUTER_BASE_URL='https://openrouter.ai/api/v1',
    )
    @patch('integrations.openrouter_client.requests.post')
    def test_persists_structured_ai_enrichment(self, mocked_post):
        mocked_response = Mock()
        mocked_response.raise_for_status.return_value = None
        mocked_response.json.return_value = {
            'choices': [
                {
                    'message': {
                        'content': '{"finding_title":"Nginx Exposure","finding_type":"vulnerability","severity":"high","confidence":"medium","impact_summary":"Impact","evidence_summary":"Evidence","cve_context":"CVE-2026-9001","exploit_context":"Public exploit available","priority_reason":"Exploit público","remediation":"Patch nginx","owasp_category":"A06","cwe":"CWE-79","insufficient_evidence":false,"ai_tags":["exploit","internet-facing"]}'
                    }
                }
            ]
        }
        mocked_post.return_value = mocked_response

        service = AIFindingEnrichmentService()
        total = service.enrich_findings([self.finding])

        self.assertEqual(total, 1)
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.ai_title, 'Nginx Exposure')
        self.assertEqual(self.finding.ai_priority_reason, 'Exploit público')
        self.assertEqual(self.finding.ai_owasp_category, 'A06')
        self.assertEqual(self.finding.ai_cwe, 'CWE-79')
        self.assertEqual(self.finding.ai_enrichment.get('insufficient_evidence'), False)
        self.assertEqual(self.finding.ai_enrichment.get('status'), 'success')

    @override_settings(
        OPENROUTER_API_KEY='test-key',
        OPENROUTER_MODEL='openai/gpt-4o-mini',
        OPENROUTER_BASE_URL='https://openrouter.ai/api/v1',
    )
    @patch('integrations.openrouter_client.requests.post')
    def test_marks_error_status_when_openrouter_call_fails(self, mocked_post):
        mocked_post.side_effect = RuntimeError('network failure')

        service = AIFindingEnrichmentService()
        total = service.enrich_findings([self.finding])

        self.assertEqual(total, 0)
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.ai_enrichment.get('status'), 'error')
        self.assertEqual(self.finding.ai_enrichment.get('status_message'), 'Error al generar enriquecimiento IA')

from __future__ import annotations

import logging
from typing import Any

from django.conf import settings

from findings.nvd_correlation import FindingNvdCorrelationService
from integrations.openrouter_client import OpenRouterClient
from knowledge_base.models import CVEExploit

logger = logging.getLogger(__name__)


ENRICHMENT_SCHEMA: dict[str, Any] = {
    'type': 'object',
    'additionalProperties': False,
    'required': [
        'finding_title',
        'finding_type',
        'severity',
        'confidence',
        'impact_summary',
        'evidence_summary',
        'cve_context',
        'exploit_context',
        'priority_reason',
        'remediation',
        'owasp_category',
        'cwe',
        'insufficient_evidence',
    ],
    'properties': {
        'finding_title': {'type': 'string'},
        'finding_type': {'type': 'string'},
        'severity': {'type': 'string', 'enum': ['info', 'low', 'medium', 'high', 'critical']},
        'confidence': {'type': 'string', 'enum': ['low', 'medium', 'high']},
        'impact_summary': {'type': 'string'},
        'evidence_summary': {'type': 'string'},
        'cve_context': {'type': 'string'},
        'exploit_context': {'type': 'string'},
        'priority_reason': {'type': 'string'},
        'remediation': {'type': 'string'},
        'owasp_category': {'type': 'string'},
        'cwe': {'type': 'string'},
        'insufficient_evidence': {'type': 'boolean'},
        'ai_tags': {'type': 'array', 'items': {'type': 'string'}},
    },
}


SYSTEM_PROMPT = (
    'Eres un asistente de ciberseguridad para Vulnsight. '
    'NO inventes vulnerabilidades, CVEs o exploits. '
    'Solo puedes enriquecer la información técnica provista por el backend. '
    'Si no existe evidencia suficiente, marca insufficient_evidence=true y explica las limitaciones. '
    'Debes priorizar hallazgos que tengan exploit público correlacionado. '
    'Usa exclusivamente CVEs y exploits incluidos en el input. '
    'Responde únicamente en JSON válido según el schema.'
)


class AIFindingEnrichmentService:
    def __init__(self):
        self.client = OpenRouterClient(
            api_key=getattr(settings, 'OPENROUTER_API_KEY', ''),
            base_url=getattr(settings, 'OPENROUTER_BASE_URL', 'https://openrouter.ai/api/v1'),
            model=getattr(settings, 'OPENROUTER_MODEL', ''),
            timeout=getattr(settings, 'OPENROUTER_TIMEOUT', 45),
        )

    def enrich_findings(self, findings) -> int:
        if not self.client.enabled:
            logger.info('AI enrichment skipped: OpenRouter is not configured.')
            return 0

        total = 0
        if hasattr(findings, 'select_related'):
            iterable = findings.select_related('asset', 'service_finding', 'vulnerability_rule', 'raw_evidence')
        else:
            iterable = findings

        for finding in iterable:
            try:
                payload = self._build_context_payload(finding)
                result = self.client.create_structured_completion(
                    system_prompt=SYSTEM_PROMPT,
                    user_payload=payload,
                    schema_name='finding_enrichment',
                    json_schema=ENRICHMENT_SCHEMA,
                )
                self._persist_enrichment(finding, result)
                total += 1
            except Exception:
                logger.exception('AI enrichment failed for finding_id=%s', finding.id)
        return total

    def _build_context_payload(self, finding) -> dict[str, Any]:
        service = finding.service_finding
        raw = finding.raw_evidence
        structured = ((finding.scan_execution.engine_metadata or {}).get('structured_results') or {})
        nvd_correlation = FindingNvdCorrelationService().correlate(finding)

        cve_ids: set[str] = set()
        if finding.vulnerability_rule and finding.vulnerability_rule.cve:
            cve_ids.add(finding.vulnerability_rule.cve.strip().upper())
        advisory = nvd_correlation.get('advisory') if isinstance(nvd_correlation, dict) else None
        if advisory:
            cve_ids.add(advisory.cve_id)

        exploit_links = list(
            CVEExploit.objects.filter(cve__cve_id__in=cve_ids)
            .select_related('cve', 'exploit')
            .order_by('exploit__exploit_id')
        )

        return {
            'asset': {
                'id': finding.asset_id,
                'name': finding.asset.name if finding.asset else '',
                'value': finding.asset.value if finding.asset else '',
                'type': finding.asset.asset_type if finding.asset else '',
            },
            'scan_type': structured.get('scan_type') or (finding.scan_execution.engine_metadata or {}).get('requested_scan_type') or '',
            'evidence': {
                'source': raw.source if raw else '',
                'raw_output': (raw.raw_output if raw else '')[:2500],
                'payload': raw.payload if raw else {},
                'metadata': raw.metadata if raw else {},
            },
            'detected_product': (service.normalized_product if service else '') or (service.product if service else ''),
            'detected_version': (service.normalized_version if service else '') or (service.raw_version if service else '') or (service.version if service else ''),
            'endpoints': structured.get('endpoints') or [],
            'headers_findings': structured.get('interpreted_headers') or [],
            'findings_base': {
                'title': finding.title,
                'description': finding.description,
                'remediation': finding.remediation,
                'rule_type': (
                    'vulnerability' if finding.vulnerability_rule_id else 'misconfiguration' if finding.misconfiguration_rule_id else 'eol' if finding.end_of_life_rule_id else 'other'
                ),
            },
            'cves_correlated': sorted(cve_ids),
            'exploits_correlated': [
                {
                    'exploit_id': link.exploit.exploit_id,
                    'title': link.exploit.title,
                    'platform': link.exploit.platform,
                    'type': link.exploit.exploit_type or link.exploit.type,
                    'source': link.exploit.source,
                    'cve_id': link.cve.cve_id,
                }
                for link in exploit_links
            ],
            'severity_base': finding.severity,
            'confidence_base': finding.confidence,
            'nvd_correlation_status': nvd_correlation.get('status') if isinstance(nvd_correlation, dict) else '',
            'guardrails': {
                'do_not_invent_cves': True,
                'do_not_invent_exploits': True,
                'do_not_assert_without_evidence': True,
                'mark_insufficient_evidence_when_needed': True,
            },
        }

    def _persist_enrichment(self, finding, result: dict[str, Any]) -> None:
        finding.ai_enrichment = result
        finding.ai_title = (result.get('finding_title') or '')[:255]
        finding.ai_summary = result.get('evidence_summary') or ''
        finding.ai_impact = result.get('impact_summary') or ''
        finding.ai_remediation = result.get('remediation') or ''
        finding.ai_priority_reason = result.get('priority_reason') or ''
        finding.ai_confidence = result.get('confidence') or ''
        finding.ai_tags = result.get('ai_tags') or []
        finding.ai_owasp_category = (result.get('owasp_category') or '')[:120]
        finding.ai_cwe = (result.get('cwe') or '')[:80]
        finding.save(
            update_fields=[
                'ai_enrichment',
                'ai_title',
                'ai_summary',
                'ai_impact',
                'ai_remediation',
                'ai_priority_reason',
                'ai_confidence',
                'ai_tags',
                'ai_owasp_category',
                'ai_cwe',
                'updated_at',
            ]
        )

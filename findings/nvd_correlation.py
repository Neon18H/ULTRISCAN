from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from django.db.models import Q, QuerySet

from knowledge_base.models import ExternalAdvisory, Product, ProductAlias
from scans.services.versioning import compare_versions, normalize_version


_CPE_SPLIT_RE = re.compile(r'cpe:2\.3:[aho]:([^:]*):([^:]*):([^:]*)', re.IGNORECASE)


@dataclass
class AdvisoryCandidate:
    advisory: ExternalAdvisory
    score: int
    reasons: list[str]


class FindingNvdCorrelationService:
    MINIMUM_CANDIDATE_SCORE = 8

    def correlate(self, finding) -> dict[str, Any]:
        cve_id = (
            (finding.vulnerability_rule.cve or '').strip().upper()
            if finding.vulnerability_rule
            else ''
        )
        if cve_id:
            exact = (
                ExternalAdvisory.objects.filter(source=ExternalAdvisory.Source.NVD, cve_id=cve_id)
                .prefetch_related('references')
                .first()
            )
            if exact:
                return {
                    'status': 'exact',
                    'message': 'Correlación CVE exacta validada con advisory NVD sincronizado.',
                    'advisory': exact,
                    'references': list(exact.references.all()[:6]),
                    'candidates': [],
                }

        service_finding = finding.service_finding
        if not service_finding:
            return self._no_match_payload(finding)

        token_bundle = self._build_tokens(finding)
        if not token_bundle['product_aliases']:
            return self._no_match_payload(finding)
        candidates = self._search_candidates(token_bundle, token_bundle['version'])
        if candidates:
            return {
                'status': 'candidate',
                'message': 'No hay coincidencia CVE exacta para este finding todavía. Se detectaron advisories NVD potencialmente relacionados.',
                'advisory': None,
                'references': [],
                'candidates': [
                    {
                        'advisory': candidate.advisory,
                        'score': candidate.score,
                        'reason': ' · '.join(candidate.reasons[:3]),
                    }
                    for candidate in candidates[:3]
                ],
            }
        return self._no_match_payload(finding)

    def _no_match_payload(self, finding) -> dict[str, Any]:
        if finding.misconfiguration_rule and not finding.vulnerability_rule:
            message = 'Finding basado en exposición, sin correlación CVE específica.'
            status = 'exposure'
        else:
            message = 'No hay coincidencia CVE exacta para este finding todavía.'
            status = 'none'
        return {
            'status': status,
            'message': message,
            'advisory': None,
            'references': [],
            'candidates': [],
        }

    def _build_tokens(self, finding) -> dict[str, Any]:
        service_finding = finding.service_finding
        aliases: set[str] = set()
        normalized_product = (service_finding.normalized_product or '').strip()
        if service_finding.product:
            aliases.add(service_finding.product.strip().lower())
        if normalized_product:
            aliases.add(normalized_product.lower())
            aliases.update(
                alias.lower()
                for alias in ProductAlias.objects.filter(product__name__iexact=normalized_product)
                .values_list('alias', flat=True)
            )
        normalized_product_obj = Product.objects.filter(name__iexact=normalized_product).first() if normalized_product else None
        vendor = (normalized_product_obj.vendor or '').strip().lower() if normalized_product_obj else ''

        normalized_version = normalize_version(service_finding.normalized_version or service_finding.raw_version or service_finding.version)
        detected_cpes = self._extract_detected_cpes(finding)
        return {
            'service_name': (service_finding.service or '').lower(),
            'protocol': (service_finding.protocol or '').lower(),
            'port': service_finding.port,
            'version': normalized_version,
            'product_aliases': {name for name in aliases if len(name) >= 3},
            'vendor_aliases': {vendor} if vendor else set(),
            'detected_cpes': detected_cpes,
        }

    def _extract_detected_cpes(self, finding) -> set[str]:
        cpes: set[str] = set()
        raw_payload = (finding.raw_evidence.payload if finding.raw_evidence else {}) or {}
        for parsed_port in (raw_payload.get('ports') or []):
            cpe_value = (parsed_port.get('cpe') or '').strip().lower()
            if cpe_value:
                cpes.add(cpe_value)
        return cpes

    def _search_candidates(self, token_bundle: dict[str, Any], observed_version: str) -> list[AdvisoryCandidate]:
        names = list(token_bundle['product_aliases'])[:24]
        criteria_query = Q()
        for token in names:
            criteria_query |= Q(cpe_matches__criteria__icontains=token)

        query: QuerySet[ExternalAdvisory] = (
            ExternalAdvisory.objects.filter(source=ExternalAdvisory.Source.NVD)
            .prefetch_related('cpe_matches')
            .distinct()
        )
        if criteria_query:
            query = query.filter(criteria_query)
        else:
            return []

        scored: list[AdvisoryCandidate] = []
        for advisory in query[:250]:
            score, reasons = self._score_advisory(advisory, token_bundle, observed_version)
            if score >= self.MINIMUM_CANDIDATE_SCORE:
                scored.append(AdvisoryCandidate(advisory=advisory, score=score, reasons=reasons))
        return sorted(scored, key=lambda item: item.score, reverse=True)

    def _score_advisory(self, advisory: ExternalAdvisory, token_bundle: dict[str, Any], observed_version: str) -> tuple[int, list[str]]:
        score = 0
        reasons: list[str] = []
        version_candidate = normalize_version(observed_version)
        cpe_product_match = False
        vendor_match = False
        version_match = False
        detected_cpes = token_bundle['detected_cpes']
        for cpe in advisory.cpe_matches.all():
            vendor, product, _ = self._parse_cpe(cpe.criteria)
            if vendor and vendor in token_bundle['vendor_aliases']:
                vendor_match = True
            if product and product in token_bundle['product_aliases']:
                cpe_product_match = True
                reasons.append(f'producto CPE: {product}')
                if vendor_match:
                    reasons.append(f'vendor CPE: {vendor}')
                if detected_cpes and any(product in detected_cpe for detected_cpe in detected_cpes):
                    reasons.append('CPE detectado en evidencia')

            if version_candidate and self._cpe_version_matches(cpe, version_candidate):
                version_match = True
                reasons.append(f'versión compatible ({version_candidate})')

        if not cpe_product_match:
            return 0, ['sin match de producto CPE']

        score += 6
        if vendor_match:
            score += 2
        if version_match:
            score += 6
        elif version_candidate:
            reasons.append('sin match fuerte de versión en rango CPE')

        if advisory.severity in {'critical', 'high'}:
            score += 1
        if advisory.has_kev:
            score += 2
            reasons.append('KEV')
        return score, reasons

    def _parse_cpe(self, criteria: str) -> tuple[str, str, str]:
        match = _CPE_SPLIT_RE.search(criteria or '')
        if not match:
            return '', '', ''
        return tuple((match.group(i) or '').replace('_', ' ').lower() for i in [1, 2, 3])

    def _cpe_version_matches(self, cpe_match, version_candidate: str) -> bool:
        if not version_candidate:
            return False
        if cpe_match.version_start_including and not compare_versions(version_candidate, '>=', cpe_match.version_start_including):
            return False
        if cpe_match.version_start_excluding and not compare_versions(version_candidate, '>', cpe_match.version_start_excluding):
            return False
        if cpe_match.version_end_including and not compare_versions(version_candidate, '<=', cpe_match.version_end_including):
            return False
        if cpe_match.version_end_excluding and not compare_versions(version_candidate, '<', cpe_match.version_end_excluding):
            return False
        return True

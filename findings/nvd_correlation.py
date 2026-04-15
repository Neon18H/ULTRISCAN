from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from django.db.models import Q, QuerySet

from knowledge_base.models import ExternalAdvisory, ProductAlias
from scans.services.versioning import compare_versions, normalize_version


_CPE_SPLIT_RE = re.compile(r'cpe:2\.3:[aho]:([^:]*):([^:]*):([^:]*)', re.IGNORECASE)


@dataclass
class AdvisoryCandidate:
    advisory: ExternalAdvisory
    score: int
    reasons: list[str]


class FindingNvdCorrelationService:
    MINIMUM_CANDIDATE_SCORE = 5

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
        candidates = self._search_candidates(token_bundle, service_finding.normalized_version or service_finding.version)
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
        aliases = set()
        normalized_product = (service_finding.normalized_product or '').strip()
        if normalized_product:
            aliases.update(
                ProductAlias.objects.filter(product__name__iexact=normalized_product)
                .values_list('alias', flat=True)
            )

        technologies = set()
        raw_payload = (finding.raw_evidence.payload if finding.raw_evidence else {}) or {}
        metadata = (finding.raw_evidence.metadata if finding.raw_evidence else {}) or {}
        for source in [raw_payload, metadata, service_finding.scripts]:
            technologies.update(self._extract_technologies(source))

        normalized_version = normalize_version(service_finding.normalized_version or service_finding.version)
        names = {
            value.lower().strip()
            for value in [
                service_finding.service,
                service_finding.product,
                normalized_product,
                finding.title,
                finding.description,
                *aliases,
                *technologies,
            ]
            if value
        }
        return {
            'names': {name for name in names if len(name) >= 3},
            'service_name': (service_finding.service or '').lower(),
            'protocol': (service_finding.protocol or '').lower(),
            'port': service_finding.port,
            'version': normalized_version,
        }

    def _extract_technologies(self, value: Any) -> set[str]:
        out: set[str] = set()
        if isinstance(value, dict):
            for k, v in value.items():
                if any(h in str(k).lower() for h in ['tech', 'product', 'service', 'fingerprint']):
                    out.add(str(v).lower())
                out.update(self._extract_technologies(v))
        elif isinstance(value, list):
            for item in value:
                out.update(self._extract_technologies(item))
        elif isinstance(value, str):
            clean = value.strip().lower()
            if clean and len(clean) > 2:
                out.add(clean)
        return out

    def _search_candidates(self, token_bundle: dict[str, Any], observed_version: str) -> list[AdvisoryCandidate]:
        names = list(token_bundle['names'])[:24]
        criteria_query = Q()
        text_query = Q()
        for token in names:
            criteria_query |= Q(cpe_matches__criteria__icontains=token)
            text_query |= Q(description__icontains=token) | Q(title__icontains=token)

        query: QuerySet[ExternalAdvisory] = (
            ExternalAdvisory.objects.filter(source=ExternalAdvisory.Source.NVD)
            .prefetch_related('cpe_matches')
            .distinct()
        )
        if criteria_query or text_query:
            query = query.filter(criteria_query | text_query)

        scored: list[AdvisoryCandidate] = []
        for advisory in query[:250]:
            score, reasons = self._score_advisory(advisory, token_bundle, observed_version)
            if score >= self.MINIMUM_CANDIDATE_SCORE:
                scored.append(AdvisoryCandidate(advisory=advisory, score=score, reasons=reasons))
        return sorted(scored, key=lambda item: item.score, reverse=True)

    def _score_advisory(self, advisory: ExternalAdvisory, token_bundle: dict[str, Any], observed_version: str) -> tuple[int, list[str]]:
        score = 0
        reasons: list[str] = []
        description_blob = f'{advisory.title} {advisory.description}'.lower()
        token_hits = 0
        for token in token_bundle['names']:
            if token and token in description_blob:
                token_hits += 1
        if token_hits:
            score += min(token_hits * 2, 8)
            reasons.append(f'{token_hits} coincidencias en descripción/título')

        version_candidate = normalize_version(observed_version)
        for cpe in advisory.cpe_matches.all():
            vendor, product, _ = self._parse_cpe(cpe.criteria)
            if vendor and vendor in token_bundle['names']:
                score += 2
                reasons.append(f'vendor CPE: {vendor}')
            if product and product in token_bundle['names']:
                score += 4
                reasons.append(f'producto CPE: {product}')

            if version_candidate and self._cpe_version_matches(cpe, version_candidate):
                score += 3
                reasons.append(f'versión compatible ({version_candidate})')

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

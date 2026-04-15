from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import UTC
from decimal import Decimal, InvalidOperation
from typing import Any

from django.db import transaction
from django.utils import dateparse, timezone

from knowledge_base.models import (
    AdvisorySyncJob,
    ExternalAdvisory,
    ExternalAdvisoryCpeMatch,
    ExternalAdvisoryReference,
    ExternalAdvisoryWeakness,
)

logger = logging.getLogger(__name__)


def _safe_decimal(value: Any) -> Decimal | None:
    if value is None or value == '':
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return None


def _parse_nvd_datetime(value: Any):
    if not value:
        return None

    if hasattr(value, 'tzinfo'):
        if timezone.is_naive(value):
            return timezone.make_aware(value, timezone=UTC)
        return value.astimezone(UTC)

    if isinstance(value, str):
        parsed = dateparse.parse_datetime(value.strip())
        if parsed is None:
            return None
        if timezone.is_naive(parsed):
            return timezone.make_aware(parsed, timezone=UTC)
        return parsed.astimezone(UTC)

    return None


def _normalize_url(value: Any) -> str:
    if not value:
        return ''
    return str(value).strip()


def _pick_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get('descriptions') or []
    english = next((item for item in descriptions if item.get('lang') == 'en'), None)
    if english:
        return english.get('value', '')
    if descriptions:
        return descriptions[0].get('value', '')
    return ''


def _extract_cvss(cve: dict[str, Any]) -> dict[str, Any]:
    metrics = cve.get('metrics') or {}
    candidates: list[tuple[int, dict[str, Any], str]] = []
    for key, weight in (('cvssMetricV31', 3), ('cvssMetricV30', 2), ('cvssMetricV2', 1)):
        for item in metrics.get(key, []):
            data = item.get('cvssData') or {}
            if data:
                candidates.append((weight, data, key))

    if not candidates:
        return {'severity': '', 'cvss_score': None, 'cvss_vector': '', 'cvss_version': ''}

    _, data, _ = sorted(candidates, key=lambda row: row[0], reverse=True)[0]
    severity = data.get('baseSeverity') or ''
    return {
        'severity': str(severity).lower(),
        'cvss_score': _safe_decimal(data.get('baseScore')),
        'cvss_vector': data.get('vectorString') or '',
        'cvss_version': data.get('version') or '',
    }


def _extract_weaknesses(cve: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for weak in cve.get('weaknesses') or []:
        source = weak.get('source') or ''
        for desc in weak.get('description') or []:
            rows.append(
                {
                    'source': source,
                    'cwe_id': desc.get('value', ''),
                    'description': desc.get('value', ''),
                }
            )
    return rows


def _extract_cpe_matches(cve: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for config in cve.get('configurations') or []:
        for node in config.get('nodes') or []:
            for cpe in node.get('cpeMatch') or []:
                rows.append(
                    {
                        'vulnerable': bool(cpe.get('vulnerable', False)),
                        'criteria': cpe.get('criteria', ''),
                        'match_criteria_id': cpe.get('matchCriteriaId', ''),
                        'version_start_including': cpe.get('versionStartIncluding', ''),
                        'version_start_excluding': cpe.get('versionStartExcluding', ''),
                        'version_end_including': cpe.get('versionEndIncluding', ''),
                        'version_end_excluding': cpe.get('versionEndExcluding', ''),
                    }
                )
    return [item for item in rows if item['criteria']]


def _extract_references(cve: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    deduped: dict[str, dict[str, Any]] = {}
    original_count = 0

    for reference in cve.get('references') or []:
        original_count += 1
        url = _normalize_url(reference.get('url'))
        if not url or url in deduped:
            continue

        tags = reference.get('tags') or []
        if isinstance(tags, list):
            normalized_tags = [str(tag).strip() for tag in tags if str(tag).strip()]
        else:
            normalized_tags = [str(tags).strip()] if str(tags).strip() else []

        deduped[url] = {
            'url': url,
            'source': (reference.get('source') or '').strip(),
            'tags': normalized_tags,
        }

    return list(deduped.values()), original_count


def _sync_references(advisory: ExternalAdvisory, refs: list[dict[str, Any]], original_count: int) -> dict[str, int]:
    existing_rows = ExternalAdvisoryReference.objects.filter(advisory=advisory)
    existing_by_url = {row.url: row for row in existing_rows}
    desired_urls = {item['url'] for item in refs}

    deleted_count, _ = existing_rows.exclude(url__in=desired_urls).delete()

    to_create: list[ExternalAdvisoryReference] = []
    to_update: list[ExternalAdvisoryReference] = []

    for item in refs:
        existing = existing_by_url.get(item['url'])
        if existing is None:
            to_create.append(ExternalAdvisoryReference(advisory=advisory, **item))
            continue

        changed = False
        if existing.source != item['source']:
            existing.source = item['source']
            changed = True
        if existing.tags != item['tags']:
            existing.tags = item['tags']
            changed = True

        if changed:
            to_update.append(existing)

    if to_create:
        ExternalAdvisoryReference.objects.bulk_create(to_create, ignore_conflicts=True)
    if to_update:
        ExternalAdvisoryReference.objects.bulk_update(to_update, ['source', 'tags', 'updated_at'])

    inserted_count = len(to_create)
    duplicate_count = max(original_count - len(refs), 0)
    ignored_count = duplicate_count + len(refs) - inserted_count

    logger.info(
        'NVD references synced cve_id=%s original=%s deduped=%s inserted=%s ignored=%s deleted=%s updated=%s',
        advisory.cve_id,
        original_count,
        len(refs),
        inserted_count,
        ignored_count,
        deleted_count,
        len(to_update),
    )

    return {
        'original': original_count,
        'deduped': len(refs),
        'inserted': inserted_count,
        'ignored': ignored_count,
        'deleted': deleted_count,
        'updated': len(to_update),
    }


def _upsert_related(advisory: ExternalAdvisory, refs: list[dict[str, Any]], refs_original_count: int, weaknesses: list[dict[str, Any]], cpe_matches: list[dict[str, Any]]) -> None:
    _sync_references(advisory=advisory, refs=refs, original_count=refs_original_count)

    advisory.weaknesses.all().delete()
    advisory.cpe_matches.all().delete()

    if weaknesses:
        ExternalAdvisoryWeakness.objects.bulk_create([ExternalAdvisoryWeakness(advisory=advisory, **item) for item in weaknesses])
    if cpe_matches:
        ExternalAdvisoryCpeMatch.objects.bulk_create([ExternalAdvisoryCpeMatch(advisory=advisory, **item) for item in cpe_matches])


def sync_nvd_vulnerabilities(command: str, vulnerabilities: Iterable[dict[str, Any]], filters: dict[str, Any] | None = None) -> AdvisorySyncJob:
    job = AdvisorySyncJob.objects.create(command=command, filters=filters or {})
    created_count = 0
    updated_count = 0
    fetched_count = 0
    errors_count = 0
    error_messages: list[str] = []

    try:
        for entry in vulnerabilities:
            fetched_count += 1
            cve = entry.get('cve') or {}
            cve_id = cve.get('id')
            if not cve_id:
                logger.warning('Skipping NVD entry without CVE id. entry_keys=%s', list(entry.keys()))
                continue

            try:
                cvss_data = _extract_cvss(cve)
                references, refs_original_count = _extract_references(cve)
                metadata = {
                    'source_identifier': cve.get('sourceIdentifier') or '',
                    'vuln_status': cve.get('vulnStatus') or '',
                    'cisa_exploit_add': cve.get('cisaExploitAdd') or '',
                    'cisa_action_due': cve.get('cisaActionDue') or '',
                    'cisa_required_action': cve.get('cisaRequiredAction') or '',
                }

                defaults = {
                    'source': ExternalAdvisory.Source.NVD,
                    'title': '',
                    'description': _pick_description(cve),
                    'published_at': _parse_nvd_datetime(cve.get('published')),
                    'last_modified_at': _parse_nvd_datetime(cve.get('lastModified')),
                    'severity': cvss_data['severity'],
                    'cvss_score': cvss_data['cvss_score'],
                    'cvss_vector': cvss_data['cvss_vector'],
                    'cvss_version': cvss_data['cvss_version'],
                    'has_kev': bool(cve.get('cisaExploitAdd')),
                    'metadata': metadata,
                    'raw_payload': entry,
                }

                with transaction.atomic():
                    advisory, created = ExternalAdvisory.objects.update_or_create(cve_id=cve_id, defaults=defaults)
                    _upsert_related(
                        advisory=advisory,
                        refs=references,
                        refs_original_count=refs_original_count,
                        weaknesses=_extract_weaknesses(cve),
                        cpe_matches=_extract_cpe_matches(cve),
                    )

                if created:
                    created_count += 1
                else:
                    updated_count += 1
            except Exception as exc:
                errors_count += 1
                error_detail = f'{cve_id}: {exc}'
                error_messages.append(error_detail)
                logger.exception('Failed to sync NVD advisory cve_id=%s', cve_id)
                continue

        job.status = AdvisorySyncJob.Status.SUCCEEDED
        if errors_count:
            job.total_errors = errors_count
            job.error_message = '; '.join(error_messages[:10])
    except Exception as exc:  # pragma: no cover
        job.status = AdvisorySyncJob.Status.FAILED
        job.error_message = str(exc)
        job.total_errors = 1
        raise
    finally:
        job.finished_at = timezone.now()
        job.total_fetched = fetched_count
        job.total_created = created_count
        job.total_updated = updated_count
        job.save(
            update_fields=[
                'status',
                'error_message',
                'total_errors',
                'finished_at',
                'total_fetched',
                'total_created',
                'total_updated',
                'updated_at',
            ]
        )

    return job

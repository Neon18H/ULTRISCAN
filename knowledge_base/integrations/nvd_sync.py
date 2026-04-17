from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from django.db import transaction
from django.db.models import Count, Min
from django.utils import dateparse, timezone

from knowledge_base.models import (
    AdvisorySyncJob,
    ExternalAdvisory,
    ExternalAdvisoryCpeMatch,
    ExternalAdvisoryMetric,
    ExternalAdvisoryReference,
    ExternalAdvisoryWeakness,
)
from knowledge_base.integrations.exploitdb_sync import sync_exploit_links

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


def _extract_metrics(cve: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    metrics = cve.get('metrics') or {}

    for metric_type, entries in metrics.items():
        if not isinstance(entries, list):
            continue

        for item in entries:
            cvss_data = item.get('cvssData') or {}
            source = (item.get('source') or '').strip()
            rows.append(
                {
                    'source': source,
                    'metric_type': metric_type,
                    'cvss_version': cvss_data.get('version') or '',
                    'base_score': _safe_decimal(cvss_data.get('baseScore')),
                    'base_severity': (cvss_data.get('baseSeverity') or '').lower(),
                    'vector_string': cvss_data.get('vectorString') or '',
                    'exploitability_score': _safe_decimal(item.get('exploitabilityScore')),
                    'impact_score': _safe_decimal(item.get('impactScore')),
                    'raw_payload': item,
                }
            )

    deduped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = (row['source'], row['metric_type'], row['cvss_version'])
        deduped[key] = row
    return list(deduped.values())


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


def _prune_duplicate_weaknesses(advisory: ExternalAdvisory) -> int:
    duplicate_groups = (
        ExternalAdvisoryWeakness.objects.filter(advisory=advisory)
        .values('cwe_id')
        .annotate(keep_id=Min('id'), row_count=Count('id'))
        .filter(row_count__gt=1)
    )

    deleted_total = 0
    for group in duplicate_groups:
        deleted_count, _ = (
            ExternalAdvisoryWeakness.objects.filter(advisory=advisory, cwe_id=group['cwe_id'])
            .exclude(id=group['keep_id'])
            .delete()
        )
        deleted_total += deleted_count

    return deleted_total


def _sync_weaknesses(advisory: ExternalAdvisory, weaknesses: list[dict[str, Any]]) -> dict[str, int]:
    deduped: dict[str, dict[str, Any]] = {}
    for row in weaknesses:
        cwe_id = (row.get('cwe_id') or '').strip()
        if not cwe_id:
            continue
        deduped[cwe_id] = {
            'source': (row.get('source') or '').strip(),
            'cwe_id': cwe_id,
            'description': (row.get('description') or '').strip(),
        }

    duplicate_deleted_count = _prune_duplicate_weaknesses(advisory=advisory)

    existing_rows = ExternalAdvisoryWeakness.objects.filter(advisory=advisory)
    existing_by_cwe = {row.cwe_id: row for row in existing_rows}
    desired_cwe_ids = set(deduped.keys())
    stale_deleted_count, _ = existing_rows.exclude(cwe_id__in=desired_cwe_ids).delete()
    deleted_count = duplicate_deleted_count + stale_deleted_count

    to_create: list[ExternalAdvisoryWeakness] = []
    to_update: list[ExternalAdvisoryWeakness] = []

    for cwe_id, item in deduped.items():
        existing = existing_by_cwe.get(cwe_id)
        if existing is None:
            to_create.append(ExternalAdvisoryWeakness(advisory=advisory, **item))
            continue

        changed = False
        if existing.source != item['source']:
            existing.source = item['source']
            changed = True
        if existing.description != item['description']:
            existing.description = item['description']
            changed = True
        if changed:
            to_update.append(existing)

    if to_create:
        ExternalAdvisoryWeakness.objects.bulk_create(to_create, ignore_conflicts=True)
    if to_update:
        ExternalAdvisoryWeakness.objects.bulk_update(to_update, ['source', 'description', 'updated_at'])

    ignored_count = max(len(weaknesses) - len(deduped), 0)
    logger.info(
        'NVD weaknesses synced cve_id=%s deduped=%s created=%s updated=%s ignored=%s deleted=%s',
        advisory.cve_id,
        len(deduped),
        len(to_create),
        len(to_update),
        ignored_count,
        deleted_count,
    )
    return {
        'deduped': len(deduped),
        'created': len(to_create),
        'updated': len(to_update),
        'ignored': ignored_count,
        'deleted': deleted_count,
    }


def _sync_cpe_matches(advisory: ExternalAdvisory, cpe_matches: list[dict[str, Any]]) -> dict[str, int]:
    deduped: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for row in cpe_matches:
        key = (
            (row.get('criteria') or '').strip(),
            (row.get('version_start_including') or '').strip(),
            (row.get('version_start_excluding') or '').strip(),
            (row.get('version_end_including') or '').strip(),
            (row.get('version_end_excluding') or '').strip(),
        )
        if not key[0]:
            continue
        deduped[key] = {
            'vulnerable': bool(row.get('vulnerable', False)),
            'criteria': key[0],
            'match_criteria_id': (row.get('match_criteria_id') or '').strip(),
            'version_start_including': key[1],
            'version_start_excluding': key[2],
            'version_end_including': key[3],
            'version_end_excluding': key[4],
        }

    existing_rows = ExternalAdvisoryCpeMatch.objects.filter(advisory=advisory)
    existing_by_signature = {
        (
            row.criteria,
            row.version_start_including,
            row.version_start_excluding,
            row.version_end_including,
            row.version_end_excluding,
        ): row
        for row in existing_rows
    }
    desired_signatures = set(deduped.keys())

    stale_ids = [
        row.id
        for signature, row in existing_by_signature.items()
        if signature not in desired_signatures
    ]
    deleted_count, _ = ExternalAdvisoryCpeMatch.objects.filter(id__in=stale_ids).delete()

    to_create: list[ExternalAdvisoryCpeMatch] = []
    to_update: list[ExternalAdvisoryCpeMatch] = []

    for signature, item in deduped.items():
        existing = existing_by_signature.get(signature)
        if existing is None:
            to_create.append(ExternalAdvisoryCpeMatch(advisory=advisory, **item))
            continue

        changed = False
        if existing.vulnerable != item['vulnerable']:
            existing.vulnerable = item['vulnerable']
            changed = True
        if existing.match_criteria_id != item['match_criteria_id']:
            existing.match_criteria_id = item['match_criteria_id']
            changed = True
        if changed:
            to_update.append(existing)

    if to_create:
        ExternalAdvisoryCpeMatch.objects.bulk_create(to_create, ignore_conflicts=True)
    if to_update:
        ExternalAdvisoryCpeMatch.objects.bulk_update(to_update, ['vulnerable', 'match_criteria_id', 'updated_at'])

    ignored_count = max(len(cpe_matches) - len(deduped), 0)
    logger.info(
        'NVD CPE matches synced cve_id=%s deduped=%s created=%s updated=%s ignored=%s deleted=%s',
        advisory.cve_id,
        len(deduped),
        len(to_create),
        len(to_update),
        ignored_count,
        deleted_count,
    )
    return {
        'deduped': len(deduped),
        'created': len(to_create),
        'updated': len(to_update),
        'ignored': ignored_count,
        'deleted': deleted_count,
    }


def _sync_metrics(advisory: ExternalAdvisory, metrics: list[dict[str, Any]]) -> dict[str, int]:
    existing_rows = ExternalAdvisoryMetric.objects.filter(advisory=advisory)
    existing_by_signature = {
        (row.source, row.metric_type, row.cvss_version): row
        for row in existing_rows
    }
    desired_signatures = {(item['source'], item['metric_type'], item['cvss_version']) for item in metrics}
    stale_ids = [
        row.id
        for signature, row in existing_by_signature.items()
        if signature not in desired_signatures
    ]
    deleted_count, _ = ExternalAdvisoryMetric.objects.filter(id__in=stale_ids).delete()

    to_create: list[ExternalAdvisoryMetric] = []
    to_update: list[ExternalAdvisoryMetric] = []

    for item in metrics:
        signature = (item['source'], item['metric_type'], item['cvss_version'])
        existing = existing_by_signature.get(signature)
        if existing is None:
            to_create.append(ExternalAdvisoryMetric(advisory=advisory, **item))
            continue

        changed = False
        for field in ('base_score', 'base_severity', 'vector_string', 'exploitability_score', 'impact_score', 'raw_payload'):
            if getattr(existing, field) != item[field]:
                setattr(existing, field, item[field])
                changed = True
        if changed:
            to_update.append(existing)

    if to_create:
        ExternalAdvisoryMetric.objects.bulk_create(to_create, ignore_conflicts=True)
    if to_update:
        ExternalAdvisoryMetric.objects.bulk_update(
            to_update,
            ['base_score', 'base_severity', 'vector_string', 'exploitability_score', 'impact_score', 'raw_payload', 'updated_at'],
        )

    logger.info(
        'NVD metrics synced cve_id=%s deduped=%s created=%s updated=%s ignored=%s deleted=%s',
        advisory.cve_id,
        len(metrics),
        len(to_create),
        len(to_update),
        0,
        deleted_count,
    )
    return {
        'deduped': len(metrics),
        'created': len(to_create),
        'updated': len(to_update),
        'ignored': 0,
        'deleted': deleted_count,
    }


def _upsert_related(
    advisory: ExternalAdvisory,
    refs: list[dict[str, Any]],
    refs_original_count: int,
    weaknesses: list[dict[str, Any]],
    cpe_matches: list[dict[str, Any]],
    metrics: list[dict[str, Any]],
) -> None:
    _sync_references(advisory=advisory, refs=refs, original_count=refs_original_count)
    _sync_weaknesses(advisory=advisory, weaknesses=weaknesses)
    _sync_cpe_matches(advisory=advisory, cpe_matches=cpe_matches)
    _sync_metrics(advisory=advisory, metrics=metrics)


def _normalize_job_filters(filters: dict[str, Any] | None) -> dict[str, Any]:
    return {k: v for k, v in (filters or {}).items() if v not in (None, '')}


def create_sync_job(
    command: str,
    job_type: str,
    filters: dict[str, Any] | None = None,
    page_size: int = 0,
    start_index: int = 0,
    resume: bool = False,
) -> AdvisorySyncJob:
    clean_filters = _normalize_job_filters(filters)
    if resume:
        previous = (
            AdvisorySyncJob.objects.filter(
                source=ExternalAdvisory.Source.NVD,
                command=command,
                job_type=job_type,
                status__in=[AdvisorySyncJob.Status.PENDING, AdvisorySyncJob.Status.RUNNING, AdvisorySyncJob.Status.FAILED],
            )
            .order_by('-created_at')
            .first()
        )
        if previous:
            was_completed = previous.status == AdvisorySyncJob.Status.COMPLETED
            previous.filters = clean_filters
            previous.filters_json = clean_filters
            previous.page_size = page_size or previous.page_size
            previous.status = AdvisorySyncJob.Status.PENDING
            previous.error_message = ''
            previous.last_error = ''
            if not was_completed:
                previous.finished_at = None
            previous.save(
                update_fields=[
                    'filters',
                    'filters_json',
                    'page_size',
                    'status',
                    'error_message',
                    'last_error',
                    'finished_at',
                    'updated_at',
                ]
            )
            return previous

    return AdvisorySyncJob.objects.create(
        command=command,
        job_type=job_type,
        filters=clean_filters,
        filters_json=clean_filters,
        status=AdvisorySyncJob.Status.PENDING,
        current_start_index=start_index,
        last_start_index=start_index,
        page_size=page_size,
    )


def run_sync_job(
    *,
    job: AdvisorySyncJob,
    client,
    filters: dict[str, Any] | None = None,
    page_size: int = 0,
    limit: int | None = None,
    max_pages: int | None = None,
    stop_at_existing: bool = False,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
) -> AdvisorySyncJob:
    clean_filters = _normalize_job_filters(filters or job.filters_json)
    requested_page_size = int(page_size or job.page_size or 0)
    limit = int(limit) if limit else None
    max_pages = int(max_pages) if max_pages else None

    if job.status == AdvisorySyncJob.Status.COMPLETED:
        return job

    if not job.started_at:
        job.started_at = timezone.now()
    job.status = AdvisorySyncJob.Status.RUNNING
    job.page_size = requested_page_size
    job.filters = clean_filters
    job.filters_json = clean_filters
    if window_start:
        job.current_window_start = window_start
    if window_end:
        job.current_window_end = window_end
    job.save(
        update_fields=[
            'started_at',
            'status',
            'page_size',
            'filters',
            'filters_json',
            'current_window_start',
            'current_window_end',
            'updated_at',
        ]
    )

    created_count = job.created_count
    updated_count = job.updated_count
    ignored_count = job.ignored_count
    fetched_count = job.total_fetched
    errors_count = job.error_count
    error_messages: list[str] = [job.last_error] if job.last_error else []

    current_start_index = int(job.current_start_index or job.last_start_index or 0)
    processed_this_run = 0
    processed_pages = int(job.processed_pages or 0)
    stop_requested = False
    synced_cve_ids: set[str] = set()

    try:
        for page in client.iter_cve_pages(
            results_per_page=requested_page_size or None,
            start_index=current_start_index,
            **clean_filters,
        ):
            page_fetched = 0
            page_created = 0
            page_updated = 0
            page_ignored = 0
            page_items = page['vulnerabilities']
            for entry in page_items:
                cve = entry.get('cve') or {}
                cve_id = cve.get('id')
                if not cve_id:
                    ignored_count += 1
                    page_ignored += 1
                    logger.warning('Skipping NVD entry without CVE id. entry_keys=%s', list(entry.keys()))
                    continue

                if limit is not None and processed_this_run >= limit:
                    break

                fetched_count += 1
                page_fetched += 1
                processed_this_run += 1
                synced_cve_ids.add(cve_id)
                try:
                    exists_before = ExternalAdvisory.objects.filter(cve_id=cve_id).exists()
                    cvss_data = _extract_cvss(cve)
                    references, refs_original_count = _extract_references(cve)
                    metrics = _extract_metrics(cve)
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
                            metrics=metrics,
                        )

                    if created:
                        created_count += 1
                        page_created += 1
                    else:
                        updated_count += 1
                        page_updated += 1
                        if stop_at_existing and exists_before:
                            stop_requested = True
                except Exception as exc:
                    errors_count += 1
                    error_detail = f'{cve_id}: {exc}'
                    error_messages.append(error_detail)
                    logger.exception('Failed to sync NVD advisory cve_id=%s', cve_id)

            current_start_index = page['start_index'] + len(page_items)
            processed_pages += 1
            job.current_start_index = current_start_index
            job.last_start_index = current_start_index
            job.processed_pages = processed_pages
            job.total_fetched = fetched_count
            job.fetched_count = fetched_count
            job.total_created = created_count
            job.total_updated = updated_count
            job.total_errors = errors_count
            job.created_count = created_count
            job.updated_count = updated_count
            job.ignored_count = ignored_count
            job.error_count = errors_count
            job.last_error = '; '.join(error_messages[-3:])
            job.save(
                update_fields=[
                    'current_start_index',
                    'last_start_index',
                    'processed_pages',
                    'total_fetched',
                    'fetched_count',
                    'total_created',
                    'total_updated',
                    'total_errors',
                    'created_count',
                    'updated_count',
                    'ignored_count',
                    'error_count',
                    'last_error',
                    'updated_at',
                ]
            )
            logger.info(
                (
                    'NVD page synced job_id=%s page=%s startIndex=%s fetched=%s '
                    'created=%s updated=%s ignored=%s progress_fetched=%s'
                ),
                job.id,
                processed_pages,
                page['start_index'],
                page_fetched,
                page_created,
                page_updated,
                page_ignored,
                fetched_count,
            )

            if limit is not None and processed_this_run >= limit:
                break
            if max_pages is not None and processed_pages >= max_pages:
                break
            if stop_requested:
                break

        job.status = AdvisorySyncJob.Status.COMPLETED
        job.finished_at = timezone.now()
        job.last_successful_sync_at = job.finished_at
        job.error_message = '; '.join(error_messages[:10])
        exploit_link_stats = sync_exploit_links(cve_ids=synced_cve_ids)
        logger.info(
            (
                'NVD post-sync exploit correlation job_id=%s cve_candidates=%s '
                'matched_nvd_cves=%s linked=%s removed=%s'
            ),
            job.id,
            exploit_link_stats['relation_candidates'],
            exploit_link_stats['matched_cves_in_nvd'],
            exploit_link_stats['linked_relations'],
            exploit_link_stats['removed_relations'],
        )
    except Exception as exc:  # pragma: no cover
        job.status = AdvisorySyncJob.Status.FAILED
        job.finished_at = timezone.now()
        job.error_message = str(exc)
        job.last_error = str(exc)
        job.total_errors = max(job.total_errors, 1)
        job.error_count = job.total_errors
        logger.exception('NVD sync job failed job_id=%s', job.id)
        raise
    finally:
        job.total_fetched = fetched_count
        job.fetched_count = fetched_count
        job.total_created = created_count
        job.total_updated = updated_count
        job.total_errors = errors_count
        job.created_count = created_count
        job.updated_count = updated_count
        job.ignored_count = ignored_count
        job.error_count = errors_count
        job.save(
            update_fields=[
                'status',
                'finished_at',
                'last_successful_sync_at',
                'error_message',
                'last_error',
                'total_fetched',
                'fetched_count',
                'total_created',
                'total_updated',
                'total_errors',
                'created_count',
                'updated_count',
                'ignored_count',
                'error_count',
                'updated_at',
            ]
        )

    return job


def sync_nvd_vulnerabilities(command: str, vulnerabilities: Iterable[dict[str, Any]], filters: dict[str, Any] | None = None) -> AdvisorySyncJob:
    job = AdvisorySyncJob.objects.create(
        command=command,
        job_type=command,
        filters=_normalize_job_filters(filters),
        filters_json=_normalize_job_filters(filters),
        status=AdvisorySyncJob.Status.RUNNING,
        started_at=timezone.now(),
    )

    created_count = 0
    updated_count = 0
    fetched_count = 0
    ignored_count = 0
    errors_count = 0
    error_messages: list[str] = []

    try:
        for entry in vulnerabilities:
            cve = entry.get('cve') or {}
            cve_id = cve.get('id')
            if not cve_id:
                ignored_count += 1
                continue

            fetched_count += 1
            try:
                cvss_data = _extract_cvss(cve)
                references, refs_original_count = _extract_references(cve)
                metrics = _extract_metrics(cve)

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
                    'metadata': {
                        'source_identifier': cve.get('sourceIdentifier') or '',
                        'vuln_status': cve.get('vulnStatus') or '',
                        'cisa_exploit_add': cve.get('cisaExploitAdd') or '',
                        'cisa_action_due': cve.get('cisaActionDue') or '',
                        'cisa_required_action': cve.get('cisaRequiredAction') or '',
                    },
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
                        metrics=metrics,
                    )

                if created:
                    created_count += 1
                else:
                    updated_count += 1
            except Exception as exc:
                errors_count += 1
                error_messages.append(f'{cve_id}: {exc}')
                logger.exception('Failed to sync NVD advisory cve_id=%s', cve_id)

        job.status = AdvisorySyncJob.Status.COMPLETED
        job.last_successful_sync_at = timezone.now()
    except Exception as exc:  # pragma: no cover
        job.status = AdvisorySyncJob.Status.FAILED
        job.error_message = str(exc)
        job.last_error = str(exc)
        raise
    finally:
        job.finished_at = timezone.now()
        job.total_fetched = fetched_count
        job.total_created = created_count
        job.total_updated = updated_count
        job.total_errors = errors_count
        job.created_count = created_count
        job.updated_count = updated_count
        job.ignored_count = ignored_count
        job.error_count = errors_count
        if error_messages:
            job.error_message = '; '.join(error_messages[:10])
            job.last_error = error_messages[-1]
        job.save()

    return job

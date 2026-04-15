import logging
from datetime import timedelta

from celery import shared_task
from django.utils import timezone

from knowledge_base.integrations.nvd_client import NVDClient
from knowledge_base.integrations.nvd_sync import create_sync_job, run_sync_job
from knowledge_base.models import AdvisorySyncJob, ExternalAdvisory

logger = logging.getLogger(__name__)


def _recent_filters(hours_back: int, force_hours_window: bool = False) -> dict[str, str]:
    end = timezone.now()
    start = end - timedelta(hours=hours_back)

    if not force_hours_window:
        previous = (
            AdvisorySyncJob.objects.filter(
                source=ExternalAdvisory.Source.NVD,
                command='sync_nvd_recent',
                status=AdvisorySyncJob.Status.COMPLETED,
                finished_at__isnull=False,
            )
            .order_by('-finished_at')
            .values_list('finished_at', flat=True)
            .first()
        )
        if previous:
            start = previous

    return {
        'lastModStartDate': start.isoformat(timespec='seconds').replace('+00:00', 'Z'),
        'lastModEndDate': end.isoformat(timespec='seconds').replace('+00:00', 'Z'),
    }


def _backfill_filters(hours_back: int):
    end = timezone.now()
    start = end - timedelta(hours=hours_back)
    filters = {
        'pubStartDate': start.isoformat(timespec='seconds').replace('+00:00', 'Z'),
        'pubEndDate': end.isoformat(timespec='seconds').replace('+00:00', 'Z'),
    }
    return filters, start, end


@shared_task(bind=True)
def sync_nvd_recent_task(
    self,
    *,
    page_size: int = 0,
    hours_back: int = 24,
    limit: int | None = None,
    resume: bool = False,
    force_hours_window: bool = False,
) -> int:
    filters = _recent_filters(hours_back=max(int(hours_back), 1), force_hours_window=force_hours_window)
    job = create_sync_job(
        command='sync_nvd_recent',
        job_type='nvd_recent',
        filters=filters,
        page_size=page_size,
        resume=resume,
    )
    run_sync_job(job=job, client=NVDClient(), filters=filters, page_size=page_size, limit=limit)
    return job.id


@shared_task(bind=True)
def sync_nvd_cves_task(
    self,
    *,
    filters: dict | None = None,
    page_size: int = 0,
    limit: int | None = None,
    resume: bool = False,
) -> int:
    job = create_sync_job(
        command='sync_nvd_cves',
        job_type='nvd_cves',
        filters=filters or {},
        page_size=page_size,
        resume=resume,
    )
    run_sync_job(job=job, client=NVDClient(), filters=filters or {}, page_size=page_size, limit=limit)
    return job.id


@shared_task(bind=True)
def sync_nvd_backfill_task(
    self,
    *,
    hours_back: int = 24 * 365,
    page_size: int = 0,
    max_pages: int | None = None,
    resume: bool = True,
    stop_at_existing: bool = False,
) -> int:
    safe_hours_back = max(int(hours_back), 1)
    filters, window_start, window_end = _backfill_filters(hours_back=safe_hours_back)
    job = create_sync_job(
        command='sync_nvd_backfill',
        job_type='nvd_backfill',
        filters=filters,
        page_size=page_size,
        resume=resume,
    )
    run_sync_job(
        job=job,
        client=NVDClient(),
        filters=filters,
        page_size=page_size,
        max_pages=max_pages,
        stop_at_existing=stop_at_existing,
        window_start=window_start,
        window_end=window_end,
    )
    return job.id

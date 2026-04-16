import logging

from celery import shared_task
from django.utils import timezone

from findings.services import correlate_scan_execution

from .models import ScanExecution
from .services.scan_pipeline import INFRA_SCAN_TYPES, WEB_SCAN_TYPES, ScanPipelineService

logger = logging.getLogger(__name__)


def _mark_running(scan: ScanExecution) -> None:
    scan.status = ScanExecution.Status.RUNNING
    scan.started_at = timezone.now()
    scan.error_message = ''
    scan.save(update_fields=['status', 'started_at', 'error_message', 'updated_at'])


def _mark_finished(scan: ScanExecution, *, status: str, error_message: str = '') -> None:
    scan.status = status
    scan.error_message = error_message
    scan.finished_at = timezone.now()
    scan.duration_seconds = int((scan.finished_at - scan.started_at).total_seconds()) if scan.started_at else 0
    scan.save(update_fields=['status', 'error_message', 'finished_at', 'duration_seconds', 'updated_at'])


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=10, retry_kwargs={'max_retries': 1})
def scan_infra_task(self, scan_execution_id: int) -> None:
    _run_pipeline(scan_execution_id=scan_execution_id, expected='infra')


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=10, retry_kwargs={'max_retries': 1})
def scan_web_task(self, scan_execution_id: int) -> None:
    _run_pipeline(scan_execution_id=scan_execution_id, expected='web')


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=10, retry_kwargs={'max_retries': 1})
def scan_wordpress_task(self, scan_execution_id: int) -> None:
    _run_pipeline(scan_execution_id=scan_execution_id, expected='web')


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=10, retry_kwargs={'max_retries': 1})
def run_scan_task(self, scan_execution_id: int) -> None:
    try:
        scan = ScanExecution.objects.select_related('profile').get(id=scan_execution_id)
    except ScanExecution.DoesNotExist:
        logger.error('Scan execution %s not found. Task exits.', scan_execution_id)
        return

    requested_scan_type = (scan.engine_metadata or {}).get('requested_scan_type', 'nmap_discovery')
    if requested_scan_type in {'web_wordpress', 'wordpress_scan'}:
        scan_wordpress_task.delay(scan_execution_id)
    elif requested_scan_type in WEB_SCAN_TYPES:
        scan_web_task.delay(scan_execution_id)
    else:
        scan_infra_task.delay(scan_execution_id)


def _run_pipeline(*, scan_execution_id: int, expected: str) -> None:
    try:
        scan = ScanExecution.objects.select_related('asset', 'profile', 'organization').get(id=scan_execution_id)
    except ScanExecution.DoesNotExist:
        logger.error('Scan execution %s not found. Task exits.', scan_execution_id)
        return

    _mark_running(scan)

    try:
        result = ScanPipelineService().execute(scan)
        pipeline = result.engine_metadata.get('pipeline')
        if expected != pipeline:
            logger.warning('Scan %s dispatched to %s but pipeline resolved as %s', scan.id, expected, pipeline)

        scan.command_executed = result.command_executed
        scan.engine_metadata = {**(scan.engine_metadata or {}), **result.engine_metadata}

        findings = correlate_scan_execution(scan)
        summary = {**result.summary, 'findings': len(findings), 'services': scan.service_findings.count()}
        scan.summary = summary

        scan.save(update_fields=['command_executed', 'engine_metadata', 'summary', 'updated_at'])
        _mark_finished(scan, status=ScanExecution.Status.COMPLETED)
    except Exception as exc:
        logger.exception('Scan execution %s failed', scan.id)
        scan.engine_metadata = {
            **(scan.engine_metadata or {}),
            'failure': {
                'error_message': str(exc),
                'failed_at': timezone.now().isoformat(),
                'command_executed': scan.command_executed,
            },
        }
        scan.save(update_fields=['engine_metadata', 'updated_at'])
        _mark_finished(scan, status=ScanExecution.Status.FAILED, error_message=str(exc))
        raise


run_scan_pipeline_task = run_scan_task

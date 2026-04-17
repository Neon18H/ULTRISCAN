import logging

from celery import shared_task
from django.utils import timezone

from findings.services import correlate_scan_execution

from .models import ScanExecution
from .services.scan_pipeline import INFRA_SCAN_TYPES, WEB_SCAN_TYPES, ScanPipelineExecutionError, ScanPipelineService

logger = logging.getLogger(__name__)


def _scan_pipeline(scan: ScanExecution) -> str:
    requested_scan_type = (scan.engine_metadata or {}).get('requested_scan_type', 'nmap_discovery')
    return 'web' if requested_scan_type in WEB_SCAN_TYPES else 'infra'


def _update_progress(scan: ScanExecution, *, percent: int, stage: str, status_message: str = '') -> None:
    scan.progress_percent = max(0, min(100, int(percent)))
    scan.progress_stage = stage
    if status_message:
        scan.status_message = status_message[:255]
    scan.save(update_fields=['progress_percent', 'progress_stage', 'status_message', 'updated_at'])


def _mark_running(scan: ScanExecution) -> None:
    first_stage = 'http_probe' if _scan_pipeline(scan) == 'web' else 'discovery'
    scan.status = ScanExecution.Status.RUNNING
    scan.started_at = timezone.now()
    scan.error_message = ''
    scan.progress_percent = max(scan.progress_percent, 5)
    scan.progress_stage = first_stage
    scan.status_message = 'Scan en ejecución'
    scan.save(
        update_fields=[
            'status',
            'started_at',
            'error_message',
            'progress_percent',
            'progress_stage',
            'status_message',
            'updated_at',
        ]
    )


def _mark_finished(scan: ScanExecution, *, status: str, error_message: str = '') -> None:
    scan.status = status
    scan.error_message = error_message
    scan.finished_at = timezone.now()
    scan.duration_seconds = int((scan.finished_at - scan.started_at).total_seconds()) if scan.started_at else 0
    if status == ScanExecution.Status.COMPLETED:
        scan.progress_percent = 100
        scan.progress_stage = 'completed'
        scan.status_message = 'Scan completado'
    elif status == ScanExecution.Status.FAILED and error_message:
        scan.status_message = error_message[:255]
    scan.save(
        update_fields=[
            'status',
            'error_message',
            'finished_at',
            'duration_seconds',
            'progress_percent',
            'progress_stage',
            'status_message',
            'updated_at',
        ]
    )


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
        def _pipeline_progress(stage: str, percent: int, message: str = '') -> None:
            _update_progress(scan, percent=percent, stage=stage, status_message=message)

        result = ScanPipelineService(progress_callback=_pipeline_progress).execute(scan)
        pipeline = result.engine_metadata.get('pipeline')
        if expected != pipeline:
            logger.warning('Scan %s dispatched to %s but pipeline resolved as %s', scan.id, expected, pipeline)

        scan.command_executed = result.command_executed
        scan.engine_metadata = {**(scan.engine_metadata or {}), **result.engine_metadata}
        _update_progress(scan, percent=90, stage='correlation', status_message='Correlacionando hallazgos')

        findings = correlate_scan_execution(scan)
        _update_progress(scan, percent=97, stage='reporting', status_message='Generando resumen operativo')
        summary = {**result.summary, 'findings': len(findings), 'services': scan.service_findings.count()}
        scan.summary = summary

        scan.save(update_fields=['command_executed', 'engine_metadata', 'summary', 'updated_at'])
        _mark_finished(scan, status=ScanExecution.Status.COMPLETED)
    except ScanPipelineExecutionError as exc:
        logger.exception('Scan execution %s failed with controlled pipeline error', scan.id)
        failure_payload = {
            'error_message': str(exc),
            'failed_at': timezone.now().isoformat(),
            'command_executed': exc.command or scan.command_executed,
            'stderr': exc.stderr,
            'stdout': exc.stdout,
            'reason': exc.reason,
            'retryable': exc.retryable,
        }
        scan.command_executed = exc.command or scan.command_executed
        scan.engine_metadata = {**(scan.engine_metadata or {}), 'failure': failure_payload}
        scan.save(update_fields=['command_executed', 'engine_metadata', 'updated_at'])
        _mark_finished(scan, status=ScanExecution.Status.FAILED, error_message=str(exc))
        if exc.retryable:
            raise
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

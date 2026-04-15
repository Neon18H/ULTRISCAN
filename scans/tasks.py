import logging

from celery import shared_task
from django.db import transaction
from django.utils import timezone

from findings.services import correlate_scan_execution
from integrations.parsers.nmap_parser import NmapXmlParser
from integrations.runners.nmap_runner import NmapRunner

from .models import RawEvidence, ScanExecution, ServiceFinding

logger = logging.getLogger(__name__)

PROFILE_KEY_MAP = {
    'discovery': 'discovery',
    'full_tcp_safe': 'full_tcp_safe',
    'web_basic': 'discovery',
    'wordpress': 'discovery',
    'misconfiguration': 'discovery',
}

REQUESTED_TYPE_TO_PROFILE = {
    'nmap_discovery': 'discovery',
    'nmap_full_tcp_safe': 'full_tcp_safe',
    'web_basic': 'discovery',
    'wordpress_scan': 'discovery',
    'misconfiguration_scan': 'discovery',
}


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=10, retry_kwargs={'max_retries': 2})
def run_scan_task(self, scan_execution_id: int) -> None:
    try:
        scan = ScanExecution.objects.select_related('asset', 'profile', 'organization').get(id=scan_execution_id)
    except ScanExecution.DoesNotExist:
        logger.error('Scan execution %s not found. Task will exit.', scan_execution_id)
        return

    logger.info('Starting scan execution %s for org %s', scan.id, scan.organization_id)
    scan.status = ScanExecution.Status.RUNNING
    scan.started_at = timezone.now()
    scan.error_message = ''
    scan.save(update_fields=['status', 'started_at', 'error_message', 'updated_at'])

    try:
        requested_scan_type = (scan.engine_metadata or {}).get('requested_scan_type')
        if requested_scan_type == 'gobuster_directory':
            scan.status = ScanExecution.Status.FAILED
            scan.error_message = 'Gobuster Directory Scan está pendiente de implementación backend.'
            scan.finished_at = timezone.now()
            scan.duration_seconds = int((scan.finished_at - scan.started_at).total_seconds()) if scan.started_at else 0
            scan.summary = {'note': 'pending_implementation'}
            scan.save(update_fields=['status', 'error_message', 'finished_at', 'duration_seconds', 'summary', 'updated_at'])
            return

        mapped_profile = REQUESTED_TYPE_TO_PROFILE.get(requested_scan_type) or PROFILE_KEY_MAP.get(scan.profile.name.lower().strip(), 'discovery')
        run_result = NmapRunner().run(target=scan.asset.value, profile=mapped_profile)
        runner_metadata = {
            **(run_result.metadata or {}),
            'return_code': run_result.return_code,
            'stderr': run_result.stderr,
            'stdout': run_result.stdout,
            'command': run_result.command,
        }

        scan.command_executed = run_result.command
        scan.engine_metadata = {**(scan.engine_metadata or {}), 'runner_metadata': runner_metadata}
        logger.info('Scan %s executing command: %s', scan.id, run_result.command)

        if runner_metadata.get('fallback_used'):
            logger.warning(
                'Scan %s executed with unprivileged fallback profile. Initial command: %s',
                scan.id,
                runner_metadata.get('initial_command'),
            )
        if runner_metadata.get('timed_out'):
            logger.warning('Scan %s timed out after %ss.', scan.id, runner_metadata.get('timeout_seconds'))
        if runner_metadata.get('scan_truncated'):
            logger.warning('Scan %s produced truncated output.', scan.id)

        if run_result.return_code != 0:
            raise RuntimeError(run_result.stderr or 'Nmap returned non-zero exit status')

        parsed_output = NmapXmlParser().parse(run_result.xml_output)

        with transaction.atomic():
            for parsed_host in parsed_output.hosts:
                raw_evidence = RawEvidence.objects.create(
                    organization=scan.organization,
                    scan_execution=scan,
                    source='nmap',
                    host=parsed_host.host,
                    payload=parsed_host.model_dump(),
                    raw_output=run_result.xml_output,
                    metadata={'stderr': run_result.stderr, 'stdout': run_result.stdout, 'runner_metadata': runner_metadata},
                )
                for parsed_service in parsed_host.ports:
                    ServiceFinding.objects.create(
                        organization=scan.organization,
                        scan_execution=scan,
                        host=parsed_host.host,
                        port=parsed_service.port,
                        protocol=parsed_service.protocol,
                        state=parsed_service.state,
                        service=parsed_service.service,
                        product=parsed_service.product,
                        version=parsed_service.version,
                        extrainfo=parsed_service.extrainfo,
                        banner=parsed_service.banner,
                        scripts=[vars(script) for script in parsed_service.scripts],
                    )
                logger.debug('Persisted raw evidence %s for scan %s', raw_evidence.id, scan.id)

            findings = correlate_scan_execution(scan)
            scan.summary = {
                'hosts': len(parsed_output.hosts),
                'services': scan.service_findings.count(),
                'findings': len(findings),
            }

        scan.status = ScanExecution.Status.COMPLETED
        scan.finished_at = timezone.now()
        scan.duration_seconds = int((scan.finished_at - scan.started_at).total_seconds()) if scan.started_at else 0
        scan.save(update_fields=['status', 'finished_at', 'duration_seconds', 'command_executed', 'engine_metadata', 'summary', 'updated_at'])
        logger.info('Completed scan execution %s', scan.id)
    except Exception as exc:
        logger.exception('Scan execution %s failed', scan.id)
        scan.status = ScanExecution.Status.FAILED
        scan.error_message = str(exc)
        scan.engine_metadata = {
            **(scan.engine_metadata or {}),
            'failure': {
                'error_message': str(exc),
                'failed_at': timezone.now().isoformat(),
                'command_executed': scan.command_executed,
            },
        }
        scan.finished_at = timezone.now()
        scan.duration_seconds = int((scan.finished_at - scan.started_at).total_seconds()) if scan.started_at else 0
        scan.save(update_fields=['status', 'error_message', 'finished_at', 'duration_seconds', 'command_executed', 'engine_metadata', 'updated_at'])
        raise


# Backward-compatible alias.
run_scan_pipeline_task = run_scan_task

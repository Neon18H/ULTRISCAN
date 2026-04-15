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


def _map_profile_name(profile_name: str) -> str:
    return PROFILE_KEY_MAP.get(profile_name.lower().strip(), 'discovery')


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=10, retry_kwargs={'max_retries': 2})
def run_scan_pipeline_task(self, scan_execution_id: int) -> None:
    scan = ScanExecution.objects.select_related('asset', 'profile', 'organization').get(id=scan_execution_id)
    logger.info('Starting scan execution %s for org %s', scan.id, scan.organization_id)
    scan.status = ScanExecution.Status.RUNNING
    scan.started_at = timezone.now()
    scan.save(update_fields=['status', 'started_at', 'updated_at'])

    try:
        mapped_profile = _map_profile_name(scan.profile.name)
        run_result = NmapRunner().run(target=scan.asset.value, profile=mapped_profile)
        scan.command_executed = run_result.command
        scan.engine_metadata = run_result.metadata

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
                    metadata={'stderr': run_result.stderr, 'runner_metadata': run_result.metadata},
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
        scan.finished_at = timezone.now()
        scan.save(update_fields=['status', 'error_message', 'finished_at', 'command_executed', 'engine_metadata', 'updated_at'])
        raise

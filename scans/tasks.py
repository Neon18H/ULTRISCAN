from celery import shared_task
from django.utils import timezone

from findings.services import correlate_scan_execution
from integrations.nmap.runner import NmapRunner
from .models import RawEvidence, ScanExecution, ServiceFinding


@shared_task
def run_scan_pipeline_task(scan_execution_id: int) -> None:
    scan = ScanExecution.objects.select_related('asset', 'profile').get(id=scan_execution_id)
    scan.status = ScanExecution.Status.RUNNING
    scan.started_at = timezone.now()
    scan.save(update_fields=['status', 'started_at', 'updated_at'])
    try:
        output = NmapRunner().run(scan.asset.value, version_detection=scan.profile.version_detection)
        scan.command_executed = output.command
        for host in output.parsed.hosts:
            raw = RawEvidence.objects.create(scan_execution=scan, source='nmap', host=host.address, payload=host.model_dump())
            for svc in host.services:
                ServiceFinding.objects.create(
                    scan_execution=scan, host=host.address, port=svc.port, protocol=svc.protocol, state=svc.state,
                    service=svc.name, product=svc.product, version=svc.version, banner=svc.banner
                )
        correlate_scan_execution(scan)
        scan.status = ScanExecution.Status.COMPLETED
        scan.finished_at = timezone.now()
        scan.duration_seconds = int((scan.finished_at - scan.started_at).total_seconds()) if scan.started_at else 0
        scan.save(update_fields=['status', 'finished_at', 'duration_seconds', 'command_executed', 'updated_at'])
    except Exception as exc:
        scan.status = ScanExecution.Status.FAILED
        scan.error_message = str(exc)
        scan.finished_at = timezone.now()
        scan.save(update_fields=['status', 'error_message', 'finished_at', 'updated_at'])
        raise

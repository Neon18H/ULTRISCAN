from django.core.management.base import BaseCommand

from scans.models import ScanExecution
from scans.services.correlation_service import CorrelationService


class Command(BaseCommand):
    help = 'Reprocesa correlación sobre scans completados para generar findings faltantes.'

    def add_arguments(self, parser):
        parser.add_argument('--scan-id', type=int, help='Procesa un scan específico')

    def handle(self, *args, **options):
        scan_id = options.get('scan_id')
        queryset = ScanExecution.objects.select_related('organization', 'asset').prefetch_related('service_findings')
        if scan_id:
            queryset = queryset.filter(id=scan_id)
        else:
            queryset = queryset.filter(status=ScanExecution.Status.COMPLETED)

        total_scans = 0
        total_findings = 0
        service = CorrelationService()
        for scan in queryset.iterator():
            total_scans += 1
            findings = service.correlate_scan_execution(scan)
            total_findings += len(findings)
            self.stdout.write(
                self.style.SUCCESS(
                    f'Scan {scan.id} ({scan.asset.value}) correlacionado: {len(findings)} findings creados/confirmados.'
                )
            )

        self.stdout.write(
            self.style.SUCCESS(
                f'Backfill completado. Scans procesados: {total_scans}. Findings creados/confirmados: {total_findings}.'
            )
        )

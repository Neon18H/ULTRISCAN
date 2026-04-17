from django.core.management.base import BaseCommand

from findings.services import enrich_findings_with_ai
from scans.models import ScanExecution


class Command(BaseCommand):
    help = 'Ejecuta enriquecimiento IA para findings existentes (OpenRouter).'

    def add_arguments(self, parser):
        parser.add_argument('--scan-id', type=int, help='Procesa findings de un scan específico')
        parser.add_argument('--only-missing', action='store_true', help='Procesa solo findings sin enriquecimiento exitoso')

    def handle(self, *args, **options):
        scan_id = options.get('scan_id')
        only_missing = bool(options.get('only_missing'))

        scans = ScanExecution.objects.select_related('asset', 'organization').order_by('-created_at')
        if scan_id:
            scans = scans.filter(id=scan_id)
        else:
            scans = scans.filter(status=ScanExecution.Status.COMPLETED)

        total_scans = 0
        total_findings = 0
        total_enriched = 0

        for scan in scans.iterator():
            total_scans += 1
            findings = scan.findings.all().order_by('id')
            if only_missing:
                findings = findings.exclude(ai_enrichment__status='success')
            findings = list(findings)
            if not findings:
                self.stdout.write(self.style.WARNING(f'Scan {scan.id}: no hay findings para enriquecer.'))
                continue

            enriched_count = enrich_findings_with_ai(findings)
            total_findings += len(findings)
            total_enriched += enriched_count
            self.stdout.write(
                self.style.SUCCESS(
                    f'Scan {scan.id} ({scan.asset.value}): findings evaluados={len(findings)} enriquecidos={enriched_count}.'
                )
            )

        self.stdout.write(
            self.style.SUCCESS(
                f'Proceso finalizado. Scans={total_scans}, findings evaluados={total_findings}, enriquecidos={total_enriched}.'
            )
        )

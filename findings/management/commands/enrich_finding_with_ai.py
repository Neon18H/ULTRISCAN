from django.core.management.base import BaseCommand, CommandError

from findings.models import Finding
from findings.services import enrich_findings_with_ai


class Command(BaseCommand):
    help = 'Ejecuta enriquecimiento IA para un finding específico por ID.'

    def add_arguments(self, parser):
        parser.add_argument('--id', type=int, required=True, help='ID del finding a enriquecer')

    def handle(self, *args, **options):
        finding_id = options['id']
        try:
            finding = (
                Finding.objects
                .select_related('asset', 'service_finding', 'vulnerability_rule', 'raw_evidence', 'scan_execution')
                .get(id=finding_id)
            )
        except Finding.DoesNotExist as exc:
            raise CommandError(f'No existe finding con id={finding_id}') from exc

        enriched = enrich_findings_with_ai([finding])
        finding.refresh_from_db(fields=['ai_enrichment'])
        status = (finding.ai_enrichment or {}).get('status', 'unknown')
        self.stdout.write(
            self.style.SUCCESS(
                f'Finding {finding.id} procesado. enriched={enriched} status={status}'
            )
        )

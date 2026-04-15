from django.core.management.base import BaseCommand

from knowledge_base.integrations.nvd_client import NVDClient
from knowledge_base.integrations.nvd_sync import sync_nvd_vulnerabilities


class Command(BaseCommand):
    help = 'Synchronize NVD CVEs with pagination and optional filters.'

    def add_arguments(self, parser):
        parser.add_argument('--cve-id', type=str, default='', help='Filter by exact cveId.')
        parser.add_argument('--cpe-name', type=str, default='', help='Filter by cpeName.')
        parser.add_argument('--has-kev', action='store_true', help='Filter only KEV CVEs.')
        parser.add_argument('--last-mod-start-date', type=str, default='', help='ISO date filter for lastModStartDate.')
        parser.add_argument('--last-mod-end-date', type=str, default='', help='ISO date filter for lastModEndDate.')
        parser.add_argument('--page-size', type=int, default=0, help='resultsPerPage override (default from settings).')

    def handle(self, *args, **options):
        filters = {
            'cveId': options['cve_id'] or None,
            'cpeName': options['cpe_name'] or None,
            'hasKev': 'true' if options['has_kev'] else None,
            'lastModStartDate': options['last_mod_start_date'] or None,
            'lastModEndDate': options['last_mod_end_date'] or None,
        }
        clean_filters = {k: v for k, v in filters.items() if v is not None}

        client = NVDClient()
        vulnerabilities = client.iter_cves(results_per_page=options['page_size'] or None, **clean_filters)
        job = sync_nvd_vulnerabilities(command='sync_nvd_cves', vulnerabilities=vulnerabilities, filters=clean_filters)

        self.stdout.write(
            self.style.SUCCESS(
                f'NVD sync complete. fetched={job.total_fetched} created={job.total_created} updated={job.total_updated}'
            )
        )

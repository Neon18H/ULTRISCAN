from django.core.management.base import BaseCommand

from knowledge_base.integrations.nvd_client import NVDClient
from knowledge_base.integrations.nvd_sync import sync_nvd_vulnerabilities


class Command(BaseCommand):
    help = 'Synchronize a small sample of NVD CVEs into local Knowledge Base.'

    def add_arguments(self, parser):
        parser.add_argument('--limit', type=int, default=25, help='Number of CVEs to fetch for sample sync.')
        parser.add_argument('--has-kev', action='store_true', help='Restrict sample to CVEs with KEV flag.')

    def handle(self, *args, **options):
        limit = options['limit']
        filters = {'hasKev': 'true'} if options['has_kev'] else {}
        client = NVDClient()

        vulnerabilities = []
        for item in client.iter_cves(results_per_page=min(limit, 2000), **filters):
            vulnerabilities.append(item)
            if len(vulnerabilities) >= limit:
                break

        job = sync_nvd_vulnerabilities(command='sync_nvd_sample', vulnerabilities=vulnerabilities, filters=filters)
        self.stdout.write(
            self.style.SUCCESS(
                f'Sample sync complete. fetched={job.total_fetched} created={job.total_created} updated={job.total_updated}'
            )
        )

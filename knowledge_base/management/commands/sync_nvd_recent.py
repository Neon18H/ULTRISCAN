from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from knowledge_base.integrations.nvd_client import NVDClient
from knowledge_base.integrations.nvd_sync import sync_nvd_vulnerabilities


class Command(BaseCommand):
    help = 'Synchronize CVEs modified recently using last modification date range.'

    def add_arguments(self, parser):
        parser.add_argument('--hours', type=int, default=24, help='How many hours back to query by last-modified date.')
        parser.add_argument('--page-size', type=int, default=0, help='resultsPerPage override (default from settings).')

    def handle(self, *args, **options):
        hours = max(options['hours'], 1)
        end = timezone.now()
        start = end - timedelta(hours=hours)

        filters = {
            'lastModStartDate': start.isoformat(timespec='seconds').replace('+00:00', 'Z'),
            'lastModEndDate': end.isoformat(timespec='seconds').replace('+00:00', 'Z'),
        }

        client = NVDClient()
        vulnerabilities = client.iter_cves(results_per_page=options['page_size'] or None, **filters)
        job = sync_nvd_vulnerabilities(command='sync_nvd_recent', vulnerabilities=vulnerabilities, filters=filters)

        self.stdout.write(
            self.style.SUCCESS(
                'Recent NVD sync complete '
                f'({filters["lastModStartDate"]} -> {filters["lastModEndDate"]}). '
                f'fetched={job.total_fetched} created={job.total_created} updated={job.total_updated}'
            )
        )

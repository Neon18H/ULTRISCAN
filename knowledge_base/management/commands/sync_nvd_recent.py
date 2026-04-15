from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from knowledge_base.integrations.nvd_client import NVDClient
from knowledge_base.integrations.nvd_sync import sync_nvd_vulnerabilities
from knowledge_base.models import AdvisorySyncJob, ExternalAdvisory


class Command(BaseCommand):
    help = 'Synchronize CVEs modified recently using last modification date range.'

    def add_arguments(self, parser):
        parser.add_argument('--hours', type=int, default=24, help='How many hours back to query by last-modified date.')
        parser.add_argument('--page-size', type=int, default=0, help='resultsPerPage override (default from settings).')
        parser.add_argument(
            '--force-hours-window',
            action='store_true',
            help='Ignore last successful sync and always use --hours window.',
        )

    def handle(self, *args, **options):
        hours = max(options['hours'], 1)
        end = timezone.now()
        start = end - timedelta(hours=hours)

        if not options['force_hours_window']:
            last_successful_sync = (
                AdvisorySyncJob.objects.filter(
                    source=ExternalAdvisory.Source.NVD,
                    command='sync_nvd_recent',
                    status=AdvisorySyncJob.Status.SUCCEEDED,
                    finished_at__isnull=False,
                )
                .order_by('-finished_at')
                .values_list('finished_at', flat=True)
                .first()
            )
            if last_successful_sync:
                start = last_successful_sync

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

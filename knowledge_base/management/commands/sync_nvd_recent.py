from django.core.management.base import BaseCommand

from knowledge_base.integrations.nvd_client import NVDClient
from knowledge_base.integrations.nvd_sync import create_sync_job, run_sync_job
from knowledge_base.tasks import sync_nvd_recent_task


class Command(BaseCommand):
    help = 'Synchronize CVEs modified recently using last modification date range with checkpoint/resume support.'

    def add_arguments(self, parser):
        parser.add_argument('--hours', type=int, default=24, help='How many hours back to query by last-modified date.')
        parser.add_argument('--hours-back', type=int, default=None, help='Alias for --hours.')
        parser.add_argument('--page-size', type=int, default=0, help='resultsPerPage override (default from settings).')
        parser.add_argument('--limit', type=int, default=0, help='Stop after processing N records in this run.')
        parser.add_argument('--resume', action='store_true', help='Resume from the latest pending/running/failed checkpoint.')
        parser.add_argument('--async-task', action='store_true', help='Queue sync on Celery worker instead of running inline.')
        parser.add_argument(
            '--force-hours-window',
            action='store_true',
            help='Ignore last successful sync and always use --hours/--hours-back window.',
        )

    def handle(self, *args, **options):
        hours_back = options['hours_back'] if options['hours_back'] is not None else options['hours']
        hours_back = max(hours_back, 1)
        page_size = max(options['page_size'], 0)
        limit = options['limit'] or None

        if options['async_task']:
            task = sync_nvd_recent_task.delay(
                page_size=page_size,
                hours_back=hours_back,
                limit=limit,
                resume=options['resume'],
                force_hours_window=options['force_hours_window'],
            )
            self.stdout.write(self.style.SUCCESS(f'Sync queued in Celery. task_id={task.id}'))
            return

        from knowledge_base.tasks import _recent_filters

        filters = _recent_filters(hours_back=hours_back, force_hours_window=options['force_hours_window'])
        job = create_sync_job(
            command='sync_nvd_recent',
            job_type='nvd_recent',
            filters=filters,
            page_size=page_size,
            resume=options['resume'],
        )
        run_sync_job(job=job, client=NVDClient(), filters=filters, page_size=page_size, limit=limit)

        self.stdout.write(
            self.style.SUCCESS(
                'Recent NVD sync complete '
                f'({filters["lastModStartDate"]} -> {filters["lastModEndDate"]}). '
                f'fetched={job.total_fetched} created={job.created_count} updated={job.updated_count} '
                f'ignored={job.ignored_count} errors={job.error_count} '
                f'checkpoint_start_index={job.last_start_index}'
            )
        )

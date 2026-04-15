from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from knowledge_base.integrations.nvd_client import NVDClient
from knowledge_base.integrations.nvd_sync import create_sync_job, run_sync_job
from knowledge_base.tasks import sync_nvd_cves_task


class Command(BaseCommand):
    help = 'Synchronize NVD CVEs with pagination, resume/checkpoints and optional Celery execution.'

    def add_arguments(self, parser):
        parser.add_argument('--cve-id', type=str, default='', help='Filter by exact cveId.')
        parser.add_argument('--cpe-name', type=str, default='', help='Filter by cpeName.')
        parser.add_argument('--has-kev', action='store_true', help='Filter only KEV CVEs.')
        parser.add_argument('--last-mod-start-date', type=str, default='', help='ISO date filter for lastModStartDate.')
        parser.add_argument('--last-mod-end-date', type=str, default='', help='ISO date filter for lastModEndDate.')
        parser.add_argument('--hours-back', type=int, default=0, help='Set lastModStartDate/endDate from now - N hours.')
        parser.add_argument('--page-size', type=int, default=0, help='resultsPerPage override (default from settings).')
        parser.add_argument('--limit', type=int, default=0, help='Stop after processing N records in this run.')
        parser.add_argument('--resume', action='store_true', help='Resume from last checkpoint.')
        parser.add_argument('--async-task', action='store_true', help='Queue sync on Celery worker.')

    def handle(self, *args, **options):
        filters = {
            'cveId': options['cve_id'] or None,
            'cpeName': options['cpe_name'] or None,
            'hasKev': 'true' if options['has_kev'] else None,
            'lastModStartDate': options['last_mod_start_date'] or None,
            'lastModEndDate': options['last_mod_end_date'] or None,
        }

        hours_back = max(options['hours_back'], 0)
        if hours_back > 0 and not options['last_mod_start_date']:
            end = timezone.now()
            start = end - timedelta(hours=hours_back)
            filters['lastModStartDate'] = start.isoformat(timespec='seconds').replace('+00:00', 'Z')
            filters['lastModEndDate'] = end.isoformat(timespec='seconds').replace('+00:00', 'Z')

        clean_filters = {k: v for k, v in filters.items() if v is not None}
        page_size = max(options['page_size'], 0)
        limit = options['limit'] or None

        if options['async_task']:
            task = sync_nvd_cves_task.delay(
                filters=clean_filters,
                page_size=page_size,
                limit=limit,
                resume=options['resume'],
            )
            self.stdout.write(self.style.SUCCESS(f'Sync queued in Celery. task_id={task.id}'))
            return

        job = create_sync_job(
            command='sync_nvd_cves',
            job_type='nvd_cves',
            filters=clean_filters,
            page_size=page_size,
            resume=options['resume'],
        )
        run_sync_job(job=job, client=NVDClient(), filters=clean_filters, page_size=page_size, limit=limit)

        self.stdout.write(
            self.style.SUCCESS(
                'NVD sync complete. '
                f'fetched={job.total_fetched} created={job.created_count} updated={job.updated_count} '
                f'ignored={job.ignored_count} errors={job.error_count} '
                f'checkpoint_start_index={job.last_start_index}'
            )
        )

from django.core.management.base import BaseCommand

from knowledge_base.tasks import sync_nvd_backfill_task


class Command(BaseCommand):
    help = 'Run long NVD historical backfill with pagination, checkpointing and resume support.'

    def add_arguments(self, parser):
        parser.add_argument('--hours-back', type=int, default=24 * 365, help='How many hours to backfill from now.')
        parser.add_argument('--page-size', type=int, default=0, help='resultsPerPage override (default from settings).')
        parser.add_argument('--max-pages', type=int, default=0, help='Optional page cap for controlled runs.')
        parser.add_argument('--resume', action='store_true', help='Resume from latest backfill checkpoint.')
        parser.add_argument('--stop-at-existing', action='store_true', help='Stop when an already-existing CVE is found.')
        parser.add_argument('--inline', action='store_true', help='Run inline instead of queueing Celery task.')

    def handle(self, *args, **options):
        kwargs = {
            'hours_back': max(int(options['hours_back']), 1),
            'page_size': max(int(options['page_size']), 0),
            'max_pages': int(options['max_pages']) or None,
            'resume': bool(options['resume']),
            'stop_at_existing': bool(options['stop_at_existing']),
        }

        if options['inline']:
            result = sync_nvd_backfill_task.apply(kwargs=kwargs)
            job_id = result.get()
            self.stdout.write(self.style.SUCCESS(f'Backfill run completed inline. job_id={job_id}'))
            return

        task = sync_nvd_backfill_task.delay(**kwargs)
        self.stdout.write(self.style.SUCCESS(f'Backfill queued in Celery. task_id={task.id}'))

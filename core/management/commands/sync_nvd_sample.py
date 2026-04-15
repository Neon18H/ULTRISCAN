from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Placeholder for future NVD synchronization workflow.'

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.WARNING(
                'sync_nvd_sample aún no descarga datos externos. '
                'Este comando está preparado para implementar sincronización incremental de NVD en futuras versiones.'
            )
        )

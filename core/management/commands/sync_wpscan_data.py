from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Placeholder for future WPScan synchronization workflow.'

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.WARNING(
                'sync_wpscan_data aún no descarga datos externos. '
                'Este comando está preparado para integrar datasets de WPScan en futuras versiones.'
            )
        )

import os

from celery import Celery

# Railway should provide DJANGO_SETTINGS_MODULE per-service.
# Keep a development fallback for local usage.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vulnsight.settings.development')

app = Celery('vulnsight')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()


@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')

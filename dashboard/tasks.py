from celery import shared_task


@shared_task
def refresh_dashboard_metrics() -> str:
    return 'ok'

#!/bin/sh
set -e

echo "Current dir: $(pwd)"
echo "Listing files:"
ls -la

echo "Python version:"
python --version

echo "Celery version:"
celery --version

echo "DJANGO_SETTINGS_MODULE=${DJANGO_SETTINGS_MODULE:-vulnsight.settings.development}"
echo "CELERY_BROKER_URL=${CELERY_BROKER_URL:-<not-set>}"
echo "Starting Celery worker..."

exec celery -A vulnsight worker -l debug

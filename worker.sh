#!/bin/sh
set -e

echo "[worker] Starting Celery worker..."
echo "[worker] DJANGO_SETTINGS_MODULE=${DJANGO_SETTINGS_MODULE:-vulnsight.settings.development}"
exec celery -A vulnsight worker -l info

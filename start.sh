#!/bin/sh
set -e

echo "[start] Applying database migrations..."
python manage.py migrate --noinput

echo "[start] Seeding initial data..."
python manage.py seed_initial_data

echo "[start] Collecting static files..."
python manage.py collectstatic --noinput

echo "[start] Starting Gunicorn..."
exec gunicorn vulnsight.wsgi:application --bind 0.0.0.0:${PORT:-8000} --workers 3 --timeout 120

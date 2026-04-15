#!/usr/bin/env bash
set -e

echo "[start] Esperando DB..."
if [ -n "${DATABASE_URL}" ]; then
python - <<'PY'
import os
import socket
import time
from urllib.parse import urlparse

parsed = urlparse(os.getenv('DATABASE_URL', ''))
if parsed.hostname:
    for _ in range(30):
        try:
            with socket.create_connection((parsed.hostname, parsed.port or 5432), timeout=2):
                print('[start] DB disponible')
                break
        except OSError:
            print('[start] Esperando PostgreSQL...')
            time.sleep(2)
PY
fi

python manage.py migrate --noinput
python manage.py collectstatic --noinput
exec gunicorn vulnsight.wsgi:application -c gunicorn.conf.py

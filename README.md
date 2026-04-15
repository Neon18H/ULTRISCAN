# vulnsight

Plataforma web defensiva y autorizada de gestión de vulnerabilidades, inspirada en flujos de Tenable/Nessus, basada en Django + PostgreSQL + Celery + Redis.

## Arquitectura
Apps: `core`, `accounts`, `assets`, `scan_profiles`, `scans`, `integrations`, `knowledge_base`, `findings`, `dashboard`.

## Flujo de escaneo
1. Se registra un activo autorizado.
2. Se crea `ScanExecution` con un `ScanProfile`.
3. Celery ejecuta Nmap con salida XML.
4. Se guardan `RawEvidence` y `ServiceFinding`.
5. Motor de correlación cruza evidencias contra `knowledge_base`.
6. Se generan `Finding` con severidad/confianza/remediación.

## Ejecución local
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python manage.py migrate
python manage.py createsuperuser
python manage.py seed_initial_data
python manage.py runserver
```

## Docker local
```bash
docker compose up --build
```

## Railway
Variables requeridas:
- SECRET_KEY
- DEBUG=False
- DATABASE_URL
- ALLOWED_HOSTS
- CSRF_TRUSTED_ORIGINS
- REDIS_URL
- CELERY_BROKER_URL
- CELERY_RESULT_BACKEND
- DJANGO_SETTINGS_MODULE=vulnsight.settings.production
- PORT (Railway lo inyecta)

En cada deploy, `start.sh` ejecuta automáticamente:
1. `python manage.py migrate --noinput`
2. `python manage.py collectstatic --noinput`
3. `gunicorn vulnsight.wsgi:application -c gunicorn.conf.py`

Comandos útiles Railway:
```bash
railway logs
railway shell
python manage.py seed_initial_data
```

## Troubleshooting
- Si `collectstatic` falla, revisar `STATIC_ROOT` y permisos.
- Si no conecta DB, validar `DATABASE_URL`.
- Si Celery no consume tareas, revisar `REDIS_URL`/`CELERY_BROKER_URL`.

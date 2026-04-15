# vulnsight

Plataforma web defensiva y autorizada de gestión de vulnerabilidades, inspirada en flujos tipo Tenable/Nessus, basada en Django + PostgreSQL + Celery + Redis.

## Arquitectura
Apps locales del proyecto:
- `core` (modelo base abstracto)
- `accounts`
- `assets`
- `scan_profiles`
- `scans`
- `integrations`
- `knowledge_base`
- `findings`
- `dashboard`

> Las migraciones de todas las apps con modelos persistentes **ya están versionadas en el repositorio** (`0001_initial.py`).

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

## Verificación de migraciones antes de deploy
Antes de merge/deploy, ejecuta:

```bash
python manage.py makemigrations --check --dry-run
```

Si este comando falla, existen cambios de modelo sin migrar.

También puedes usar el script de verificación:

```bash
./scripts/deploy_check.sh
```

Este script valida:
1. que no haya migraciones pendientes de crear
2. que el proyecto cumpla checks de despliegue de Django

## Cómo crear nuevas migraciones correctamente
Cuando cambies modelos:

```bash
python manage.py makemigrations
python manage.py migrate
```

Después, confirma que no quedaron cambios pendientes:

```bash
python manage.py makemigrations --check --dry-run
```

Y versiona los archivos `*/migrations/*.py` en Git.

## Docker local
```bash
docker compose up --build
```

## Railway (deploy automático)
Variables requeridas:
- `SECRET_KEY`
- `DEBUG=False`
- `DATABASE_URL`
- `ALLOWED_HOSTS` (CSV, ejemplo: `vulnsight.up.railway.app,localhost`)
- `CSRF_TRUSTED_ORIGINS` (CSV con esquema, ejemplo: `https://vulnsight.up.railway.app`)
- `REDIS_URL`
- `CELERY_BROKER_URL`
- `CELERY_RESULT_BACKEND`
- `DJANGO_SETTINGS_MODULE=vulnsight.settings.production`
- `PORT` (Railway lo inyecta automáticamente)

En cada deploy, el contenedor ejecuta automáticamente y en orden:
1. `python manage.py migrate --noinput`
2. `python manage.py collectstatic --noinput`
3. `gunicorn vulnsight.wsgi:application --bind 0.0.0.0:${PORT:-8000} --workers 3 --timeout 120`

Esto evita que la aplicación arranque con tablas faltantes.

## Troubleshooting

### `relation "..." does not exist`
Causa típica: faltan migraciones aplicadas o no versionadas.

Pasos:
1. `python manage.py showmigrations`
2. `python manage.py migrate`
3. Verifica migraciones pendientes:
   `python manage.py makemigrations --check --dry-run`
4. Si faltan archivos de migración, créalos y súbelos al repo.

### `No migrations to apply` pero faltan tablas
Causa típica: app con modelos sin `0001_initial.py` versionado en el historial.

Pasos:
1. valida que exista `migrations/0001_initial.py` en la app
2. revisa dependencias entre migraciones
3. en entorno limpio, ejecuta `python manage.py migrate`

### `DisallowedHost`
Configura `ALLOWED_HOSTS` correctamente (CSV), incluyendo el dominio Railway.

Ejemplo:
```bash
ALLOWED_HOSTS=vulnsight.up.railway.app,localhost,127.0.0.1
```

### Static files missing
1. verifica `STATIC_ROOT` (`/app/staticfiles` dentro del contenedor)
2. ejecuta `python manage.py collectstatic --noinput`
3. confirma que `whitenoise.middleware.WhiteNoiseMiddleware` esté activo
4. confirma `STATICFILES_STORAGE=whitenoise.storage.CompressedManifestStaticFilesStorage`

## Comandos útiles Railway
```bash
railway logs
railway shell
python manage.py showmigrations
python manage.py seed_initial_data
```

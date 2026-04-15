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
python manage.py runserver
```

> Nota: en despliegue, la base de conocimiento inicial se carga automáticamente. El cliente final no debe ejecutar comandos manuales para habilitar correlación.

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
Este mismo repositorio se despliega en **dos servicios separados** en Railway:

1. **Servicio web** (Gunicorn)
2. **Servicio worker** `ultriscan-worker` (Celery)

No se necesita otro repo ni otro proyecto Django; ambos servicios usan la misma imagen/código y cambian solo el Start Command.

### Variables requeridas (web y worker)
- `SECRET_KEY`
- `DEBUG=False`
- `DJANGO_SETTINGS_MODULE=vulnsight.settings.production`
- `DATABASE_URL`
- `ALLOWED_HOSTS` (CSV, ejemplo: `vulnsight.up.railway.app,localhost`)
- `CSRF_TRUSTED_ORIGINS` (CSV con esquema, ejemplo: `https://vulnsight.up.railway.app`)
- `REDIS_URL`
- `CELERY_BROKER_URL`
- `CELERY_RESULT_BACKEND`
- `PORT` (Railway lo inyecta para el servicio web)

### Servicio web
Start Command (actual):
- `./start.sh`

En cada deploy del web, el contenedor ejecuta automáticamente y en orden:
1. `python manage.py migrate --noinput`
2. `python manage.py seed_initial_data`
3. `python manage.py collectstatic --noinput`
4. `gunicorn vulnsight.wsgi:application --bind 0.0.0.0:${PORT:-8000} --workers 3 --timeout 120`

### Servicio worker `ultriscan-worker`
Configura un segundo servicio Railway apuntando al **mismo repositorio** y usa:

- Start Command: `./worker.sh`

El worker:
- no necesita dominio público
- consume la cola Redis (`CELERY_BROKER_URL`)
- guarda resultados usando `CELERY_RESULT_BACKEND`
- usa Postgres y Redis vía variables de entorno del servicio
- ejecuta scans en proceso separado del web

`seed_initial_data` es idempotente: puede ejecutarse en cada deploy sin duplicar registros. La plataforma administra centralmente la Knowledge Base y reutiliza esas reglas para todas las organizaciones.

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
```

## Enterprise UX y reporting (fase actual)

### Autenticación enterprise
- Login y registro rediseñados con layout dedicado `auth_base.html`, visual SaaS corporativo, mensajes limpios y validaciones de contraseña con `django.contrib.auth.password_validation`.
- Login soporta opción **Remember me** (si no se marca, sesión expira al cerrar navegador).

### Findings con filtros avanzados
- `/findings/` ahora soporta filtros combinables por query params: `severity`, `status`, `confidence`, `asset`, `service`, `port`, `date_from`, `date_to`, `query`.
- Los filtros persisten en paginación y se reflejan en chips visuales.
- Export técnico respeta exactamente los filtros activos.

### Reportes PDF
- Se agregó un módulo dedicado `dashboard/reports.py` con un generador PDF interno (sin dependencias nativas externas).
- Nuevas rutas:
  - `GET /reports/executive-summary.pdf` (Executive Summary)
  - `GET /findings/export/technical-pdf/` (Technical Findings filtrado)
- Ambos reportes respetan multitenancy (organización activa del usuario autenticado).


## Integración NVD (Knowledge Base interna)
Se incorporó una integración oficial con **NVD CVE API 2.0** para poblar la base local (`knowledge_base`) con CVEs y metadatos relacionados.

### Objetivo de diseño
- **No** consultar NVD en tiempo real durante cada scan.
- **Sí** sincronizar CVEs a PostgreSQL y reutilizarlos en la correlación local.
- Mantener el motor actual de correlación por exposición y enriquecerlo progresivamente.

### Endpoints
- CVE API actual: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- Estructura preparada para futura extensión de historial: `https://services.nvd.nist.gov/rest/json/cvehistory/2.0`

### Variables de entorno
- `NVD_API_KEY` (opcional, recomendado para cuotas más amplias)
- `NVD_SYNC_PAGE_SIZE` (opcional, default `200`)

### Comandos de sincronización
```bash
python manage.py sync_nvd_sample
python manage.py sync_nvd_cves
python manage.py sync_nvd_recent
```

Opciones útiles:
- `sync_nvd_cves --cve-id CVE-2024-12345`
- `sync_nvd_cves --cpe-name cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*`
- `sync_nvd_cves --has-kev`
- `sync_nvd_cves --last-mod-start-date 2026-04-01T00:00:00Z --last-mod-end-date 2026-04-15T00:00:00Z`
- `sync_nvd_recent --hours 24`

Todos estos comandos hacen **upsert** (sin duplicados por `cve_id`) y registran trazabilidad de ejecución en `AdvisorySyncJob`.

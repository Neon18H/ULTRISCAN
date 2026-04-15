#!/usr/bin/env bash
set -e

echo "[entrypoint] Iniciando contenedor vulnsight"
python --version
if [ -z "${DJANGO_SETTINGS_MODULE}" ]; then
  export DJANGO_SETTINGS_MODULE=vulnsight.settings.production
fi
echo "[entrypoint] Configuración: ${DJANGO_SETTINGS_MODULE}"
exec "$@"

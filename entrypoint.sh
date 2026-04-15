#!/bin/sh
set -e

echo "[entrypoint] Starting vulnsight container"

if [ -z "${DJANGO_SETTINGS_MODULE}" ]; then
  export DJANGO_SETTINGS_MODULE="vulnsight.settings.production"
  echo "[entrypoint] DJANGO_SETTINGS_MODULE not set, defaulting to ${DJANGO_SETTINGS_MODULE}"
else
  echo "[entrypoint] DJANGO_SETTINGS_MODULE=${DJANGO_SETTINGS_MODULE}"
fi

if [ "$#" -eq 0 ]; then
  exec ./start.sh
fi

exec "$@"

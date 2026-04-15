#!/bin/sh
set -e

python manage.py makemigrations --check --dry-run
python manage.py check --deploy

from pathlib import Path

import dj_database_url
import environ

BASE_DIR = Path(__file__).resolve().parent.parent.parent
env = environ.Env(DEBUG=(bool, False))
env.read_env(BASE_DIR / '.env')


def _csv_to_list(value: str) -> list[str]:
    return [item.strip() for item in value.split(',') if item.strip()]


SECRET_KEY = env('SECRET_KEY', default='dev-insecure-key')
DEBUG = env.bool('DEBUG', default=False)

ALLOWED_HOSTS = _csv_to_list(env('ALLOWED_HOSTS', default='localhost,127.0.0.1'))
CSRF_TRUSTED_ORIGINS = _csv_to_list(env('CSRF_TRUSTED_ORIGINS', default=''))

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'core',
    'accounts',
    'assets',
    'scan_profiles',
    'scans',
    'integrations',
    'knowledge_base',
    'findings',
    'dashboard',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'vulnsight.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'accounts.context_processors.tenant_context',
            ]
        },
    }
]

WSGI_APPLICATION = 'vulnsight.wsgi.application'

DATABASES = {
    'default': dj_database_url.parse(
        env('DATABASE_URL', default='postgresql://postgres:postgres@localhost:5432/vulnsight'),
        conn_max_age=600,
        ssl_require=not DEBUG,
    )
}

LANGUAGE_CODE = 'es-es'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': ['rest_framework.permissions.IsAuthenticated'],
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ],
}

REDIS_URL = env('REDIS_URL', default='redis://localhost:6379/0')
CELERY_BROKER_URL = env('CELERY_BROKER_URL', default=REDIS_URL)
CELERY_RESULT_BACKEND = env('CELERY_RESULT_BACKEND', default=REDIS_URL)
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = env.int('CELERY_TASK_TIME_LIMIT', default=3600)
CELERY_TASK_SOFT_TIME_LIMIT = env.int('CELERY_TASK_SOFT_TIME_LIMIT', default=3300)
CELERY_WORKER_PREFETCH_MULTIPLIER = env.int('CELERY_WORKER_PREFETCH_MULTIPLIER', default=1)
CELERY_TASK_ACKS_LATE = True
CELERY_TASK_REJECT_ON_WORKER_LOST = True

SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'json': {
            'format': '{"level":"%(levelname)s","time":"%(asctime)s","logger":"%(name)s","message":"%(message)s"}'
        }
    },
    'handlers': {'console': {'class': 'logging.StreamHandler', 'formatter': 'json'}},
    'root': {'handlers': ['console'], 'level': 'INFO'},
}

LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'dashboard-home'
LOGOUT_REDIRECT_URL = 'login'

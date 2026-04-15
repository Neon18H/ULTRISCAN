from .base import *  # noqa

DEBUG = env.bool('DEBUG', default=True)
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

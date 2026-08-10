from .base import *  # noqa: F403


LOCAL_FRONTEND_ORIGINS = [
    "http://127.0.0.1:5173",
    "http://localhost:5173",
]
LOCAL_BACKEND_ORIGINS = [
    "http://127.0.0.1:8000",
    "http://localhost:8000",
]

DEBUG = env_bool("DJANGO_DEBUG", True)  # noqa: F405
CSRF_TRUSTED_ORIGINS = env_list(  # noqa: F405
    "DJANGO_CSRF_TRUSTED_ORIGINS",
    ",".join([*LOCAL_FRONTEND_ORIGINS, *LOCAL_BACKEND_ORIGINS]),
)
CORS_ALLOWED_ORIGINS = env_list(  # noqa: F405
    "DJANGO_CORS_ALLOWED_ORIGINS",
    ",".join(LOCAL_FRONTEND_ORIGINS),
)
SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", False)  # noqa: F405
CSRF_COOKIE_SECURE = env_bool("CSRF_COOKIE_SECURE", False)  # noqa: F405
# The local development profile uses an already-installed JADX executable when
# present. Production/base settings remain opt-in and never download tooling.
MSAP_JADX_ENABLED = env_bool("MSAP_JADX_ENABLED", True)  # noqa: F405

from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

import os


BASE_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BASE_DIR.parent

load_dotenv(BASE_DIR / ".env")


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_list(name: str, default: str = "") -> list[str]:
    value = os.getenv(name, default)
    return [item.strip() for item in value.split(",") if item.strip()]


def database_config() -> dict:
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        parsed = urlparse(database_url)
        if parsed.scheme == "sqlite":
            return {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": parsed.path.lstrip("/") or BASE_DIR / "db.sqlite3",
            }
        if parsed.scheme in {"postgres", "postgresql"}:
            return {
                "ENGINE": "django.db.backends.postgresql",
                "NAME": parsed.path.lstrip("/"),
                "USER": parsed.username or "",
                "PASSWORD": parsed.password or "",
                "HOST": parsed.hostname or "",
                "PORT": str(parsed.port or 5432),
                "OPTIONS": {"sslmode": os.getenv("POSTGRES_SSLMODE", "prefer")},
            }
        raise ValueError(f"Unsupported DATABASE_URL scheme: {parsed.scheme}")

    if os.getenv("POSTGRES_HOST"):
        return {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("POSTGRES_DB", "msap"),
            "USER": os.getenv("POSTGRES_USER", "msap_app"),
            "PASSWORD": os.getenv("POSTGRES_PASSWORD", ""),
            "HOST": os.getenv("POSTGRES_HOST", "localhost"),
            "PORT": os.getenv("POSTGRES_PORT", "5432"),
            "OPTIONS": {"sslmode": os.getenv("POSTGRES_SSLMODE", "prefer")},
        }

    return {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }


SECRET_KEY = os.getenv("DJANGO_SECRET_KEY") or os.getenv("SECRET_KEY", "unsafe-development-secret-key")
DEBUG = env_bool("DJANGO_DEBUG", env_bool("DEBUG", False))
ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")
CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS")
MSAP_ENVIRONMENT = os.getenv("MSAP_ENVIRONMENT", "development")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "corsheaders",
    "drf_spectacular",
    "apps.projects",
    "apps.audits",
    "apps.storage",
    "apps.apk_files",
    "apps.analyzers",
    "apps.normalization",
    "apps.appsec_rules",
    "apps.triage_rules",
    "apps.findings",
    "apps.indicators",
    "apps.evidence",
    "apps.scoring",
    "apps.reports",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "msap.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "msap.wsgi.application"
ASGI_APPLICATION = "msap.asgi.application"

DATABASES = {"default": database_config()}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

CORS_ALLOWED_ORIGINS = env_list(
    "DJANGO_CORS_ALLOWED_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173",
)

SPECTACULAR_SETTINGS = {
    "TITLE": "MSAP API",
    "DESCRIPTION": "Backend API foundation for MSAP.",
    "VERSION": "0.1.0",
}

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND") or REDIS_URL
CELERY_TASK_ALWAYS_EAGER = env_bool("CELERY_TASK_ALWAYS_EAGER", False)
CELERY_TASK_EAGER_PROPAGATES = env_bool("CELERY_TASK_EAGER_PROPAGATES", True)
CELERY_TASK_DEFAULT_QUEUE = os.getenv("CELERY_TASK_DEFAULT_QUEUE", "analysis")
CELERY_TASK_TIME_LIMIT = int(os.getenv("CELERY_TASK_TIME_LIMIT", "900"))

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "http://localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "")
MINIO_SECURE = env_bool("MINIO_SECURE", False)
MINIO_BUCKET_APK_UPLOADS = os.getenv("MINIO_BUCKET_APK_UPLOADS", "msap-apk-uploads")
MINIO_BUCKET_ARTIFACTS = os.getenv("MINIO_BUCKET_ARTIFACTS", "msap-artifacts")
MINIO_BUCKET_EVIDENCE = os.getenv("MINIO_BUCKET_EVIDENCE", "msap-evidence")
MINIO_BUCKET_REPORTS = os.getenv("MINIO_BUCKET_REPORTS", "msap-reports")
MINIO_BUCKET_EXPORTS = os.getenv("MINIO_BUCKET_EXPORTS", "msap-exports")

MSAP_MAX_APK_SIZE_BYTES = int(os.getenv("MSAP_MAX_APK_SIZE_BYTES", "524288000"))
MSAP_MAX_MANIFEST_SIZE_BYTES = int(
    os.getenv("MSAP_MAX_MANIFEST_SIZE_BYTES", str(4 * 1024 * 1024))
)
MSAP_MAX_APK_ZIP_ENTRIES = int(os.getenv("MSAP_MAX_APK_ZIP_ENTRIES", "10000"))
MSAP_LOCAL_APK_ROOT = os.getenv("MSAP_LOCAL_APK_ROOT", "")
MSAP_TEMP_DIR = os.getenv("MSAP_TEMP_DIR", "")
MSAP_VERIFY_DOWNLOADED_APK_SHA256 = env_bool(
    "MSAP_VERIFY_DOWNLOADED_APK_SHA256",
    True,
)
MSAP_UPLOAD_REQUIRE_SHA256 = env_bool("MSAP_UPLOAD_REQUIRE_SHA256", True)
MSAP_PRESIGNED_URL_EXPIRES_SECONDS = int(
    os.getenv(
        "MSAP_PRESIGNED_URL_EXPIRES_SECONDS",
        os.getenv("MSAP_PRESIGNED_URL_TTL_SECONDS", "900"),
    )
)
MSAP_PRESIGNED_URL_TTL_SECONDS = MSAP_PRESIGNED_URL_EXPIRES_SECONDS
MSAP_VERIFY_UPLOAD_WITH_HEAD = env_bool("MSAP_VERIFY_UPLOAD_WITH_HEAD", False)
MSAP_DEFAULT_RETENTION_POLICY = os.getenv("MSAP_DEFAULT_RETENTION_POLICY", "active_audit")
MSAP_REDACTION_ENABLED = env_bool("MSAP_REDACTION_ENABLED", True)

ANALYZER_RULES_PATH = os.getenv("ANALYZER_RULES_PATH", str(PROJECT_ROOT / "rules"))
ANALYZER_WORKDIR = os.getenv("ANALYZER_WORKDIR", "/tmp/msap-analysis")
ANALYZER_TIMEOUT_SECONDS = int(os.getenv("ANALYZER_TIMEOUT_SECONDS", "600"))

REPORT_DEFAULT_FORMAT = os.getenv("REPORT_DEFAULT_FORMAT", "json")
REPORT_BUCKET = os.getenv("REPORT_BUCKET", MINIO_BUCKET_REPORTS)
EXPORT_BUCKET = os.getenv("EXPORT_BUCKET", MINIO_BUCKET_EXPORTS)
REPORT_INCLUDE_EVIDENCE = env_bool("REPORT_INCLUDE_EVIDENCE", True)
REPORT_REDACTION_REQUIRED = env_bool("REPORT_REDACTION_REQUIRED", True)

AI_ASSISTANT_ENABLED = env_bool("AI_ASSISTANT_ENABLED", False)

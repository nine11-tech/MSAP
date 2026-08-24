from pathlib import Path
from datetime import timedelta
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
                "OPTIONS": {
                    "sslmode": os.getenv("POSTGRES_SSLMODE", "prefer"),
                    "connect_timeout": int(
                        os.getenv("POSTGRES_CONNECT_TIMEOUT_SECONDS", "3")
                    ),
                },
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
            "OPTIONS": {
                "sslmode": os.getenv("POSTGRES_SSLMODE", "prefer"),
                "connect_timeout": int(
                    os.getenv("POSTGRES_CONNECT_TIMEOUT_SECONDS", "3")
                ),
            },
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
    "axes",
    "apps.api",
    "apps.projects",
    "apps.audits",
    "apps.storage",
    "apps.apk_files",
    "apps.analyzers",
    "apps.normalization",
    "apps.appsec_rules",
    "apps.triage_rules",
    "apps.dynamic_analysis",
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
    "axes.middleware.AxesMiddleware",
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
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {
            "min_length": int(os.getenv("MSAP_PASSWORD_MIN_LENGTH", "12")),
        },
    },
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
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
}

CORS_ALLOWED_ORIGINS = env_list(
    "DJANGO_CORS_ALLOWED_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173",
)
CORS_EXPOSE_HEADERS = ["Content-Disposition"]
CORS_ALLOW_CREDENTIALS = True

AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesStandaloneBackend",
    "django.contrib.auth.backends.ModelBackend",
]

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "msap_sessionid")
SESSION_COOKIE_AGE = int(os.getenv("SESSION_COOKIE_AGE", str(8 * 60 * 60)))
SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", False)
CSRF_COOKIE_SECURE = env_bool("CSRF_COOKIE_SECURE", False)
CSRF_COOKIE_SAMESITE = os.getenv("CSRF_COOKIE_SAMESITE", "Lax")
CSRF_COOKIE_HTTPONLY = False

SECURE_SSL_REDIRECT = env_bool("SECURE_SSL_REDIRECT", False)
SECURE_HSTS_SECONDS = int(os.getenv("SECURE_HSTS_SECONDS", "0"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool("SECURE_HSTS_INCLUDE_SUBDOMAINS", False)
SECURE_HSTS_PRELOAD = env_bool("SECURE_HSTS_PRELOAD", False)
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_REFERRER_POLICY = "same-origin"

# Proxy-supplied forwarding headers are ignored unless the deployment explicitly
# opts in after configuring its reverse proxy to replace (not append to) them.
MSAP_TRUST_PROXY_HEADERS = env_bool("MSAP_TRUST_PROXY_HEADERS", False)
if MSAP_TRUST_PROXY_HEADERS:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    USE_X_FORWARDED_HOST = True

AXES_ENABLED = env_bool("AXES_ENABLED", True)
AXES_FAILURE_LIMIT = int(os.getenv("AXES_FAILURE_LIMIT", "5"))
AXES_COOLOFF_TIME = timedelta(
    minutes=int(os.getenv("AXES_COOLOFF_MINUTES", "15"))
)
AXES_LOCK_OUT_AT_FAILURE = True
AXES_RESET_ON_SUCCESS = True
AXES_RESET_COOL_OFF_ON_FAILURE_DURING_LOCKOUT = False
AXES_LOCKOUT_PARAMETERS = [["username", "ip_address"]]
AXES_HANDLER = "axes.handlers.database.AxesDatabaseHandler"
AXES_LOCKOUT_CALLABLE = "apps.api.security.axes_lockout_response"
AXES_HTTP_RESPONSE_CODE = 429
AXES_SENSITIVE_PARAMETERS = ["password", "csrfmiddlewaretoken"]
AXES_IPWARE_META_PRECEDENCE_ORDER = ("REMOTE_ADDR",)
if MSAP_TRUST_PROXY_HEADERS:
    AXES_IPWARE_META_PRECEDENCE_ORDER = (
        "HTTP_X_FORWARDED_FOR",
        "REMOTE_ADDR",
    )
    AXES_IPWARE_PROXY_COUNT = int(os.getenv("AXES_IPWARE_PROXY_COUNT", "1"))
    AXES_IPWARE_PROXY_TRUSTED_IPS = env_list(
        "AXES_IPWARE_PROXY_TRUSTED_IPS",
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
MSAP_STATUS_CACHE_SECONDS = int(os.getenv("MSAP_STATUS_CACHE_SECONDS", "5"))
MSAP_STATUS_TIMEOUT_SECONDS = float(
    os.getenv("MSAP_STATUS_TIMEOUT_SECONDS", "1.5")
)
MSAP_APPLICATION_VERSION = os.getenv("MSAP_APPLICATION_VERSION", "0.2.0")

MSAP_DYNAMIC_RUNNER_ENABLED = env_bool("MSAP_DYNAMIC_RUNNER_ENABLED", False)
MSAP_DYNAMIC_LAB_SCRIPT_DIR = Path(
    os.getenv(
        "MSAP_DYNAMIC_LAB_SCRIPT_DIR",
        str(PROJECT_ROOT / "scripts" / "dynamic-lab"),
    )
)
MSAP_DYNAMIC_RUNNER_TIMEOUT_SECONDS = int(
    os.getenv("MSAP_DYNAMIC_RUNNER_TIMEOUT_SECONDS", "3600")
)
# A value of 0 means "use per-stage defaults" inside the dynamic MVP runner.
MSAP_DYNAMIC_STAGE_TIMEOUT_SECONDS = int(
    os.getenv("MSAP_DYNAMIC_STAGE_TIMEOUT_SECONDS", "0")
)
MSAP_DYNAMIC_STAGE_TIMEOUTS_JSON = os.getenv("MSAP_DYNAMIC_STAGE_TIMEOUTS_JSON", "")
MSAP_DYNAMIC_STAGE_TIMEOUT_MIN_SECONDS = int(
    os.getenv("MSAP_DYNAMIC_STAGE_TIMEOUT_MIN_SECONDS", "1")
)
MSAP_DYNAMIC_STAGE_TIMEOUT_MAX_SECONDS = int(
    os.getenv("MSAP_DYNAMIC_STAGE_TIMEOUT_MAX_SECONDS", "1800")
)
MSAP_DYNAMIC_PLATFORM_TLS_PROBE_ENABLED = env_bool(
    "MSAP_DYNAMIC_PLATFORM_TLS_PROBE_ENABLED",
    False,
)
MSAP_DYNAMIC_MVP_DEVICE_SERIAL = os.getenv(
    "MSAP_DYNAMIC_MVP_DEVICE_SERIAL",
    "emulator-5554",
)
MSAP_DYNAMIC_MVP_DEVICE_NAME = os.getenv(
    "MSAP_DYNAMIC_MVP_DEVICE_NAME",
    "Lab-Root",
)
MSAP_DYNAMIC_MVP_DEVICE_POOL_SLUG = os.getenv(
    "MSAP_DYNAMIC_MVP_DEVICE_POOL_SLUG",
    "local-android-lab",
)

# The dynamic host agent is an explicitly enabled, token-authenticated local
# bridge. It stays disabled by default and binds to loopback unless an operator
# deliberately chooses a different development topology.
MSAP_DYNAMIC_HOST_AGENT_ENABLED = env_bool(
    "MSAP_DYNAMIC_HOST_AGENT_ENABLED",
    False,
)
MSAP_DYNAMIC_HOST_AGENT_URL = os.getenv("MSAP_DYNAMIC_HOST_AGENT_URL", "")
MSAP_DYNAMIC_HOST_AGENT_TOKEN = os.getenv("MSAP_DYNAMIC_HOST_AGENT_TOKEN", "")
MSAP_DYNAMIC_HOST_AGENT_TIMEOUT_SECONDS = int(
    os.getenv("MSAP_DYNAMIC_HOST_AGENT_TIMEOUT_SECONDS", "120")
)
MSAP_DYNAMIC_HOST_AGENT_BIND = os.getenv(
    "MSAP_DYNAMIC_HOST_AGENT_BIND",
    "127.0.0.1",
)
MSAP_DYNAMIC_HOST_AGENT_PORT = int(
    os.getenv("MSAP_DYNAMIC_HOST_AGENT_PORT", "8765")
)
MSAP_DYNAMIC_ADB_SERIAL = os.getenv(
    "MSAP_DYNAMIC_ADB_SERIAL",
    os.getenv("MSAP_ANDROID_SERIAL", "emulator-5554"),
)
MSAP_DYNAMIC_HOST_AGENT_MAX_APK_SIZE_BYTES = int(
    os.getenv("MSAP_DYNAMIC_HOST_AGENT_MAX_APK_SIZE_BYTES", str(300 * 1024 * 1024))
)
MSAP_DYNAMIC_HOST_AGENT_KEEP_TEMP_APKS = env_bool(
    "MSAP_DYNAMIC_HOST_AGENT_KEEP_TEMP_APKS",
    False,
)
MSAP_DYNAMIC_RUNNER_SYNC_DEMO_ENABLED = env_bool(
    "MSAP_DYNAMIC_RUNNER_SYNC_DEMO_ENABLED",
    False,
)
MSAP_DYNAMIC_LAB_PROXY_VALUE = os.getenv(
    "MSAP_DYNAMIC_LAB_PROXY_VALUE",
    "10.0.2.2:18080",
)
MSAP_DYNAMIC_INSTRUMENTED_SNAPSHOT_NAME = os.getenv(
    "MSAP_DYNAMIC_INSTRUMENTED_SNAPSHOT_NAME",
    "msap-instrumented-base",
)

# Ephemeral deterministic agent sandbox. Internal controller execution remains
# the default; operators must explicitly enable container launches and provide
# a gateway URL reachable from the configured Docker network.
MSAP_AGENT_CONTAINER_ENABLED = env_bool("MSAP_AGENT_CONTAINER_ENABLED", False)
MSAP_AGENT_CONTAINER_IMAGE = os.getenv(
    "MSAP_AGENT_CONTAINER_IMAGE",
    "msap-agent-runtime:local",
)
MSAP_AGENT_CONTAINER_NETWORK = os.getenv("MSAP_AGENT_CONTAINER_NETWORK", "")
MSAP_AGENT_GATEWAY_URL = os.getenv(
    "MSAP_AGENT_GATEWAY_URL",
    "http://host.docker.internal:8000",
)
MSAP_AGENT_RUN_TOKEN_TTL_SECONDS = int(
    os.getenv("MSAP_AGENT_RUN_TOKEN_TTL_SECONDS", "300")
)
MSAP_AGENT_CONTAINER_TIMEOUT_SECONDS = int(
    os.getenv("MSAP_AGENT_CONTAINER_TIMEOUT_SECONDS", "120")
)

# Sprint D assessment planning is backend-only and plan-only. Local and test
# environments default to the deterministic provider; production operators can
# opt into OpenAI without exposing the credential or model configuration to the
# browser or agent sandbox.
MSAP_ASSESSMENT_PLANNER_PROVIDER = os.getenv(
    "MSAP_ASSESSMENT_PLANNER_PROVIDER",
    "DETERMINISTIC",
).upper()
# Demo mode: the frontend default flows surface the simple Static -> Dynamic
# correlation journey and hide advanced operator controls by default. It is a
# UI preference only and never weakens backend enforcement.
MSAP_DEMO_MODE = env_bool("MSAP_DEMO_MODE", False)
MSAP_ASSESSMENT_PLANNER_MODEL = os.getenv(
    "MSAP_ASSESSMENT_PLANNER_MODEL",
    "gpt-5.6-luna",
)
MSAP_ASSESSMENT_PLANNER_OPENAI_API_KEY = os.getenv(
    "MSAP_OPENAI_API_KEY",
    os.getenv("OPENAI_API_KEY", ""),
)
MSAP_ASSESSMENT_PLANNER_TIMEOUT_SECONDS = min(
    120,
    max(5, int(os.getenv("MSAP_ASSESSMENT_PLANNER_TIMEOUT_SECONDS", "60"))),
)
MSAP_ASSESSMENT_PLANNER_MAX_RETRIES = min(
    2,
    max(0, int(os.getenv("MSAP_ASSESSMENT_PLANNER_MAX_RETRIES", "1"))),
)
MSAP_ASSESSMENT_PLANNER_RETRY_BASE_MILLISECONDS = min(
    2000,
    max(
        0,
        int(
            os.getenv(
                "MSAP_ASSESSMENT_PLANNER_RETRY_BASE_MILLISECONDS",
                "250",
            )
        ),
    ),
)
MSAP_ASSESSMENT_PLANNER_MAX_OUTPUT_TOKENS = min(
    16000,
    max(1024, int(os.getenv("MSAP_ASSESSMENT_PLANNER_MAX_OUTPUT_TOKENS", "3000"))),
)
MSAP_ASSESSMENT_PLANNER_REASONING_EFFORT = os.getenv(
    "MSAP_ASSESSMENT_PLANNER_REASONING_EFFORT",
    "low",
).lower()
if MSAP_ASSESSMENT_PLANNER_REASONING_EFFORT not in {
    "none",
    "low",
    "medium",
    "high",
    "xhigh",
}:
    MSAP_ASSESSMENT_PLANNER_REASONING_EFFORT = "low"

# Adaptive assessment proposes, validates, and persists a new plan only after a
# completed run. It never auto-approves or auto-executes. The database contract
# also caps the lineage at two cycles so configuration cannot create recursion.
MSAP_ASSESSMENT_MAX_ADAPTIVE_CYCLES = min(
    2,
    max(1, int(os.getenv("MSAP_ASSESSMENT_MAX_ADAPTIVE_CYCLES", "2"))),
)

# Approved AssessmentPlan execution is sequential and remains inside the
# existing run-scoped gateway. These backend-only bounds cannot be selected by
# the planner or browser.
MSAP_ASSESSMENT_EXECUTION_TOTAL_TIMEOUT_SECONDS = min(
    1800,
    max(60, int(os.getenv("MSAP_ASSESSMENT_EXECUTION_TOTAL_TIMEOUT_SECONDS", "600"))),
)
MSAP_ASSESSMENT_EXECUTION_MAX_RETRIES = min(
    1,
    max(0, int(os.getenv("MSAP_ASSESSMENT_EXECUTION_MAX_RETRIES", "1"))),
)
MSAP_ASSESSMENT_EXECUTION_MAX_TOOL_CALLS = min(
    96,
    max(1, int(os.getenv("MSAP_ASSESSMENT_EXECUTION_MAX_TOOL_CALLS", "96"))),
)
MSAP_ASSESSMENT_EXECUTION_MAX_OBSERVATION_BYTES = min(
    262144,
    max(8192, int(os.getenv("MSAP_ASSESSMENT_EXECUTION_MAX_OBSERVATION_BYTES", "65536"))),
)
MSAP_ASSESSMENT_EXECUTION_MAX_ARTIFACTS = min(
    100,
    max(1, int(os.getenv("MSAP_ASSESSMENT_EXECUTION_MAX_ARTIFACTS", "100"))),
)
MSAP_ASSESSMENT_EXECUTION_MAX_ARTIFACT_BYTES = min(
    25165824,
    max(1048576, int(os.getenv("MSAP_ASSESSMENT_EXECUTION_MAX_ARTIFACT_BYTES", "25165824"))),
)

# Adaptive assessment decisions remain inside a plan-derived immutable
# capability envelope. These bounds are backend-owned and cannot be enlarged by
# the browser, the planner, application observations, or the decision provider.
MSAP_AGENT_DECISION_PROVIDER = os.getenv(
    "MSAP_AGENT_DECISION_PROVIDER",
    MSAP_ASSESSMENT_PLANNER_PROVIDER,
).upper()
MSAP_AGENT_DECISION_MODEL = os.getenv(
    "MSAP_AGENT_DECISION_MODEL",
    "gpt-5.6-luna",
)
MSAP_AGENT_DECISION_REASONING_EFFORT = os.getenv(
    "MSAP_AGENT_DECISION_REASONING_EFFORT",
    "low",
).lower()
if MSAP_AGENT_DECISION_REASONING_EFFORT not in {
    "none",
    "low",
    "medium",
    "high",
    "xhigh",
}:
    MSAP_AGENT_DECISION_REASONING_EFFORT = "low"
MSAP_AGENT_DECISION_MAX_OUTPUT_TOKENS = min(
    4000,
    max(512, int(os.getenv("MSAP_AGENT_DECISION_MAX_OUTPUT_TOKENS", "1800"))),
)
MSAP_AGENT_MAX_DECISIONS = min(
    12,
    max(1, int(os.getenv("MSAP_AGENT_MAX_DECISIONS", "12"))),
)
MSAP_AGENT_MAX_TOOL_CALLS = min(
    12,
    max(1, int(os.getenv("MSAP_AGENT_MAX_TOOL_CALLS", "12"))),
)
MSAP_AGENT_MAX_PROVIDER_CALLS = min(
    50,
    max(1, int(os.getenv("MSAP_AGENT_MAX_PROVIDER_CALLS", "30"))),
)
MSAP_AGENT_MAX_CONSECUTIVE_FAILURES = min(
    2,
    max(1, int(os.getenv("MSAP_AGENT_MAX_CONSECUTIVE_FAILURES", "2"))),
)
MSAP_AGENT_MAX_DURATION_SECONDS = min(
    300,
    max(60, int(os.getenv("MSAP_AGENT_MAX_DURATION_SECONDS", "240"))),
)
MSAP_AGENT_MAX_ARTIFACTS = min(
    MSAP_ASSESSMENT_EXECUTION_MAX_ARTIFACTS,
    max(1, int(os.getenv("MSAP_AGENT_MAX_ARTIFACTS", "50"))),
)
MSAP_AGENT_MAX_EVIDENCE_RECORDS = min(
    100,
    max(1, int(os.getenv("MSAP_AGENT_MAX_EVIDENCE_RECORDS", "50"))),
)
MSAP_AGENT_MAX_STATE_CONTEXT_BYTES = min(
    131072,
    max(8192, int(os.getenv("MSAP_AGENT_MAX_STATE_CONTEXT_BYTES", "65536"))),
)

# Hard OpenAI call budget. The backend enforces this across mission generation,
# adaptive decision calls, provider retries, and retry runs. The frontend budget
# is advisory only; these bounds are authoritative and cannot be enlarged by the
# browser, planner, or decision provider.
MSAP_OPENAI_MAX_MISSION_GENERATION_CALLS = min(
    8,
    max(1, int(os.getenv("MSAP_OPENAI_MAX_MISSION_GENERATION_CALLS", "1"))),
)
MSAP_OPENAI_MAX_ADAPTIVE_DECISION_CALLS = min(
    50,
    max(1, int(os.getenv("MSAP_OPENAI_MAX_ADAPTIVE_DECISION_CALLS", "30"))),
)
MSAP_OPENAI_MAX_CORRELATION_CALLS = min(
    16,
    max(1, int(os.getenv("MSAP_OPENAI_MAX_CORRELATION_CALLS", "6"))),
)
MSAP_OPENAI_MAX_POC_PLANNING_CALLS = min(
    8,
    max(1, int(os.getenv("MSAP_OPENAI_MAX_POC_PLANNING_CALLS", "3"))),
)
MSAP_OPENAI_MAX_EVIDENCE_EXPLANATION_CALLS = min(
    50,
    max(1, int(os.getenv("MSAP_OPENAI_MAX_EVIDENCE_EXPLANATION_CALLS", "30"))),
)
MSAP_OPENAI_MAX_TOTAL_CALLS = min(
    50,
    max(
        1,
        int(
            os.getenv(
                "MSAP_OPENAI_MAX_TOTAL_CALLS",
                "50",
            )
        ),
    ),
)
MSAP_FRIDA_SCRIPT_GENERATION_PROVIDER = os.getenv(
    "MSAP_FRIDA_SCRIPT_GENERATION_PROVIDER",
    "OPENAI",
).upper()
if MSAP_FRIDA_SCRIPT_GENERATION_PROVIDER not in {"OPENAI", "DETERMINISTIC"}:
    MSAP_FRIDA_SCRIPT_GENERATION_PROVIDER = "OPENAI"
MSAP_EVIDENCE_EXPLANATION_PROVIDER = os.getenv(
    "MSAP_EVIDENCE_EXPLANATION_PROVIDER",
    "OPENAI",
).upper()
if MSAP_EVIDENCE_EXPLANATION_PROVIDER not in {"OPENAI", "DETERMINISTIC", "DISABLED"}:
    MSAP_EVIDENCE_EXPLANATION_PROVIDER = "OPENAI"

# Dynamic lab runtime mode. WINDOWS_HOST_AGENT uses Windows adb.exe/Frida via the
# Windows Host Agent; WSL_BRIDGED keeps the legacy WSL bridge. The default stays
# explicit so operators always choose a topology rather than guessing silently.
MSAP_DYNAMIC_LAB_MODE = os.getenv(
    "MSAP_DYNAMIC_LAB_MODE",
    "WINDOWS_HOST_AGENT",
).upper()
if MSAP_DYNAMIC_LAB_MODE not in {"WINDOWS_HOST_AGENT", "WSL_BRIDGED"}:
    MSAP_DYNAMIC_LAB_MODE = "WINDOWS_HOST_AGENT"
MSAP_WINDOWS_ANDROID_SDK_ROOT = os.getenv("MSAP_WINDOWS_ANDROID_SDK_ROOT", "")
MSAP_WINDOWS_ADB_PATH = os.getenv("MSAP_WINDOWS_ADB_PATH", "")
MSAP_WINDOWS_FRIDA_PATH = os.getenv("MSAP_WINDOWS_FRIDA_PATH", "")
MSAP_ANDROID_EMULATOR_SERIAL = os.getenv(
    "MSAP_ANDROID_EMULATOR_SERIAL",
    os.getenv("MSAP_DYNAMIC_ADB_SERIAL", "emulator-5554"),
)
MSAP_TARGET_PACKAGE = os.getenv("MSAP_TARGET_PACKAGE", "owasp.sat.agoat")

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "http://127.0.0.1:9000")
MINIO_PUBLIC_ENDPOINT = os.getenv("MINIO_PUBLIC_ENDPOINT", MINIO_ENDPOINT)
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
MSAP_MAX_APK_UNCOMPRESSED_BYTES = int(
    os.getenv("MSAP_MAX_APK_UNCOMPRESSED_BYTES", str(1024 * 1024 * 1024))
)
MSAP_MAX_APK_ENTRY_BYTES = int(
    os.getenv("MSAP_MAX_APK_ENTRY_BYTES", str(256 * 1024 * 1024))
)
MSAP_MAX_APK_COMPRESSION_RATIO = float(
    os.getenv("MSAP_MAX_APK_COMPRESSION_RATIO", "200")
)
MSAP_MAX_DEX_BYTES = int(os.getenv("MSAP_MAX_DEX_BYTES", str(256 * 1024 * 1024)))
MSAP_MAX_NORMALIZED_MATCHES = int(os.getenv("MSAP_MAX_NORMALIZED_MATCHES", "500"))
MSAP_SOURCE_INDEX_ENABLED = env_bool("MSAP_SOURCE_INDEX_ENABLED", True)
MSAP_JADX_ENABLED = env_bool("MSAP_JADX_ENABLED", False)
MSAP_SOURCE_INDEX_TIMEOUT_SECONDS = int(
    os.getenv("MSAP_SOURCE_INDEX_TIMEOUT_SECONDS", "300")
)
MSAP_SOURCE_INDEX_MAX_DOCUMENTS = int(
    os.getenv("MSAP_SOURCE_INDEX_MAX_DOCUMENTS", "5000")
)
MSAP_SOURCE_INDEX_MAX_DOCUMENT_BYTES = int(
    os.getenv("MSAP_SOURCE_INDEX_MAX_DOCUMENT_BYTES", str(2 * 1024 * 1024))
)
MSAP_SOURCE_INDEX_MAX_TOTAL_BYTES = int(
    os.getenv("MSAP_SOURCE_INDEX_MAX_TOTAL_BYTES", str(100 * 1024 * 1024))
)
MSAP_SOURCE_LINE_RANGE_LIMIT = int(
    os.getenv("MSAP_SOURCE_LINE_RANGE_LIMIT", "200")
)
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
# Upload confirmation always performs a server-side HEAD. This legacy setting
# remains parseable for compatible deployments but no longer disables proof.
MSAP_VERIFY_UPLOAD_WITH_HEAD = env_bool("MSAP_VERIFY_UPLOAD_WITH_HEAD", True)
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
MSAP_REPORT_AUTHOR = os.getenv("MSAP_REPORT_AUTHOR", "MSAP Analyst")
MSAP_REPORT_ORGANIZATION = os.getenv("MSAP_REPORT_ORGANIZATION", "MSAP")
MSAP_REPORT_CLASSIFICATION = os.getenv(
    "MSAP_REPORT_CLASSIFICATION",
    "Security Assessment Report",
)
MSAP_REPORT_VERSION = os.getenv("MSAP_REPORT_VERSION", "1.0")

AI_ASSISTANT_ENABLED = env_bool("AI_ASSISTANT_ENABLED", False)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "security": {
            "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "security",
        },
    },
    "loggers": {
        "msap.security": {
            "handlers": ["console"],
            "level": os.getenv("MSAP_SECURITY_LOG_LEVEL", "INFO"),
            "propagate": False,
        },
    },
}

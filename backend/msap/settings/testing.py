from .base import *  # noqa: F403


DEBUG = False
MSAP_ENVIRONMENT = "testing"
MSAP_SOURCE_INDEX_ENABLED = False
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
AXES_ENABLED = False
MSAP_ASSESSMENT_PLANNER_PROVIDER = "DETERMINISTIC"
MSAP_ASSESSMENT_PLANNER_OPENAI_API_KEY = ""

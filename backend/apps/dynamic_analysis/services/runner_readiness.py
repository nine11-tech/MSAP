from __future__ import annotations

import logging

from celery import current_app
from django.conf import settings


logger = logging.getLogger(__name__)


def get_dynamic_runner_readiness() -> dict:
    """Return a bounded readiness result without disclosing broker configuration."""

    runner_enabled = bool(settings.MSAP_DYNAMIC_RUNNER_ENABLED)
    synchronous = bool(settings.MSAP_DYNAMIC_RUNNER_SYNC_DEMO_ENABLED)
    base = {
        "runner_enabled": runner_enabled,
        "sync_demo_enabled": synchronous,
        "execution_mode": "synchronous" if synchronous else "celery",
        "worker_status": "UNKNOWN",
        "workers_responding": 0,
    }
    if not runner_enabled:
        return {
            **base,
            "ready": False,
            "code": "DYNAMIC_RUNNER_DISABLED",
            "detail": "Dynamic MVP runner is disabled by settings.",
        }
    if synchronous:
        return {
            **base,
            "ready": True,
            "code": "SYNC_DEMO_READY",
            "detail": (
                "Synchronous local demo mode is ready. Runs execute in the API "
                "request and may take several minutes."
            ),
        }

    try:
        inspector = current_app.control.inspect(
            timeout=settings.MSAP_STATUS_TIMEOUT_SECONDS
        )
        replies = inspector.ping() or {}
    except Exception as exc:
        logger.warning(
            "Dynamic runner readiness failed error_type=%s",
            type(exc).__name__,
        )
        return {
            **base,
            "worker_status": "OFFLINE",
            "ready": False,
            "code": "CELERY_UNAVAILABLE",
            "detail": (
                "Celery or Redis is unavailable. Start the local worker before "
                "creating or running a dynamic job."
            ),
        }

    worker_count = len(replies)
    if worker_count == 0:
        return {
            **base,
            "worker_status": "OFFLINE",
            "ready": False,
            "code": "CELERY_WORKER_OFFLINE",
            "detail": (
                "No Celery worker responded. Start the local worker before "
                "creating or running a dynamic job."
            ),
        }
    return {
        **base,
        "worker_status": "ONLINE",
        "workers_responding": worker_count,
        "ready": True,
        "code": "CELERY_WORKER_ONLINE",
        "detail": f"{worker_count} Celery worker(s) responded.",
    }

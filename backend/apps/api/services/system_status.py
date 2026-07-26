import logging
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Callable

import boto3
import redis
from botocore.config import Config
from celery import current_app
from django.conf import settings
from django.core.cache import cache
from django.db import connection

from apps.analyzers.services.registry import AnalyzerRegistry
from apps.appsec_rules.services.rule_loader import load_masvs_rules
from apps.triage_rules.services.triage_rule_loader import load_attck_triage_rules


logger = logging.getLogger(__name__)
CACHE_KEY = "msap:system-status:v1"
_last_success: dict[str, str] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _endpoint_url(endpoint: str) -> str:
    if endpoint.startswith(("http://", "https://")):
        return endpoint
    scheme = "https" if settings.MINIO_SECURE else "http"
    return f"{scheme}://{endpoint}"


def _component(
    component_id: str,
    label: str,
    check: Callable[[], dict | None],
    *,
    unavailable_status: str = "UNAVAILABLE",
) -> dict:
    started = monotonic()
    try:
        details = check() or {}
        status = details.pop("status", "OPERATIONAL")
        latency = round((monotonic() - started) * 1000)
        if status == "OPERATIONAL":
            _last_success[component_id] = _now()
        return {
            "id": component_id,
            "label": label,
            "status": status,
            "latency_ms": latency,
            "message": details.pop("message", _status_message(status)),
            "last_successful_check": _last_success.get(component_id),
            "details": details,
        }
    except Exception as exc:
        logger.warning(
            "System status check failed component=%s error_type=%s",
            component_id,
            type(exc).__name__,
        )
        return {
            "id": component_id,
            "label": label,
            "status": unavailable_status,
            "latency_ms": round((monotonic() - started) * 1000),
            "message": _status_message(unavailable_status),
            "last_successful_check": _last_success.get(component_id),
            "details": {},
        }


def _status_message(status: str) -> str:
    return {
        "OPERATIONAL": "Operational",
        "DEGRADED": "Attention required",
        "UNAVAILABLE": "Unavailable",
        "DISABLED": "Disabled",
    }.get(status, "Unknown")


def _check_database() -> dict:
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")
        cursor.fetchone()
    return {}


def _check_redis() -> dict:
    client = redis.Redis.from_url(
        settings.REDIS_URL,
        socket_connect_timeout=settings.MSAP_STATUS_TIMEOUT_SECONDS,
        socket_timeout=settings.MSAP_STATUS_TIMEOUT_SECONDS,
    )
    if client.ping() is not True:
        raise RuntimeError("Redis ping failed")
    return {}


def _check_celery() -> dict:
    inspector = current_app.control.inspect(
        timeout=settings.MSAP_STATUS_TIMEOUT_SECONDS
    )
    replies = inspector.ping() or {}
    if not replies:
        return {
            "status": "DEGRADED",
            "message": "No worker response",
            "workers_responding": 0,
        }
    return {"workers_responding": len(replies)}


def _minio_client():
    timeout = settings.MSAP_STATUS_TIMEOUT_SECONDS
    return boto3.client(
        "s3",
        endpoint_url=_endpoint_url(settings.MINIO_ENDPOINT),
        aws_access_key_id=settings.MINIO_ACCESS_KEY,
        aws_secret_access_key=settings.MINIO_SECRET_KEY,
        config=Config(
            connect_timeout=timeout,
            read_timeout=timeout,
            retries={"max_attempts": 0},
        ),
    )


def _check_minio() -> dict:
    response = _minio_client().list_buckets()
    configured = {
        settings.MINIO_BUCKET_APK_UPLOADS,
        settings.MINIO_BUCKET_ARTIFACTS,
        settings.MINIO_BUCKET_EVIDENCE,
        settings.MINIO_BUCKET_REPORTS,
        settings.MINIO_BUCKET_EXPORTS,
    }
    available = {bucket["Name"] for bucket in response.get("Buckets", [])}
    missing = sorted(configured - available)
    if missing:
        return {
            "status": "DEGRADED",
            "message": "Required bucket configuration incomplete",
            "required_buckets": len(configured),
            "available_required_buckets": len(configured) - len(missing),
            "missing_bucket_count": len(missing),
        }
    return {
        "required_buckets": len(configured),
        "available_required_buckets": len(configured),
        "missing_bucket_count": 0,
    }


def _check_analyzers() -> dict:
    metadata = AnalyzerRegistry().get_analyzer_metadata()
    enabled = [item for item in metadata if item.get("enabled")]
    unavailable = [
        item
        for item in enabled
        if item.get("available") is False
    ]
    return {
        "status": "DEGRADED" if unavailable else "OPERATIONAL",
        "registered_count": len(metadata),
        "enabled_count": len(enabled),
        "unavailable_count": len(unavailable),
        "capabilities": metadata,
    }


def _catalog_path(filename: str) -> Path:
    return Path(settings.ANALYZER_RULES_PATH) / filename


def _check_masvs_catalog() -> dict:
    rules = load_masvs_rules(_catalog_path("masvs_static_rules.yaml"))
    return {"rule_count": len(rules), "validation": "VALID"}


def _check_attck_catalog() -> dict:
    rules = load_attck_triage_rules(
        _catalog_path("attck_mobile_triage_rules.yaml")
    )
    return {"indicator_count": len(rules), "validation": "VALID"}


def collect_system_status(*, force: bool = False) -> dict:
    if not force:
        cached = cache.get(CACHE_KEY)
        if cached is not None:
            return cached

    checked_at = _now()
    components = [
        {
            "id": "api",
            "label": "Backend API",
            "status": "OPERATIONAL",
            "latency_ms": 0,
            "message": "Operational",
            "last_successful_check": checked_at,
            "details": {},
        },
        _component("postgresql", "PostgreSQL", _check_database),
        _component("redis", "Redis", _check_redis),
        _component(
            "celery",
            "Celery worker",
            _check_celery,
            unavailable_status="DEGRADED",
        ),
        _component("minio", "MinIO", _check_minio),
        _component(
            "analyzers",
            "Analyzer registry",
            _check_analyzers,
            unavailable_status="DEGRADED",
        ),
        _component(
            "masvs_catalog",
            "MASVS catalog",
            _check_masvs_catalog,
            unavailable_status="DEGRADED",
        ),
        _component(
            "attack_catalog",
            "ATT&CK Mobile catalog",
            _check_attck_catalog,
            unavailable_status="DEGRADED",
        ),
    ]

    by_id = {component["id"]: component for component in components}
    if by_id["postgresql"]["status"] != "OPERATIONAL":
        overall = "OUTAGE"
    elif by_id["minio"]["status"] == "UNAVAILABLE":
        overall = "OUTAGE"
    elif any(component["status"] != "OPERATIONAL" for component in components):
        overall = "DEGRADED"
    else:
        overall = "OPERATIONAL"

    result = {
        "overall_status": overall,
        "checked_at": checked_at,
        "components": components,
        "deployment_mode": settings.MSAP_ENVIRONMENT,
        "application_version": settings.MSAP_APPLICATION_VERSION,
    }
    cache.set(CACHE_KEY, result, timeout=settings.MSAP_STATUS_CACHE_SECONDS)
    return result


def serialize_system_status(result: dict, *, include_admin_details: bool) -> dict:
    response = {
        "overall_status": result["overall_status"],
        "checked_at": result["checked_at"],
        "components": [],
    }
    for component in result["components"]:
        item = {
            key: component.get(key)
            for key in (
                "id",
                "label",
                "status",
                "latency_ms",
                "message",
                "last_successful_check",
            )
        }
        if include_admin_details:
            item["details"] = component.get("details", {})
        response["components"].append(item)
    if include_admin_details:
        response["deployment_mode"] = result["deployment_mode"]
        response["application_version"] = result["application_version"]
    return response

from unittest.mock import patch

import pytest
from django.core.cache import cache
from rest_framework.test import APIClient


@pytest.fixture(autouse=True)
def clear_status_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def admin_client(django_user_model):
    user = django_user_model.objects.create_superuser(
        username="status-admin",
        email="status-admin@example.test",
        password="Strong-Test-Password-42!",
    )
    client = APIClient()
    client.force_authenticate(user)
    return client


@pytest.mark.django_db
@patch("apps.api.services.system_status._check_attck_catalog")
@patch("apps.api.services.system_status._check_masvs_catalog")
@patch("apps.api.services.system_status._check_analyzers")
@patch("apps.api.services.system_status._check_minio")
@patch("apps.api.services.system_status._check_celery")
@patch("apps.api.services.system_status._check_redis")
def test_system_status_healthy_and_cached(
    check_redis,
    check_celery,
    check_minio,
    check_analyzers,
    check_masvs,
    check_attck,
    admin_client,
):
    check_redis.return_value = {}
    check_celery.return_value = {"workers_responding": 1}
    check_minio.return_value = {
        "required_buckets": 5,
        "missing_bucket_count": 0,
    }
    check_analyzers.return_value = {
        "registered_count": 2,
        "enabled_count": 2,
    }
    check_masvs.return_value = {"rule_count": 14, "validation": "VALID"}
    check_attck.return_value = {"indicator_count": 15, "validation": "VALID"}

    first = admin_client.get("/api/system/status/")
    second = admin_client.get("/api/system/status/")

    assert first.status_code == 200
    assert first.json()["overall_status"] == "OPERATIONAL"
    assert first.json()["deployment_mode"] == "testing"
    assert len(first.json()["components"]) == 8
    assert second.json()["checked_at"] == first.json()["checked_at"]
    assert check_redis.call_count == 1


@pytest.mark.django_db
@patch("apps.api.services.system_status._check_attck_catalog", return_value={})
@patch("apps.api.services.system_status._check_masvs_catalog", return_value={})
@patch("apps.api.services.system_status._check_analyzers", return_value={})
@patch("apps.api.services.system_status._check_minio", return_value={})
@patch(
    "apps.api.services.system_status._check_celery",
    side_effect=RuntimeError("redis://secret-host:6379 internal detail"),
)
@patch("apps.api.services.system_status._check_redis", return_value={})
def test_system_status_degraded_without_internal_error_leakage(
    _redis,
    _worker,
    _minio,
    _analyzers,
    _masvs,
    _attck,
    admin_client,
):
    response = admin_client.get("/api/system/status/?refresh=true")
    body = response.json()

    assert response.status_code == 200
    assert body["overall_status"] == "DEGRADED"
    serialized = str(body)
    assert "secret-host" not in serialized
    worker = next(item for item in body["components"] if item["id"] == "celery")
    assert worker["status"] == "DEGRADED"
    assert worker["message"] == "Attention required"

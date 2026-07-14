import pytest
from rest_framework.test import APIClient


@pytest.fixture
def api_client():
    return APIClient()


@pytest.mark.django_db
def test_health_endpoint_returns_ok(api_client):
    response = api_client.get("/api/health/")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "msap-backend"}


@pytest.mark.django_db
def test_create_project(api_client):
    response = api_client.post(
        "/api/projects/",
        {"name": "Android Client", "description": "Initial MASVS assessment"},
        format="json",
    )

    assert response.status_code == 201
    assert response.json()["name"] == "Android Client"


@pytest.mark.django_db
def test_create_audit_linked_to_project(api_client):
    project_id = _create_project(api_client)

    response = api_client.post(
        "/api/audits/",
        {"project": project_id, "name": "Release 1.0 audit"},
        format="json",
    )

    assert response.status_code == 201
    data = response.json()
    assert data["project"] == project_id
    assert data["status"] == "created"


@pytest.mark.django_db
def test_create_storage_reference_linked_to_project_and_audit(api_client):
    project_id = _create_project(api_client)
    audit_id = _create_audit(api_client, project_id)

    response = api_client.post(
        "/api/storage-references/",
        {
            "project": project_id,
            "audit": audit_id,
            "bucket": "msap-apk-uploads",
            "object_key": "projects/1/audits/1/app.apk",
            "object_type": "APK_UPLOAD",
            "content_type": "application/vnd.android.package-archive",
            "size_bytes": 1024,
            "sha256": "a" * 64,
        },
        format="json",
    )

    assert response.status_code == 201
    data = response.json()
    assert data["project"] == project_id
    assert data["audit"] == audit_id
    assert data["bucket"] == "msap-apk-uploads"


@pytest.mark.django_db
def test_create_apk_file_metadata_linked_to_audit_and_storage_reference(api_client):
    project_id = _create_project(api_client)
    audit_id = _create_audit(api_client, project_id)
    storage_reference_id = _create_storage_reference(api_client, project_id, audit_id)

    response = api_client.post(
        "/api/apk-files/",
        {
            "audit": audit_id,
            "storage_reference": storage_reference_id,
            "package_name": "com.example.app",
            "version_name": "1.0.0",
            "sha256": "b" * 64,
            "size_bytes": 2048,
        },
        format="json",
    )

    assert response.status_code == 201
    data = response.json()
    assert data["audit"] == audit_id
    assert data["storage_reference"] == storage_reference_id
    assert data["package_name"] == "com.example.app"


@pytest.mark.django_db
def test_list_findings_endpoint_works(api_client):
    response = api_client.get("/api/findings/")

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.django_db
def test_list_indicators_endpoint_works(api_client):
    response = api_client.get("/api/indicators/")

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.django_db
def test_schema_endpoint_returns_ok(api_client):
    response = api_client.get("/api/schema/")

    assert response.status_code == 200


def _create_project(api_client) -> int:
    response = api_client.post(
        "/api/projects/",
        {"name": "Android Client", "description": ""},
        format="json",
    )
    assert response.status_code == 201
    return response.json()["id"]


def _create_audit(api_client, project_id: int) -> int:
    response = api_client.post(
        "/api/audits/",
        {"project": project_id, "name": "Release 1.0 audit"},
        format="json",
    )
    assert response.status_code == 201
    return response.json()["id"]


def _create_storage_reference(api_client, project_id: int, audit_id: int) -> int:
    response = api_client.post(
        "/api/storage-references/",
        {
            "project": project_id,
            "audit": audit_id,
            "bucket": "msap-apk-uploads",
            "object_key": f"projects/{project_id}/audits/{audit_id}/app.apk",
            "object_type": "APK_UPLOAD",
        },
        format="json",
    )
    assert response.status_code == 201
    return response.json()["id"]

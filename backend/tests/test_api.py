from types import SimpleNamespace
from unittest.mock import patch

import pytest
from rest_framework.test import APIClient

from apps.analyzers.models import RawAnalyzerResult
from apps.apk_files.models import APKFile
from apps.audits.models import AnalysisJob, Audit
from apps.audits.tasks import analyze_audit_placeholder
from apps.findings.models import Finding
from apps.indicators.models import SuspiciousIndicator
from apps.normalization.models import NormalizedArtifact
from apps.storage.models import ObjectStorageReference


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
def test_list_raw_analyzer_results_endpoint_works(api_client):
    response = api_client.get("/api/raw-analyzer-results/")

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.django_db
def test_list_normalized_artifacts_endpoint_works(api_client):
    response = api_client.get("/api/normalized-artifacts/")

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


@pytest.mark.django_db
@patch("apps.api.views.MinIOStorageService")
def test_initiate_apk_upload_creates_metadata_and_returns_contract(
    mock_storage_service,
    api_client,
):
    project_id = _create_project(api_client)
    audit_id = _create_audit(api_client, project_id)
    service = mock_storage_service.return_value
    service.get_apk_upload_bucket.return_value = "msap-apk-uploads"
    service.build_object_key.return_value = (
        f"projects/{project_id}/audits/{audit_id}/apk_upload/sample.apk"
    )
    service.generate_presigned_upload_url.return_value = (
        "http://localhost:9000/msap-apk-uploads/sample.apk?signature=test"
    )

    response = api_client.post(
        f"/api/audits/{audit_id}/apk-upload/initiate/",
        {
            "filename": "sample.apk",
            "content_type": "application/vnd.android.package-archive",
            "size_bytes": 123456,
            "sha256": "a" * 64,
        },
        format="json",
    )

    assert response.status_code == 201
    data = response.json()
    assert data["upload_url"].startswith("http://localhost:9000/")
    assert data["bucket"] == "msap-apk-uploads"
    assert f"projects/{project_id}/audits/{audit_id}" in data["object_key"]
    assert APKFile.objects.filter(id=data["apk_file_id"], audit_id=audit_id).exists()
    assert ObjectStorageReference.objects.filter(
        id=data["storage_reference_id"],
        project_id=project_id,
        audit_id=audit_id,
        object_type=ObjectStorageReference.ObjectType.APK_UPLOAD,
        storage_status=ObjectStorageReference.StorageStatus.PENDING_UPLOAD,
    ).exists()


@pytest.mark.django_db
@patch("apps.api.views.MinIOStorageService")
def test_initiate_apk_upload_rejects_non_apk_filename(
    mock_storage_service,
    api_client,
):
    project_id = _create_project(api_client)
    audit_id = _create_audit(api_client, project_id)

    response = api_client.post(
        f"/api/audits/{audit_id}/apk-upload/initiate/",
        {
            "filename": "sample.aab",
            "content_type": "application/vnd.android.package-archive",
            "size_bytes": 123456,
        },
        format="json",
    )

    assert response.status_code == 400
    assert mock_storage_service.call_count == 0


@pytest.mark.django_db
@patch("apps.api.views.MinIOStorageService")
def test_initiate_apk_upload_rejects_invalid_content_type(
    mock_storage_service,
    api_client,
):
    project_id = _create_project(api_client)
    audit_id = _create_audit(api_client, project_id)

    response = api_client.post(
        f"/api/audits/{audit_id}/apk-upload/initiate/",
        {
            "filename": "sample.apk",
            "content_type": "application/zip",
            "size_bytes": 123456,
        },
        format="json",
    )

    assert response.status_code == 400
    assert mock_storage_service.call_count == 0


@pytest.mark.django_db
@patch("apps.api.views.MinIOStorageService")
def test_initiate_apk_upload_rejects_negative_size(
    mock_storage_service,
    api_client,
):
    project_id = _create_project(api_client)
    audit_id = _create_audit(api_client, project_id)

    response = api_client.post(
        f"/api/audits/{audit_id}/apk-upload/initiate/",
        {
            "filename": "sample.apk",
            "content_type": "application/vnd.android.package-archive",
            "size_bytes": -1,
        },
        format="json",
    )

    assert response.status_code == 400
    assert mock_storage_service.call_count == 0


@pytest.mark.django_db
@patch("apps.api.views.MinIOStorageService")
def test_initiate_apk_upload_rejects_missing_audit(
    mock_storage_service,
    api_client,
):
    response = api_client.post(
        "/api/audits/9999/apk-upload/initiate/",
        {
            "filename": "sample.apk",
            "content_type": "application/vnd.android.package-archive",
            "size_bytes": 123456,
        },
        format="json",
    )

    assert response.status_code == 404
    assert mock_storage_service.call_count == 0


@pytest.mark.django_db
def test_confirm_apk_upload_updates_metadata(api_client):
    project_id = _create_project(api_client)
    audit_id = _create_audit(api_client, project_id)
    storage_reference_id = _create_storage_reference(api_client, project_id, audit_id)
    apk_file_id = _create_apk_file(api_client, audit_id, storage_reference_id)

    response = api_client.post(
        f"/api/apk-files/{apk_file_id}/confirm-upload/",
        {"size_bytes": 4096, "sha256": "c" * 64},
        format="json",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["size_bytes"] == 4096
    assert data["sha256"] == "c" * 64
    storage_reference = ObjectStorageReference.objects.get(id=storage_reference_id)
    assert storage_reference.size_bytes == 4096
    assert storage_reference.sha256 == "c" * 64
    assert storage_reference.storage_status == (
        ObjectStorageReference.StorageStatus.UPLOADED
    )


@pytest.mark.django_db
def test_start_analysis_requires_existing_audit(api_client):
    response = api_client.post("/api/audits/9999/analysis/start/", format="json")

    assert response.status_code == 404


@pytest.mark.django_db
@patch("apps.audits.tasks.AnalysisOrchestrator")
def test_start_analysis_calls_orchestrator_in_eager_mode(mock_orchestrator, api_client):
    audit_id = _create_audit_with_apk(api_client)
    mock_orchestrator.return_value.run.return_value = SimpleNamespace(
        as_dict=lambda: {
            "audit_id": audit_id,
            "created_raw_analyzer_results": 1,
            "created_normalized_artifacts": 1,
        }
    )

    response = api_client.post(f"/api/audits/{audit_id}/analysis/start/", format="json")

    assert response.status_code == 202
    job_id = response.json()["analysis_job_id"]
    mock_orchestrator.return_value.run.assert_called_once_with(
        audit_id=audit_id,
        job_id=job_id,
    )
    job = AnalysisJob.objects.get(id=job_id)
    assert job.status == AnalysisJob.Status.COMPLETED
    assert job.result_summary["audit_id"] == audit_id


@pytest.mark.django_db
def test_start_analysis_requires_apk_file(api_client):
    project_id = _create_project(api_client)
    audit_id = _create_audit(api_client, project_id)

    response = api_client.post(f"/api/audits/{audit_id}/analysis/start/", format="json")

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Audit must have at least one APK file before analysis."
    )


@pytest.mark.django_db
def test_start_analysis_creates_job_and_updates_audit_status(api_client):
    audit_id = _create_audit_with_apk(api_client)

    response = api_client.post(f"/api/audits/{audit_id}/analysis/start/", format="json")

    assert response.status_code == 202
    data = response.json()
    assert data["audit_id"] == audit_id
    assert data["analysis_job_id"]
    assert data["task_id"]
    assert data["status"] in {
        Audit.Status.ANALYSIS_QUEUED,
        Audit.Status.ANALYSIS_COMPLETED,
    }
    assert AnalysisJob.objects.filter(
        id=data["analysis_job_id"],
        audit_id=audit_id,
        task_id=data["task_id"],
    ).exists()
    assert RawAnalyzerResult.objects.filter(audit_id=audit_id).count() == 1
    assert NormalizedArtifact.objects.filter(audit_id=audit_id).count() == 1


@pytest.mark.django_db
def test_placeholder_task_transitions_job_to_completed(api_client):
    audit_id = _create_audit_with_apk(api_client)
    job = AnalysisJob.objects.create(
        audit_id=audit_id,
        status=AnalysisJob.Status.QUEUED,
    )

    analyze_audit_placeholder.delay(audit_id)

    job.refresh_from_db()
    audit = Audit.objects.get(id=audit_id)
    assert job.status == AnalysisJob.Status.COMPLETED
    assert job.started_at is not None
    assert job.finished_at is not None
    assert job.error_message == ""
    assert job.result_summary["summary"]["created_raw_analyzer_results"] == 1
    assert job.result_summary["summary"]["created_normalized_artifacts"] == 1
    assert audit.status == Audit.Status.ANALYSIS_COMPLETED


@pytest.mark.django_db
def test_analysis_creates_raw_result_and_normalized_artifact_only(api_client):
    audit_id = _create_audit_with_apk(api_client)
    job = AnalysisJob.objects.create(
        audit_id=audit_id,
        status=AnalysisJob.Status.QUEUED,
    )

    analyze_audit_placeholder.delay(audit_id)

    raw_result = RawAnalyzerResult.objects.get(audit_id=audit_id)
    artifact = NormalizedArtifact.objects.get(audit_id=audit_id)
    assert raw_result.apk_file.audit_id == audit_id
    assert raw_result.status == RawAnalyzerResult.Status.COMPLETED
    assert raw_result.result_summary["real_apk_parsing"] is False
    assert artifact.apk_file.audit_id == audit_id
    assert artifact.artifact_type == NormalizedArtifact.ArtifactType.APK_METADATA
    assert artifact.normalized_data["real_apk_parsing"] is False
    assert Finding.objects.filter(audit_id=audit_id).count() == 0
    assert SuspiciousIndicator.objects.filter(audit_id=audit_id).count() == 0
    job.refresh_from_db()
    assert job.status == AnalysisJob.Status.COMPLETED


@pytest.mark.django_db
def test_analysis_fails_cleanly_if_audit_has_no_apk_file(api_client):
    project_id = _create_project(api_client)
    audit_id = _create_audit(api_client, project_id)
    job = AnalysisJob.objects.create(
        audit_id=audit_id,
        status=AnalysisJob.Status.QUEUED,
    )

    with pytest.raises(ValueError, match="Audit has no APK file"):
        analyze_audit_placeholder.delay(audit_id)

    job.refresh_from_db()
    audit = Audit.objects.get(id=audit_id)
    assert job.status == AnalysisJob.Status.FAILED
    assert job.error_message == "Audit has no APK file to analyze."
    assert job.result_summary == {}
    assert audit.status == Audit.Status.ANALYSIS_FAILED
    assert RawAnalyzerResult.objects.filter(audit_id=audit_id).count() == 0
    assert NormalizedArtifact.objects.filter(audit_id=audit_id).count() == 0


@pytest.mark.django_db
def test_analysis_fails_cleanly_if_latest_apk_has_no_storage_reference(api_client):
    project_id = _create_project(api_client)
    audit_id = _create_audit(api_client, project_id)
    APKFile.objects.create(audit_id=audit_id, package_name="com.example.app")
    job = AnalysisJob.objects.create(
        audit_id=audit_id,
        status=AnalysisJob.Status.QUEUED,
    )

    with pytest.raises(ValueError, match="storage reference"):
        analyze_audit_placeholder.delay(audit_id)

    job.refresh_from_db()
    audit = Audit.objects.get(id=audit_id)
    assert job.status == AnalysisJob.Status.FAILED
    assert job.error_message == "Latest APK file has no storage reference."
    assert audit.status == Audit.Status.ANALYSIS_FAILED
    assert RawAnalyzerResult.objects.filter(audit_id=audit_id).count() == 0
    assert NormalizedArtifact.objects.filter(audit_id=audit_id).count() == 0


@pytest.mark.django_db
def test_analysis_status_endpoint_returns_latest_job(api_client):
    audit_id = _create_audit_with_apk(api_client)
    older_job = AnalysisJob.objects.create(
        audit_id=audit_id,
        status=AnalysisJob.Status.COMPLETED,
    )
    latest_job = AnalysisJob.objects.create(
        audit_id=audit_id,
        task_id="latest-task",
        status=AnalysisJob.Status.QUEUED,
    )

    response = api_client.get(f"/api/audits/{audit_id}/analysis/status/")

    assert response.status_code == 200
    data = response.json()
    assert data["audit_id"] == audit_id
    assert data["latest_job"]["id"] == latest_job.id
    assert data["latest_job"]["id"] != older_job.id
    assert data["latest_job"]["task_id"] == "latest-task"
    assert data["latest_job"]["status"] == AnalysisJob.Status.QUEUED


@pytest.mark.django_db
def test_cannot_start_analysis_while_queued(api_client):
    audit_id = _create_audit_with_apk(api_client)
    Audit.objects.filter(id=audit_id).update(status=Audit.Status.ANALYSIS_QUEUED)
    AnalysisJob.objects.create(
        audit_id=audit_id,
        status=AnalysisJob.Status.QUEUED,
    )

    response = api_client.post(f"/api/audits/{audit_id}/analysis/start/", format="json")

    assert response.status_code == 409
    assert AnalysisJob.objects.filter(audit_id=audit_id).count() == 1


@pytest.mark.django_db
def test_cannot_start_analysis_while_running(api_client):
    audit_id = _create_audit_with_apk(api_client)
    Audit.objects.filter(id=audit_id).update(status=Audit.Status.ANALYSIS_RUNNING)
    AnalysisJob.objects.create(
        audit_id=audit_id,
        status=AnalysisJob.Status.RUNNING,
    )

    response = api_client.post(f"/api/audits/{audit_id}/analysis/start/", format="json")

    assert response.status_code == 409
    assert AnalysisJob.objects.filter(audit_id=audit_id).count() == 1


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


def _create_apk_file(api_client, audit_id: int, storage_reference_id: int) -> int:
    response = api_client.post(
        "/api/apk-files/",
        {
            "audit": audit_id,
            "storage_reference": storage_reference_id,
            "package_name": "com.example.app",
            "version_name": "1.0.0",
        },
        format="json",
    )
    assert response.status_code == 201
    return response.json()["id"]


def _create_audit_with_apk(api_client) -> int:
    project_id = _create_project(api_client)
    audit_id = _create_audit(api_client, project_id)
    storage_reference_id = _create_storage_reference(api_client, project_id, audit_id)
    _create_apk_file(api_client, audit_id, storage_reference_id)
    return audit_id

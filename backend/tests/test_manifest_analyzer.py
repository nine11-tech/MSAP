from contextlib import nullcontext
from hashlib import sha256
from pathlib import Path
from unittest.mock import Mock
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from apps.analyzers.models import RawAnalyzerResult
from apps.analyzers.services.base import AnalyzerContext
from apps.analyzers.services.manifest_analyzer import ManifestMetadataAnalyzer
from apps.analyzers.services.manifest_metadata_adapter import (
    ManifestMetadata,
)
from apps.analyzers.services.registry import AnalyzerRegistry
from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.audits.services.analysis_orchestrator import AnalysisOrchestrator
from apps.findings.models import Finding
from apps.indicators.models import SuspiciousIndicator
from apps.normalization.models import NormalizedArtifact
from apps.normalization.services.schemas import build_manifest_artifact
from apps.projects.models import Project
from apps.storage.models import ObjectStorageReference
from apps.storage.services.file_provider import APKFileProvider, DevelopmentFileProvider


FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def tiny_apk(tmp_path):
    apk_path = tmp_path / "tiny-fixture.apk"
    manifest_xml = (FIXTURE_DIR / "AndroidManifest.xml").read_bytes()
    with ZipFile(apk_path, "w", compression=ZIP_DEFLATED) as apk_zip:
        apk_zip.writestr("AndroidManifest.xml", manifest_xml)
    return apk_path


@pytest.fixture
def analyzer_context(db):
    project = Project.objects.create(name="Manifest test project")
    audit = Audit.objects.create(project=project, name="Manifest test audit")
    storage_reference = ObjectStorageReference.objects.create(
        project=project,
        audit=audit,
        bucket="msap-apk-uploads",
        object_key="projects/1/audits/1/test.apk",
        object_type=ObjectStorageReference.ObjectType.APK_UPLOAD,
    )
    apk_file = APKFile.objects.create(
        audit=audit,
        storage_reference=storage_reference,
        package_name="com.example.old",
        version_name="0.0.1",
    )
    return AnalyzerContext(audit=audit, apk_file=apk_file)


def test_manifest_normalized_schema_has_stable_fields():
    artifact = build_manifest_artifact()

    assert artifact["schema_version"] == "2.0"
    assert artifact["analyzer_name"] == "manifest_metadata_analyzer"
    assert artifact["source"] == "AndroidManifest.xml"
    assert artifact["package_name"] is None
    assert artifact["permissions"] == []
    assert artifact["declared_permissions"] == []
    assert artifact["components"] == []
    assert artifact["application"]["debuggable"] is None
    assert artifact["application"]["network_security_config"] is None
    assert artifact["parsing_status"] == "NOT_STARTED"


@pytest.mark.django_db
def test_manifest_analyzer_skips_when_no_local_apk_path(analyzer_context):
    file_provider = Mock(spec=["get_local_path_for_apk"])
    file_provider.get_local_path_for_apk.return_value = None
    analyzer = ManifestMetadataAnalyzer(file_provider=file_provider)

    result = analyzer.run(analyzer_context)

    assert result.status == RawAnalyzerResult.Status.SKIPPED
    assert result.normalized_artifacts == []
    assert result.raw_summary["parsing_status"] == "SKIPPED_NO_LOCAL_PATH"
    assert result.error_message == "No local APK path is available."


@pytest.mark.django_db
def test_orchestrator_completes_and_records_skipped_manifest(analyzer_context):
    result = AnalysisOrchestrator().run(analyzer_context.audit.id)

    skipped_result = RawAnalyzerResult.objects.get(
        audit=analyzer_context.audit,
        analyzer_name="manifest_metadata_analyzer",
    )
    assert skipped_result.status == RawAnalyzerResult.Status.SKIPPED
    assert result.summary["analyzers_run"] == [
        "placeholder_metadata",
        "manifest_metadata_analyzer",
        "advanced_static_analyzer",
    ]
    assert result.summary["skipped_analyzers"] == [
        "advanced_static_analyzer",
        "manifest_metadata_analyzer",
    ]
    assert result.summary["errors"] == []
    assert result.summary["created_raw_analyzer_results"] == 3
    assert result.summary["created_normalized_artifacts"] == 1


@pytest.mark.django_db
def test_manifest_analyzer_updates_apk_metadata(analyzer_context, tmp_path):
    local_apk_path = tmp_path / "mocked.apk"
    file_provider = Mock()
    file_provider.open_apk_local_copy.return_value = nullcontext(local_apk_path)
    adapter = Mock()
    adapter.parse.return_value = ManifestMetadata(
        package_name="com.example.parsed",
        version_name="9.8.7",
        version_code="98",
        min_sdk="24",
        target_sdk="35",
    )
    analyzer = ManifestMetadataAnalyzer(
        file_provider=file_provider,
        manifest_adapter=adapter,
    )

    result = analyzer.run(analyzer_context)

    analyzer_context.apk_file.refresh_from_db()
    assert result.status == RawAnalyzerResult.Status.COMPLETED
    assert analyzer_context.apk_file.package_name == "com.example.parsed"
    assert analyzer_context.apk_file.version_name == "9.8.7"
    assert result.normalized_artifacts[0].normalized_data["version_code"] == "98"
    file_provider.open_apk_local_copy.assert_called_once_with(
        analyzer_context.apk_file
    )


@pytest.mark.django_db
def test_valid_fixture_creates_parsed_manifest_artifact(
    analyzer_context,
    tiny_apk,
):
    file_provider = Mock()
    file_provider.open_apk_local_copy.return_value = nullcontext(tiny_apk)
    registry = AnalyzerRegistry(
        analyzers=[ManifestMetadataAnalyzer(file_provider=file_provider)]
    )

    result = AnalysisOrchestrator(registry=registry).run(analyzer_context.audit.id)

    artifact = NormalizedArtifact.objects.get(
        audit=analyzer_context.audit,
        artifact_type=NormalizedArtifact.ArtifactType.MANIFEST,
    )
    assert result.summary["real_apk_parsing"] is True
    normalized = artifact.normalized_data
    assert normalized["schema_version"] == "2.0"
    assert normalized["package_name"] == "com.example.fixture"
    assert normalized["version_name"] == "2.3.4"
    assert normalized["version_code"] == "42"
    assert normalized["min_sdk"] == "24"
    assert normalized["target_sdk"] == "35"
    assert normalized["permissions"] == [
        "android.permission.CAMERA",
        "android.permission.INTERNET",
    ]
    assert {item["type"] for item in normalized["components"]} == {
        "activity",
        "provider",
        "receiver",
        "service",
    }
    assert normalized["application"]["debuggable"] is True
    assert normalized["application"]["allow_backup"] is False
    assert normalized["application"]["uses_cleartext_traffic"] is True
    assert normalized["parsing_status"] == "PARSED"
    analyzer_context.apk_file.refresh_from_db()
    assert analyzer_context.apk_file.package_name == "com.example.fixture"
    assert analyzer_context.apk_file.version_name == "2.3.4"
    assert Finding.objects.filter(audit=analyzer_context.audit).count() == 2
    assert Finding.objects.filter(
        audit=analyzer_context.audit,
        rule_id="MSAP-AND-001",
    ).exists()
    assert Finding.objects.filter(
        audit=analyzer_context.audit,
        rule_id="MSAP-AND-003",
    ).exists()
    assert (
        SuspiciousIndicator.objects.filter(audit=analyzer_context.audit).count()
        == 1
    )
    assert SuspiciousIndicator.objects.filter(
        audit=analyzer_context.audit,
        indicator_id="MSAP-MOB-009",
    ).exists()


@pytest.mark.django_db
def test_manifest_analyzer_parses_checksum_verified_temporary_download(
    analyzer_context,
    tiny_apk,
    tmp_path,
):
    downloaded_bytes = tiny_apk.read_bytes()
    downloaded_path = None
    storage_service = Mock()

    def download_file(bucket, object_key, destination):
        nonlocal downloaded_path
        downloaded_path = Path(destination)
        downloaded_path.write_bytes(downloaded_bytes)

    storage_service.download_file.side_effect = download_file
    storage_reference = analyzer_context.apk_file.storage_reference
    storage_reference.storage_status = ObjectStorageReference.StorageStatus.UPLOADED
    storage_reference.sha256 = sha256(downloaded_bytes).hexdigest()
    provider = APKFileProvider(
        local_root=None,
        environment="production",
        storage_service=storage_service,
        temp_dir=tmp_path,
    )

    result = ManifestMetadataAnalyzer(file_provider=provider).run(analyzer_context)

    assert result.status == RawAnalyzerResult.Status.COMPLETED
    assert result.raw_summary["package_name"] == "com.example.fixture"
    assert result.normalized_artifacts[0].normalized_data["parsing_status"] == "PARSED"
    assert downloaded_path is not None
    assert not downloaded_path.exists()
    assert Finding.objects.filter(audit=analyzer_context.audit).count() == 0
    assert (
        SuspiciousIndicator.objects.filter(audit=analyzer_context.audit).count()
        == 0
    )


@pytest.mark.django_db
def test_invalid_apk_fails_cleanly(analyzer_context, tmp_path):
    invalid_apk = tmp_path / "invalid.apk"
    invalid_apk.write_bytes(b"not an APK")
    file_provider = Mock()
    file_provider.open_apk_local_copy.return_value = nullcontext(invalid_apk)
    analyzer = ManifestMetadataAnalyzer(file_provider=file_provider)

    result = analyzer.run(analyzer_context)

    assert result.status == RawAnalyzerResult.Status.FAILED
    assert result.normalized_artifacts == []
    assert result.raw_summary["parsing_status"] == "FAILED"
    assert result.error_message == "APK is not a readable ZIP archive."


@pytest.mark.django_db
def test_manifest_analyzer_cleans_download_when_parser_fails(
    analyzer_context,
    tmp_path,
):
    downloaded_bytes = b"controlled test bytes"
    downloaded_path = None
    storage_service = Mock()

    def download_file(bucket, object_key, destination):
        nonlocal downloaded_path
        downloaded_path = Path(destination)
        downloaded_path.write_bytes(downloaded_bytes)

    storage_service.download_file.side_effect = download_file
    storage_reference = analyzer_context.apk_file.storage_reference
    storage_reference.storage_status = ObjectStorageReference.StorageStatus.UPLOADED
    storage_reference.sha256 = sha256(downloaded_bytes).hexdigest()
    adapter = Mock()

    def fail_while_path_exists(apk_path):
        assert Path(apk_path).is_file()
        raise ValueError("parser exploded")

    adapter.parse.side_effect = fail_while_path_exists
    provider = APKFileProvider(
        local_root=None,
        environment="production",
        storage_service=storage_service,
        temp_dir=tmp_path,
    )
    analyzer = ManifestMetadataAnalyzer(
        file_provider=provider,
        manifest_adapter=adapter,
    )

    result = analyzer.run(analyzer_context)

    assert result.status == RawAnalyzerResult.Status.FAILED
    assert result.error_message == "AndroidManifest.xml parsing failed unexpectedly."
    assert downloaded_path is not None
    assert not downloaded_path.exists()


@pytest.mark.django_db
def test_manifest_analyzer_fails_cleanly_on_checksum_mismatch(
    analyzer_context,
    tmp_path,
):
    storage_service = Mock()
    storage_service.download_file.side_effect = (
        lambda bucket, object_key, destination: Path(destination).write_bytes(
            b"unexpected bytes"
        )
    )
    storage_reference = analyzer_context.apk_file.storage_reference
    storage_reference.storage_status = ObjectStorageReference.StorageStatus.UPLOADED
    analyzer_context.apk_file.sha256 = "0" * 64
    provider = APKFileProvider(
        local_root=None,
        environment="production",
        storage_service=storage_service,
        temp_dir=tmp_path,
    )

    result = ManifestMetadataAnalyzer(file_provider=provider).run(analyzer_context)

    assert result.status == RawAnalyzerResult.Status.FAILED
    assert result.normalized_artifacts == []
    assert result.error_message == (
        "Downloaded APK checksum does not match expected SHA-256."
    )


@pytest.mark.django_db
def test_manifest_analyzer_skips_missing_object_reference(analyzer_context):
    analyzer_context.apk_file.storage_reference = None
    storage_service = Mock()
    provider = APKFileProvider(
        local_root=None,
        environment="production",
        storage_service=storage_service,
    )

    result = ManifestMetadataAnalyzer(file_provider=provider).run(analyzer_context)

    assert result.status == RawAnalyzerResult.Status.SKIPPED
    assert result.raw_summary["parsing_status"] == "SKIPPED_NO_LOCAL_PATH"
    assert result.error_message == (
        "APK file has no downloadable object storage reference."
    )
    storage_service.download_file.assert_not_called()


@pytest.mark.django_db
def test_manifest_analyzer_fails_cleanly_when_minio_download_fails(
    analyzer_context,
    tmp_path,
):
    storage_service = Mock()
    storage_service.download_file.side_effect = RuntimeError("MinIO unavailable")
    storage_reference = analyzer_context.apk_file.storage_reference
    storage_reference.storage_status = ObjectStorageReference.StorageStatus.UPLOADED
    provider = APKFileProvider(
        local_root=None,
        environment="production",
        storage_service=storage_service,
        temp_dir=tmp_path,
    )

    result = ManifestMetadataAnalyzer(file_provider=provider).run(analyzer_context)

    assert result.status == RawAnalyzerResult.Status.FAILED
    assert result.normalized_artifacts == []
    assert result.error_message == (
        "APK could not be downloaded from object storage."
    )


@pytest.mark.django_db
def test_development_file_provider_resolves_storage_metadata(
    analyzer_context,
    tiny_apk,
    tmp_path,
):
    object_key = "projects/1/audits/1/tiny-fixture.apk"
    local_apk = tmp_path / object_key
    local_apk.parent.mkdir(parents=True)
    local_apk.write_bytes(tiny_apk.read_bytes())
    analyzer_context.apk_file.storage_reference.object_key = object_key
    provider = DevelopmentFileProvider(
        local_root=tmp_path,
        environment="testing",
    )

    assert provider.get_local_path_for_apk(analyzer_context.apk_file) == local_apk


@pytest.mark.django_db
def test_development_file_provider_is_disabled_in_production(
    analyzer_context,
    tmp_path,
):
    provider = DevelopmentFileProvider(
        local_root=tmp_path,
        environment="production",
    )

    assert provider.get_local_path_for_apk(analyzer_context.apk_file) is None

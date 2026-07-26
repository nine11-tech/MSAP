from dataclasses import dataclass, field

from apps.apk_files.models import APKFile
from apps.normalization.models import NormalizedArtifact


SCHEMA_VERSION = "2.0"


@dataclass(frozen=True)
class NormalizedArtifactPayload:
    artifact_type: str
    source: str
    normalized_data: dict = field(default_factory=dict)
    storage_reference_id: int | None = None


def build_apk_metadata_schema(apk_file: APKFile) -> dict:
    storage_reference = apk_file.storage_reference
    return {
        "schema_version": SCHEMA_VERSION,
        "analyzer_name": "placeholder_metadata",
        "analyzer_version": "0.2.0",
        "source": "database_metadata",
        "extraction_status": "NOT_STARTED",
        "warnings": [],
        "package_name": apk_file.package_name or None,
        "version_name": apk_file.version_name or None,
        "sha256": apk_file.sha256 or "",
        "size_bytes": apk_file.size_bytes,
        "storage": {
            "bucket": storage_reference.bucket if storage_reference else "",
            "object_key": storage_reference.object_key if storage_reference else "",
            "storage_reference_id": apk_file.storage_reference_id,
        },
        "parsing_status": "NOT_STARTED",
        "real_apk_parsing": False,
    }


def build_manifest_artifact(
    package_name: str | None = None,
    version_name: str | None = None,
    version_code: str | None = None,
    min_sdk: str | None = None,
    target_sdk: str | None = None,
    compile_sdk: str | None = None,
    permissions: list[str] | None = None,
    declared_permissions: list[dict] | None = None,
    features: list[dict] | None = None,
    components: list[dict] | None = None,
    deep_links: list[dict] | None = None,
    application: dict | None = None,
    shared_user_id: str | None = None,
    parsing_status: str = "NOT_STARTED",
    analyzer_name: str = "manifest_metadata_analyzer",
    analyzer_version: str = "0.2.0",
) -> dict:
    application = application or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "analyzer_name": analyzer_name,
        "analyzer_version": analyzer_version,
        "source": "AndroidManifest.xml",
        "extraction_status": parsing_status,
        "warnings": [],
        "package_name": package_name,
        "version_name": version_name,
        "version_code": version_code,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "compile_sdk": compile_sdk,
        "shared_user_id": shared_user_id,
        "permissions": list(permissions or []),
        "declared_permissions": list(declared_permissions or []),
        "features": list(features or []),
        "components": list(components or []),
        "deep_links": list(deep_links or []),
        "application": {
            "debuggable": application.get("debuggable"),
            "test_only": application.get("test_only"),
            "allow_backup": application.get("allow_backup"),
            "full_backup_content": application.get("full_backup_content"),
            "data_extraction_rules": application.get("data_extraction_rules"),
            "uses_cleartext_traffic": application.get("uses_cleartext_traffic"),
            "network_security_config": application.get("network_security_config"),
            "request_legacy_external_storage": application.get(
                "request_legacy_external_storage"
            ),
            "task_affinity": application.get("task_affinity"),
            "application_class": application.get("application_class"),
            "metadata": application.get("metadata", []),
        },
        "parsing_status": parsing_status,
    }


def build_manifest_schema(
    package_name: str | None = None,
    version_name: str | None = None,
    parsing_status: str = "NOT_IMPLEMENTED",
) -> dict:
    """Backward-compatible wrapper for the original placeholder contract."""
    return build_manifest_artifact(
        package_name=package_name,
        version_name=version_name,
        parsing_status=parsing_status,
    )


def build_permissions_schema(permissions: list[dict] | None = None) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "permissions": permissions or [],
        "parsing_status": "NOT_IMPLEMENTED",
    }


def build_components_schema(components: list[dict] | None = None) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "components": components or [],
        "parsing_status": "NOT_IMPLEMENTED",
    }


def apk_metadata_payload(apk_file: APKFile, source: str) -> NormalizedArtifactPayload:
    return NormalizedArtifactPayload(
        artifact_type=NormalizedArtifact.ArtifactType.APK_METADATA,
        source=source,
        normalized_data=build_apk_metadata_schema(apk_file),
    )


def manifest_payload(
    source: str,
    package_name: str | None = None,
    version_name: str | None = None,
    version_code: str | None = None,
    min_sdk: str | None = None,
    target_sdk: str | None = None,
    compile_sdk: str | None = None,
    permissions: list[str] | None = None,
    declared_permissions: list[dict] | None = None,
    features: list[dict] | None = None,
    components: list[dict] | None = None,
    deep_links: list[dict] | None = None,
    application: dict | None = None,
    shared_user_id: str | None = None,
    parsing_status: str = "NOT_IMPLEMENTED",
) -> NormalizedArtifactPayload:
    return NormalizedArtifactPayload(
        artifact_type=NormalizedArtifact.ArtifactType.MANIFEST,
        source=source,
        normalized_data=build_manifest_artifact(
            package_name=package_name,
            version_name=version_name,
            version_code=version_code,
            min_sdk=min_sdk,
            target_sdk=target_sdk,
            compile_sdk=compile_sdk,
            permissions=permissions,
            declared_permissions=declared_permissions,
            features=features,
            components=components,
            deep_links=deep_links,
            application=application,
            shared_user_id=shared_user_id,
            parsing_status=parsing_status,
        ),
    )


def permissions_payload(
    source: str,
    permissions: list[str],
    declared_permissions: list[dict],
) -> NormalizedArtifactPayload:
    return NormalizedArtifactPayload(
        artifact_type=NormalizedArtifact.ArtifactType.PERMISSIONS,
        source=source,
        normalized_data={
            "schema_version": SCHEMA_VERSION,
            "analyzer_name": "manifest_metadata_analyzer",
            "analyzer_version": "0.2.0",
            "source": "AndroidManifest.xml",
            "extraction_status": "PARSED",
            "warnings": [],
            "permissions": list(permissions),
            "declared_permissions": list(declared_permissions),
        },
    )


def components_payload(
    source: str,
    components: list[dict],
    deep_links: list[dict],
) -> NormalizedArtifactPayload:
    return NormalizedArtifactPayload(
        artifact_type=NormalizedArtifact.ArtifactType.COMPONENTS,
        source=source,
        normalized_data={
            "schema_version": SCHEMA_VERSION,
            "analyzer_name": "manifest_metadata_analyzer",
            "analyzer_version": "0.2.0",
            "source": "AndroidManifest.xml",
            "extraction_status": "PARSED",
            "warnings": [],
            "components": list(components),
            "deep_links": list(deep_links),
        },
    )

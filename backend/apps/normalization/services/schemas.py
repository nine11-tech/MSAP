from dataclasses import dataclass, field

from apps.apk_files.models import APKFile
from apps.normalization.models import NormalizedArtifact


SCHEMA_VERSION = "1.0"


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


def build_manifest_schema(
    package_name: str | None = None,
    version_name: str | None = None,
    parsing_status: str = "NOT_IMPLEMENTED",
) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "package_name": package_name,
        "version_name": version_name,
        "permissions": [],
        "components": [],
        "parsing_status": parsing_status,
    }


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
) -> NormalizedArtifactPayload:
    return NormalizedArtifactPayload(
        artifact_type=NormalizedArtifact.ArtifactType.MANIFEST,
        source=source,
        normalized_data=build_manifest_schema(
            package_name=package_name,
            version_name=version_name,
        ),
    )

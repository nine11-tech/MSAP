from pathlib import Path

from apps.analyzers.models import RawAnalyzerResult
from apps.analyzers.services.base import AnalyzerContext, AnalyzerResult
from apps.analyzers.services.manifest_metadata_adapter import (
    ManifestMetadataAdapter,
    ManifestParsingError,
)
from apps.normalization.services.schemas import manifest_payload
from apps.storage.services.file_provider import DevelopmentFileProvider, FileProvider


class ManifestMetadataAnalyzer:
    name = "manifest_metadata_analyzer"
    version = "0.1.0"
    description = (
        "Safely extracts and normalizes metadata from an APK AndroidManifest.xml."
    )
    enabled = True

    def __init__(
        self,
        file_provider: FileProvider | None = None,
        manifest_adapter: ManifestMetadataAdapter | None = None,
    ):
        self.file_provider = file_provider or DevelopmentFileProvider()
        self.manifest_adapter = manifest_adapter or ManifestMetadataAdapter()

    def supports(self, context: AnalyzerContext) -> bool:
        return context.apk_file.storage_reference_id is not None

    def run(self, context: AnalyzerContext) -> AnalyzerResult:
        apk_file = context.apk_file
        local_path = self.file_provider.get_local_path_for_apk(apk_file)
        if local_path is None:
            message = (
                "No local APK path is available; object-storage download is not "
                "implemented by the current file provider."
            )
            return AnalyzerResult(
                analyzer_name=self.name,
                analyzer_version=self.version,
                status=RawAnalyzerResult.Status.SKIPPED,
                raw_summary={
                    "apk_file_id": apk_file.id,
                    "parsing_status": "SKIPPED_NO_LOCAL_PATH",
                    "real_apk_parsing": False,
                },
                error_message=message,
            )

        try:
            metadata = self.manifest_adapter.parse(Path(local_path))
        except ManifestParsingError as exc:
            return self._failed_result(apk_file.id, str(exc))
        except Exception:
            return self._failed_result(
                apk_file.id,
                "AndroidManifest.xml parsing failed unexpectedly.",
            )

        updated_fields = []
        if metadata.package_name:
            apk_file.package_name = metadata.package_name
            updated_fields.append("package_name")
        if metadata.version_name:
            apk_file.version_name = metadata.version_name
            updated_fields.append("version_name")
        if updated_fields:
            apk_file.save(update_fields=updated_fields)

        return AnalyzerResult(
            analyzer_name=self.name,
            analyzer_version=self.version,
            status=RawAnalyzerResult.Status.COMPLETED,
            raw_summary={
                "apk_file_id": apk_file.id,
                "package_name": metadata.package_name,
                "version_name": metadata.version_name,
                "permission_count": len(metadata.permissions),
                "component_count": len(metadata.components),
                "parsing_status": "PARSED",
                "real_apk_parsing": True,
            },
            normalized_artifacts=[
                manifest_payload(
                    source=self.name,
                    package_name=metadata.package_name,
                    version_name=metadata.version_name,
                    version_code=metadata.version_code,
                    min_sdk=metadata.min_sdk,
                    target_sdk=metadata.target_sdk,
                    permissions=metadata.permissions,
                    components=metadata.components,
                    application=metadata.application,
                    parsing_status="PARSED",
                )
            ],
        )

    def _failed_result(self, apk_file_id: int, message: str) -> AnalyzerResult:
        return AnalyzerResult(
            analyzer_name=self.name,
            analyzer_version=self.version,
            status=RawAnalyzerResult.Status.FAILED,
            raw_summary={
                "apk_file_id": apk_file_id,
                "parsing_status": "FAILED",
                "real_apk_parsing": False,
            },
            error_message=message,
        )

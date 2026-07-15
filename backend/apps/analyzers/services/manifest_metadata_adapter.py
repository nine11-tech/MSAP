from apps.analyzers.models import RawAnalyzerResult
from apps.analyzers.services.base import AnalyzerContext, AnalyzerResult
from apps.normalization.services.schemas import manifest_payload


class ManifestMetadataAdapter:
    """Future AndroidManifest.xml adapter.

    This contract intentionally does not extract or parse APK bytes yet. Real
    AndroidManifest.xml extraction is deferred to the next analyzer sprint.
    """

    name = "manifest_metadata_adapter"
    version = "0.1.0"
    description = "Placeholder contract for future AndroidManifest.xml metadata."
    enabled = True

    def supports(self, context: AnalyzerContext) -> bool:
        return context.apk_file.storage_reference_id is not None

    def run(self, context: AnalyzerContext) -> AnalyzerResult:
        apk_file = context.apk_file
        return AnalyzerResult(
            analyzer_name=self.name,
            analyzer_version=self.version,
            status=RawAnalyzerResult.Status.COMPLETED,
            raw_summary={
                "analysis_mode": "placeholder",
                "apk_file_id": apk_file.id,
                "parsing_status": "NOT_IMPLEMENTED",
                "real_apk_parsing": False,
            },
            normalized_artifacts=[
                manifest_payload(
                    source=self.name,
                    package_name=apk_file.package_name or None,
                    version_name=apk_file.version_name or None,
                )
            ],
        )

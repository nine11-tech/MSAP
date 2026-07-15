from dataclasses import dataclass

from django.db import transaction

from apps.analyzers.models import RawAnalyzerResult
from apps.analyzers.services.base import AnalyzerContext, PlaceholderMetadataAnalyzer
from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.normalization.models import NormalizedArtifact


@dataclass(frozen=True)
class AnalysisOrchestratorResult:
    audit_id: int
    apk_file_id: int
    raw_analyzer_result_id: int
    normalized_artifact_id: int
    analyzer_name: str
    analyzer_status: str
    summary: dict

    def as_dict(self) -> dict:
        return {
            "audit_id": self.audit_id,
            "apk_file_id": self.apk_file_id,
            "raw_analyzer_result_id": self.raw_analyzer_result_id,
            "normalized_artifact_id": self.normalized_artifact_id,
            "analyzer_name": self.analyzer_name,
            "analyzer_status": self.analyzer_status,
            "summary": self.summary,
        }


class AnalysisOrchestrator:
    def __init__(self, analyzers=None):
        self.analyzers = analyzers or [PlaceholderMetadataAnalyzer()]

    def run(self, audit_id: int, job_id: int | None = None) -> AnalysisOrchestratorResult:
        with transaction.atomic():
            audit = Audit.objects.select_for_update().get(id=audit_id)
            apk_file = (
                APKFile.objects.select_related("storage_reference")
                .filter(audit=audit)
                .order_by("-created_at", "-id")
                .first()
            )
            if apk_file is None:
                raise ValueError("Audit has no APK file to analyze.")
            if apk_file.storage_reference_id is None:
                raise ValueError("Latest APK file has no storage reference.")

            context = AnalyzerContext(audit=audit, apk_file=apk_file, job_id=job_id)
            analyzer = self._select_analyzer(context)
            analyzer_result = analyzer.run(context)

            raw_result = RawAnalyzerResult.objects.create(
                audit=audit,
                apk_file=apk_file,
                analyzer_name=analyzer_result.analyzer_name,
                analyzer_version=analyzer_result.analyzer_version,
                status=analyzer_result.status,
                storage_reference=None,
                result_summary=analyzer_result.summary,
                error_message=analyzer_result.error_message or None,
            )

            normalized_artifact = NormalizedArtifact.objects.create(
                audit=audit,
                apk_file=apk_file,
                artifact_type=NormalizedArtifact.ArtifactType.APK_METADATA,
                source=analyzer_result.analyzer_name,
                normalized_data={
                    "analysis_mode": "placeholder",
                    "apk_file_id": apk_file.id,
                    "package_name": apk_file.package_name,
                    "version_name": apk_file.version_name,
                    "sha256": apk_file.sha256,
                    "size_bytes": apk_file.size_bytes,
                    "storage_reference_id": apk_file.storage_reference_id,
                    "real_apk_parsing": False,
                },
                storage_reference=None,
            )

            return AnalysisOrchestratorResult(
                audit_id=audit.id,
                apk_file_id=apk_file.id,
                raw_analyzer_result_id=raw_result.id,
                normalized_artifact_id=normalized_artifact.id,
                analyzer_name=analyzer_result.analyzer_name,
                analyzer_status=analyzer_result.status,
                summary={
                    "created_raw_analyzer_results": 1,
                    "created_normalized_artifacts": 1,
                    "created_findings": 0,
                    "created_suspicious_indicators": 0,
                    "real_apk_parsing": False,
                    "external_tools_executed": [],
                },
            )

    def _select_analyzer(self, context: AnalyzerContext):
        for analyzer in self.analyzers:
            if analyzer.supports(context):
                return analyzer
        raise ValueError("No analyzer supports the current APK context.")

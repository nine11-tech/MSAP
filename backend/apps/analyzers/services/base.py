from dataclasses import dataclass, field
from typing import Protocol

from apps.apk_files.models import APKFile
from apps.audits.models import Audit


@dataclass(frozen=True)
class AnalyzerContext:
    audit: Audit
    apk_file: APKFile
    job_id: int | None = None


@dataclass(frozen=True)
class AnalyzerResult:
    analyzer_name: str
    analyzer_version: str
    status: str
    summary: dict = field(default_factory=dict)
    error_message: str = ""


class BaseAnalyzer(Protocol):
    name: str
    version: str

    def supports(self, context: AnalyzerContext) -> bool:
        ...

    def run(self, context: AnalyzerContext) -> AnalyzerResult:
        ...


class PlaceholderMetadataAnalyzer:
    name = "placeholder_metadata"
    version = "0.1.0"

    def supports(self, context: AnalyzerContext) -> bool:
        return context.apk_file.storage_reference_id is not None

    def run(self, context: AnalyzerContext) -> AnalyzerResult:
        apk_file = context.apk_file
        storage_reference = apk_file.storage_reference
        return AnalyzerResult(
            analyzer_name=self.name,
            analyzer_version=self.version,
            status="COMPLETED",
            summary={
                "analysis_mode": "placeholder",
                "audit_id": context.audit.id,
                "apk_file_id": apk_file.id,
                "package_name": apk_file.package_name,
                "version_name": apk_file.version_name,
                "sha256": apk_file.sha256,
                "size_bytes": apk_file.size_bytes,
                "storage_reference_id": apk_file.storage_reference_id,
                "storage_bucket": storage_reference.bucket if storage_reference else "",
                "storage_object_key": (
                    storage_reference.object_key if storage_reference else ""
                ),
                "real_apk_parsing": False,
            },
        )


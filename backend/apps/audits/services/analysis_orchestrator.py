from dataclasses import dataclass
from copy import deepcopy

from django.conf import settings

from apps.analyzers.models import RawAnalyzerResult
from apps.analyzers.services.base import AnalyzerContext
from apps.analyzers.services.registry import AnalyzerRegistry
from apps.analyzers.services.source_index import SourceIndexService
from apps.analyzers.services.source_verification import SourceVerificationService
from apps.appsec_rules.services.masvs_evaluator import evaluate_masvs_rules
from apps.apk_files.models import APKFile
from apps.audits.models import AnalysisJob, Audit
from apps.normalization.models import NormalizedArtifact
from apps.evidence.services.source_resolution import enrich_finding_source_references
from apps.evidence.models import FindingSourceReference, SourceDocument
from apps.scoring.services.compliance_scoring import (
    calculate_masvs_compliance,
    summarize_attck_triage,
)
from apps.scoring.services.risk_scoring import calculate_risk_score
from apps.triage_rules.services.attck_evaluator import evaluate_attck_indicators


@dataclass(frozen=True)
class AnalysisOrchestratorResult:
    audit_id: int
    apk_file_id: int
    summary: dict

    def as_dict(self) -> dict:
        return {
            "audit_id": self.audit_id,
            "apk_file_id": self.apk_file_id,
            "summary": self.summary,
        }


class AnalysisOrchestrator:
    def __init__(self, registry: AnalyzerRegistry | None = None):
        self.registry = registry or AnalyzerRegistry()

    def run(self, audit_id: int, job_id: int | None = None) -> AnalysisOrchestratorResult:
        audit = Audit.objects.get(id=audit_id)
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
        FindingSourceReference.objects.filter(finding__audit=audit).delete()
        SourceDocument.objects.filter(audit=audit).exclude(apk_file=apk_file).delete()
        NormalizedArtifact.objects.filter(audit=audit).exclude(apk_file=apk_file).delete()
        RawAnalyzerResult.objects.filter(audit=audit).exclude(apk_file=apk_file).delete()
        registered_analyzers = self.registry.get_registered_analyzers()
        supported_analyzers = self.registry.get_supported_analyzers(context)
        skipped_analyzers = [
            analyzer.name
            for analyzer in registered_analyzers
            if analyzer not in supported_analyzers
        ]
        if not supported_analyzers:
            raise ValueError("No analyzer supports the current APK context.")

        analyzers_run = []
        raw_results_created = 0
        normalized_artifacts_created = 0
        errors = []
        real_apk_parsing = False
        completed = 0
        _update_progress(
            job_id,
            current_stage="EXTRACTION",
            analyzers_total=len(registered_analyzers),
            analyzers_completed=0,
            analyzers_skipped=len(skipped_analyzers),
            analyzers_failed=0,
        )

        for analyzer in supported_analyzers:
            try:
                analyzer_result = analyzer.run(context)
            except Exception:
                safe_error = f"{analyzer.name} failed unexpectedly."
                errors.append({"analyzer": analyzer.name, "error": safe_error})
                RawAnalyzerResult.objects.update_or_create(
                    audit=audit,
                    apk_file=apk_file,
                    analyzer_name=analyzer.name,
                    defaults={
                        "analyzer_version": analyzer.version,
                        "status": RawAnalyzerResult.Status.FAILED,
                        "result_summary": {},
                        "error_message": safe_error,
                    },
                )
                raw_results_created += 1
                completed += 1
                _update_progress(
                    job_id,
                    analyzers_completed=completed,
                    analyzers_failed=len(errors),
                )
                continue

            RawAnalyzerResult.objects.update_or_create(
                audit=audit,
                apk_file=apk_file,
                analyzer_name=analyzer_result.analyzer_name,
                defaults={
                    "analyzer_version": analyzer_result.analyzer_version,
                    "status": analyzer_result.status,
                    "storage_reference": None,
                    "result_summary": analyzer_result.raw_summary,
                    "error_message": analyzer_result.error_message or None,
                },
            )
            raw_results_created += 1
            analyzers_run.append(analyzer_result.analyzer_name)
            completed += 1

            if analyzer_result.status == RawAnalyzerResult.Status.SKIPPED:
                skipped_analyzers.append(analyzer_result.analyzer_name)
            elif analyzer_result.status == RawAnalyzerResult.Status.FAILED:
                errors.append(
                    {
                        "analyzer": analyzer_result.analyzer_name,
                        "error": analyzer_result.error_message
                        or "Analyzer returned FAILED.",
                    }
                )
            real_apk_parsing = real_apk_parsing or bool(
                analyzer_result.raw_summary.get("real_apk_parsing", False)
            )

            for artifact_payload in analyzer_result.normalized_artifacts:
                normalized_data = deepcopy(artifact_payload.normalized_data)
                if artifact_payload.source_locators:
                    locator_target = normalized_data
                    if isinstance(normalized_data.get("data"), dict):
                        locator_target = normalized_data["data"]
                    locator_target["_source_locators"] = [
                        hint.as_dict() for hint in artifact_payload.source_locators
                    ]
                NormalizedArtifact.objects.update_or_create(
                    audit=audit,
                    apk_file=apk_file,
                    artifact_type=artifact_payload.artifact_type,
                    source=artifact_payload.source,
                    defaults={
                        "normalized_data": normalized_data,
                        "storage_reference_id": artifact_payload.storage_reference_id,
                    },
                )
                normalized_artifacts_created += 1
            _update_progress(
                job_id,
                analyzers_completed=completed,
                analyzers_skipped=len(set(skipped_analyzers)),
                analyzers_failed=len(errors),
            )

        source_index = {"status": "DISABLED"}
        if settings.MSAP_SOURCE_INDEX_ENABLED:
            _update_progress(job_id, current_stage="SOURCE_INDEXING")
            try:
                source_index = SourceIndexService().index(context).as_dict()
            except Exception:
                source_index = {
                    "status": "FAILED_SAFE",
                    "warnings": [
                        "Source indexing failed safely; metadata evidence remains available."
                    ],
                }

        source_verification = {"status": "SOURCE_UNAVAILABLE"}
        if source_index.get("jadx_status") == "COMPLETED":
            _update_progress(job_id, current_stage="SOURCE_VERIFICATION")
            try:
                source_verification = SourceVerificationService().verify(context).as_dict()
            except Exception:
                NormalizedArtifact.objects.filter(
                    audit=audit,
                    apk_file=apk_file,
                    artifact_type=NormalizedArtifact.ArtifactType.SOURCE_VERIFICATION,
                ).delete()
                source_verification = {
                    "status": "FAILED_SAFE",
                    "warnings": [
                        "Source verification failed safely; DEX observations remain review-only."
                    ],
                }

        _update_progress(job_id, current_stage="RULE_EVALUATION")
        masvs_evaluation = evaluate_masvs_rules(audit)
        source_evidence = enrich_finding_source_references(audit, apk_file)
        attck_evaluation = evaluate_attck_indicators(audit)
        scoring = {
            "risk": calculate_risk_score(audit.id),
            "masvs_compliance": calculate_masvs_compliance(audit.id),
            "attack_mobile_triage": summarize_attck_triage(audit.id),
        }
        summary = {
            "current_stage": "COMPLETED",
            "analyzers_total": len(registered_analyzers),
            "analyzers_completed": completed,
            "analyzers_skipped": len(set(skipped_analyzers)),
            "analyzers_failed": len(errors),
            "rules_evaluated": masvs_evaluation.get("evaluated_rules", 0),
            "findings_created": masvs_evaluation["findings_created"],
            "indicators_created": attck_evaluation["indicators_created"],
            "analyzers_run": analyzers_run,
            "raw_results_created": raw_results_created,
            "normalized_artifacts_created": normalized_artifacts_created,
            "skipped_analyzers": sorted(set(skipped_analyzers)),
            "errors": errors,
            "masvs_evaluation": masvs_evaluation,
            "source_index": source_index,
            "source_verification": source_verification,
            "source_evidence": source_evidence,
            "attck_evaluation": attck_evaluation,
            "scoring": scoring,
            "created_raw_analyzer_results": raw_results_created,
            "created_normalized_artifacts": normalized_artifacts_created,
            "created_findings": masvs_evaluation["findings_created"],
            "created_suspicious_indicators": attck_evaluation[
                "indicators_created"
            ],
            "created_evidence": (
                masvs_evaluation["evidence_created"]
                + attck_evaluation["evidence_created"]
            ),
            "real_apk_parsing": real_apk_parsing,
            "external_tools_executed": (
                ["jadx"] if source_index.get("jadx_status") == "COMPLETED" else []
            ),
        }
        _update_progress(job_id, **{
            key: summary[key]
            for key in (
                "current_stage",
                "analyzers_total",
                "analyzers_completed",
                "analyzers_skipped",
                "analyzers_failed",
                "rules_evaluated",
                "findings_created",
                "indicators_created",
            )
        })
        return AnalysisOrchestratorResult(
            audit_id=audit.id,
            apk_file_id=apk_file.id,
            summary=summary,
        )


def _update_progress(job_id: int | None, **updates) -> None:
    if job_id is None:
        return
    job = AnalysisJob.objects.filter(id=job_id).first()
    if job is None:
        return
    summary = job.result_summary if isinstance(job.result_summary, dict) else {}
    progress = summary.get("progress", {})
    if not isinstance(progress, dict):
        progress = {}
    progress.update(updates)
    summary["progress"] = progress
    job.result_summary = summary
    job.save(update_fields=["result_summary", "updated_at"])

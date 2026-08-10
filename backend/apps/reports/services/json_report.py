from collections import Counter
from pathlib import PurePosixPath
import re

from django.db import transaction
from django.db.models import Prefetch

from apps.analyzers.models import RawAnalyzerResult
from apps.appsec_rules.models import RuleEvaluation
from apps.appsec_rules.services.coverage import calculate_rule_coverage
from apps.apk_files.models import APKFile
from apps.audits.models import AnalysisJob, Audit
from apps.evidence.models import Evidence, FindingSourceReference, SourceDocument
from apps.findings.models import Finding
from apps.indicators.models import SuspiciousIndicator
from apps.normalization.models import NormalizedArtifact
from apps.reports.models import Report
from apps.scoring.services.compliance_scoring import (
    calculate_masvs_compliance,
    summarize_attck_triage,
)
from apps.scoring.services.risk_scoring import calculate_risk_score
from apps.triage_rules.services.triage_rule_loader import default_attck_rules_by_id


REPORT_LIMITATIONS = [
    "Static analysis only",
    "No runtime behavior is observed",
    "Coverage does not include all MASVS controls",
    "Only implemented deterministic rules are evaluated",
    "ATT&CK indicators are triage signals, not malware verdicts",
    "Absence of a finding does not prove absence of a vulnerability",
]


@transaction.atomic
def generate_json_report(audit_id: int) -> dict:
    audit = Audit.objects.select_related("project").get(id=audit_id)
    apk_file = (
        APKFile.objects.select_related("storage_reference")
        .filter(audit_id=audit_id)
        .order_by("-created_at", "-id")
        .first()
    )
    findings = list(
        Finding.objects.filter(audit_id=audit_id)
        .prefetch_related(
            Prefetch(
                "source_references",
                queryset=FindingSourceReference.objects.select_related(
                    "source_document"
                ).order_by("-is_primary", "id"),
            )
        )
        .order_by("id")
    )
    indicators = list(
        SuspiciousIndicator.objects.filter(audit_id=audit_id).order_by("id")
    )
    evidence = list(Evidence.objects.filter(audit_id=audit_id).order_by("id"))
    artifacts = list(
        NormalizedArtifact.objects.filter(audit_id=audit_id)
        .only("id", "artifact_type", "source", "created_at")
        .order_by("id")
    )
    evaluations = list(
        RuleEvaluation.objects.filter(audit_id=audit_id).order_by("framework", "rule_id")
    )
    analyzer_results = list(
        RawAnalyzerResult.objects.filter(audit_id=audit_id).order_by("analyzer_name")
    )
    latest_job = (
        AnalysisJob.objects.filter(audit_id=audit_id)
        .order_by("-created_at", "-id")
        .first()
    )
    source_documents = list(
        SourceDocument.objects.filter(audit_id=audit_id).order_by(
            "logical_path", "id"
        )
    )

    risk = calculate_risk_score(audit_id)
    masvs_compliance = calculate_masvs_compliance(audit_id)
    attack_mobile_triage = summarize_attck_triage(audit_id)
    report_record, _ = Report.objects.get_or_create(
        audit_id=audit_id,
        report_type=Report.ReportType.JSON,
    )

    artifact_counts = Counter(artifact.artifact_type for artifact in artifacts)
    return {
        "report": {
            "id": report_record.id,
            "report_type": "JSON",
            "recorded_at": _isoformat(report_record.created_at),
        },
        "audit": {
            "id": audit.id,
            "name": audit.name,
            "status": audit.status,
            "created_at": _isoformat(audit.created_at),
            "updated_at": _isoformat(audit.updated_at),
        },
        "project": {
            "id": audit.project.id,
            "name": audit.project.name,
            "description": audit.project.description,
        },
        "apk": _apk_data(apk_file),
        "summary": {
            "risk": risk,
            "masvs_compliance": masvs_compliance,
            "attack_mobile_triage": attack_mobile_triage,
            "coverage": calculate_rule_coverage(audit_id),
        },
        "findings": [_finding_data(finding) for finding in findings],
        "indicators": [_indicator_data(indicator) for indicator in indicators],
        "rule_evaluations": [_evaluation_data(item) for item in evaluations],
        "analyzer_results": [
            {
                "name": item.analyzer_name,
                "version": item.analyzer_version,
                "status": item.status,
                "message": (
                    item.error_message
                    if item.error_message
                    in {
                        "Analyzer is disabled.",
                        "Analyzer capability is unavailable.",
                        "No local APK path is available.",
                    }
                    else ("Analyzer did not complete." if item.error_message else "")
                ),
            }
            for item in analyzer_results
        ],
        "evidence": [_evidence_data(item) for item in evidence],
        "normalized_artifacts": {
            "count": len(artifacts),
            "by_type": dict(sorted(artifact_counts.items())),
            "items": [
                {
                    "id": artifact.id,
                    "artifact_type": artifact.artifact_type,
                    "source": artifact.source,
                    "created_at": _isoformat(artifact.created_at),
                }
                for artifact in artifacts
            ],
        },
        "source_documents": {
            "count": len(source_documents),
            "items": [
                {
                    "id": document.id,
                    "representation": document.representation_type,
                    "path": document.logical_path,
                    "sha256": document.sha256,
                    "line_count": document.line_count,
                    "generated_by": document.generated_by,
                    "tool_version": document.tool_version,
                }
                for document in source_documents
            ],
        },
        "analysis_job": _analysis_job_data(latest_job),
        "limitations": REPORT_LIMITATIONS,
    }


def _apk_data(apk_file: APKFile | None) -> dict | None:
    if apk_file is None:
        return None
    storage_reference = apk_file.storage_reference
    return {
        "id": apk_file.id,
        "filename": _apk_filename(storage_reference.object_key)
        if storage_reference is not None
        else "",
        "package_name": apk_file.package_name,
        "version_name": apk_file.version_name,
        "sha256": apk_file.sha256,
        "size_bytes": apk_file.size_bytes,
        "storage_status": storage_reference.storage_status
        if storage_reference is not None
        else "",
        "created_at": _isoformat(apk_file.created_at),
    }


def _finding_data(finding: Finding) -> dict:
    return {
        "id": finding.id,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "standard": finding.standard,
        "category": finding.category,
        "description": finding.description,
        "mappings": finding.mapping_data,
        "recommendation": finding.recommendation,
        "false_positive_guidance": finding.false_positive_guidance,
        "requires_manual_validation": finding.requires_manual_validation,
        "source_evidence": [
            _source_reference_data(reference)
            for reference in finding.source_references.all()
        ],
    }


def _source_reference_data(reference: FindingSourceReference) -> dict:
    document = reference.source_document
    return {
        "id": reference.id,
        "source_document_id": reference.source_document_id,
        "representation": reference.representation_type,
        "representation_label": reference.get_representation_type_display(),
        "path": reference.logical_path,
        "class_name": reference.class_name,
        "method_name": reference.method_name,
        "method_descriptor": reference.method_descriptor,
        "symbol": reference.symbol_name,
        "start_line": reference.start_line,
        "end_line": reference.end_line,
        "start_offset": reference.start_offset,
        "end_offset": reference.end_offset,
        "excerpt": reference.excerpt,
        "excerpt_sha256": reference.excerpt_sha256,
        "source_document_sha256": document.sha256 if document else "",
        "provenance": reference.provenance,
        "provenance_chain": (
            reference.locator.get("provenance_chain", {})
            if isinstance(reference.locator, dict)
            else {}
        ),
        "confidence": reference.confidence,
        "is_primary": reference.is_primary,
        "source_lines_available": reference.source_lines_available,
        "reason": reference.unavailable_reason,
    }


def _indicator_data(indicator: SuspiciousIndicator) -> dict:
    catalog_rule = default_attck_rules_by_id().get(indicator.indicator_id, {})
    return {
        "id": indicator.id,
        "indicator_id": indicator.indicator_id,
        "title": indicator.title,
        "tactic": indicator.tactic,
        "technique_id": indicator.technique_id,
        "technique_name": indicator.technique_name,
        "severity": indicator.severity,
        "confidence": indicator.confidence,
        "triage_interpretation": indicator.triage_interpretation,
        "auditor_explanation": (
            indicator.auditor_explanation
            or catalog_rule.get("auditor_explanation")
            or indicator.triage_interpretation
        ),
        "dynamic_verification_scenario": (
            indicator.dynamic_verification_scenario
            or catalog_rule.get("dynamic_verification_scenario", "")
        ),
        "source_evidence": indicator.source_evidence,
        "mapping_rationale": indicator.mapping_rationale,
        "false_positive_considerations": indicator.false_positive_considerations,
        "requires_manual_validation": indicator.requires_manual_validation,
        "non_malware_verdict_note": indicator.non_malware_verdict_note,
    }


def _evaluation_data(evaluation: RuleEvaluation) -> dict:
    return {
        "framework": evaluation.framework,
        "rule_id": evaluation.rule_id,
        "result": evaluation.result,
        "title": evaluation.title,
        "severity": evaluation.severity,
        "confidence": evaluation.confidence,
        "mappings": evaluation.mapping_data,
        "evidence_summary": evaluation.evidence_summary,
        "remediation": evaluation.remediation,
        "requires_manual_validation": evaluation.requires_manual_validation,
        "evaluator_version": evaluation.evaluator_version,
    }


def _evidence_data(evidence: Evidence) -> dict:
    return {
        "id": evidence.id,
        "finding_id": evidence.finding_id,
        "indicator_id": evidence.indicator_id,
        "evidence_type": evidence.evidence_type,
        "source": evidence.source,
        "snippet": evidence.snippet,
        "redacted": evidence.redacted,
    }


def _analysis_job_data(job: AnalysisJob | None) -> dict | None:
    if job is None:
        return None
    result = job.result_summary if isinstance(job.result_summary, dict) else {}
    orchestrator_summary = result.get("summary", result)
    if not isinstance(orchestrator_summary, dict):
        orchestrator_summary = {}
    analyzers_run = orchestrator_summary.get("analyzers_run", [])
    errors = orchestrator_summary.get("errors", [])
    return {
        "id": job.id,
        "status": job.status,
        "started_at": _isoformat(job.started_at),
        "finished_at": _isoformat(job.finished_at),
        "summary": {
            "analyzer_names": analyzers_run if isinstance(analyzers_run, list) else [],
            "analyzer_count": len(analyzers_run)
            if isinstance(analyzers_run, list)
            else 0,
            "raw_results_created": orchestrator_summary.get(
                "raw_results_created",
                0,
            ),
            "normalized_artifacts_created": orchestrator_summary.get(
                "normalized_artifacts_created",
                0,
            ),
            "error_count": len(errors) if isinstance(errors, list) else 0,
            "real_apk_parsing": bool(
                orchestrator_summary.get("real_apk_parsing", False)
            ),
        },
    }


def _isoformat(value) -> str | None:
    return value.isoformat() if value is not None else None


def _apk_filename(object_key: str) -> str:
    filename = PurePosixPath(object_key).name
    return re.sub(r"^[0-9a-fA-F]{32}-", "", filename)

from collections import Counter
from pathlib import PurePosixPath
import re

from django.db import transaction

from apps.apk_files.models import APKFile
from apps.audits.models import AnalysisJob, Audit
from apps.evidence.models import Evidence
from apps.findings.models import Finding
from apps.indicators.models import SuspiciousIndicator
from apps.normalization.models import NormalizedArtifact
from apps.reports.models import Report
from apps.scoring.services.compliance_scoring import (
    calculate_masvs_compliance,
    summarize_attck_triage,
)
from apps.scoring.services.risk_scoring import calculate_risk_score


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
    findings = list(Finding.objects.filter(audit_id=audit_id).order_by("id"))
    indicators = list(
        SuspiciousIndicator.objects.filter(audit_id=audit_id).order_by("id")
    )
    evidence = list(Evidence.objects.filter(audit_id=audit_id).order_by("id"))
    artifacts = list(
        NormalizedArtifact.objects.filter(audit_id=audit_id)
        .only("id", "artifact_type", "source", "created_at")
        .order_by("id")
    )
    latest_job = (
        AnalysisJob.objects.filter(audit_id=audit_id)
        .order_by("-created_at", "-id")
        .first()
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
        },
        "findings": [_finding_data(finding) for finding in findings],
        "indicators": [_indicator_data(indicator) for indicator in indicators],
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
        "recommendation": finding.recommendation,
    }


def _indicator_data(indicator: SuspiciousIndicator) -> dict:
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

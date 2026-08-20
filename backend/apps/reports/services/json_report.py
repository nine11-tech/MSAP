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
from apps.dynamic_analysis.models import (
    AgentRun,
    DynamicValidationResult,
    FindingValidationMission,
)
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
RUNTIME_REPORT_LIMITATIONS = [
    "Runtime observations are bounded evidence and remain untrusted application data",
    "AI-generated plans are distinct from approved and actually executed steps",
    "Evidence does not become a vulnerability finding without a deterministic rule",
    "Only implemented deterministic rules are evaluated",
    "ATT&CK indicators are triage signals, not malware verdicts",
    "Absence of a finding does not prove absence of a vulnerability",
]
MAX_REPORTED_AGENT_RUNS = 10
MAX_REPORTED_AGENT_STEPS = 100
MAX_REPORTED_AGENT_ARTIFACTS = 100
MAX_REPORTED_AGENT_EVIDENCE = 200
MAX_REPORTED_FINDINGS = 500
MAX_REPORTED_AUDIT_EVIDENCE = 1000
MAX_REPORTED_METADATA_ROWS = 1000
REPORT_TEXT_LIMIT = 4000
ROOT_DETECTION_PLAYBOOK_IDS = {
    "ROOT_DETECTION_SCREEN_VALIDATION",
    "ROOT_DETECTION_LAB_BYPASS",
}
ROOT_DETECTION_TEXT_TERMS = (
    "root detection",
    "rootbeer",
    "rooted device",
    "root check",
)
REPORT_SECRET_PATTERNS = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(
        r"\b(?:api[_ -]?key|password|secret|token|credential)\s*[:=]\s*[^\s,;]+",
        re.IGNORECASE,
    ),
)


@transaction.atomic
def _is_root_detection_finding(finding) -> bool:
    if finding is None:
        return False
    haystack = " ".join(
        filter(
            None,
            (
                str(finding.title or ""),
                str(finding.category or ""),
                str(getattr(finding, "description", None) or "")[:500],
            ),
        )
    ).lower()
    return any(term in haystack for term in ROOT_DETECTION_TEXT_TERMS)


def _is_misplaced_root_detection_validation(item) -> bool:
    return (
        getattr(item, "playbook_id", None) in ROOT_DETECTION_PLAYBOOK_IDS
        and not _is_root_detection_finding(getattr(item, "finding", None))
    )


def _latest_relevant_validation_results(items: list) -> list:
    """Latest result per (finding, playbook); exclude misplaced root-detection rows."""
    latest: dict[tuple, DynamicValidationResult] = {}
    for item in items:
        if _is_misplaced_root_detection_validation(item):
            continue
        key = (item.finding_id, item.playbook_id)
        previous = latest.get(key)
        if previous is None or item.created_at >= previous.created_at:
            latest[key] = item
    return sorted(latest.values(), key=lambda item: item.created_at, reverse=True)


def _latest_relevant_missions(items: list) -> list:
    """Latest mission per (finding, playbook); exclude misplaced root-detection missions."""
    latest: dict[tuple, FindingValidationMission] = {}
    for mission in items:
        if _is_misplaced_root_detection_validation(mission):
            continue
        key = (mission.finding_id, mission.playbook_id)
        previous = latest.get(key)
        if previous is None or mission.created_at >= previous.created_at:
            latest[key] = mission
    return sorted(latest.values(), key=lambda mission: mission.created_at, reverse=True)


def _validation_result_data(item: DynamicValidationResult) -> dict:
    return {
        "id": item.id,
        "finding_id": item.finding_id,
        "rule_id": item.rule_id,
        "static_finding": (
            item.finding.title if item.finding is not None else item.rule_id
        ),
        "playbook_id": item.playbook_id,
        "validation_status": item.validation_status,
        "result": item.oracle_result.get("result_contract", {}).get(
            "result", item.validation_status
        ),
        "scenario_id": item.scenario_id,
        "oracle_id": item.oracle_id,
        "oracle_result": item.oracle_result,
        "evidence_ids": [evidence.id for evidence in item.evidence.all()[:100]],
        "safe_summary": _redact_report_text(item.safe_summary),
        "limitations": _redact_report_text(item.limitations),
    }


def _mission_data(mission: FindingValidationMission) -> dict:
    return {
        "id": mission.id,
        "finding_id": mission.finding_id,
        "rule_id": mission.finding.rule_id,
        "static_finding": mission.finding.title,
        "playbook_id": mission.playbook_id,
        "status": mission.status,
        "target_package": mission.target_package,
        "assessment_plan_id": mission.assessment_plan_id,
        "agent_run_id": mission.agent_run_id,
        "dynamic_validation_result_id": mission.dynamic_validation_result_id,
        "hypothesis": _redact_report_text(mission.hypothesis),
        "poc_scenario_summary": _redact_report_text(
            mission.scenario_contract.get("validation_goal", "")
            if isinstance(mission.scenario_contract, dict)
            else ""
        ),
        "executed_actions": [
            {
                "sequence": step.sequence_number,
                "scenario_step": step.plan_step_identifier,
                "tool": step.tool_name,
                "status": step.status,
                "evidence_requirements": step.evidence_requirements,
                "failure_message": _redact_report_text(step.failure_message),
            }
            for step in (
                mission.agent_run.steps.order_by("sequence_number")[:MAX_REPORTED_AGENT_STEPS]
                if mission.agent_run_id
                else []
            )
        ],
        "troubleshooting": [
            {
                "sequence": step.sequence_number,
                "scenario_step": step.plan_step_identifier,
                "retry_count": step.retry_count,
                "failure_message": _redact_report_text(step.failure_message),
            }
            for step in (
                mission.agent_run.steps.filter(retry_count__gt=0).order_by("sequence_number")[:MAX_REPORTED_AGENT_STEPS]
                if mission.agent_run_id
                else []
            )
        ],
        "evidence_ids": [item.id for item in mission.evidence.all()[:100]],
        "oracle_result": mission.oracle_result,
        "final_conclusion": _redact_report_text(mission.final_conclusion),
        "limitations": _redact_report_text(mission.limitations),
        "scenario_hash": mission.scenario_hash,
        "mission_hash": mission.mission_hash,
    }


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
        .order_by("id")[:MAX_REPORTED_FINDINGS]
    )
    indicators = list(
        SuspiciousIndicator.objects.filter(audit_id=audit_id).order_by("id")[
            :MAX_REPORTED_FINDINGS
        ]
    )
    evidence = list(
        Evidence.objects.filter(audit_id=audit_id).order_by("id")[
            :MAX_REPORTED_AUDIT_EVIDENCE
        ]
    )
    artifacts = list(
        NormalizedArtifact.objects.filter(audit_id=audit_id)
        .only("id", "artifact_type", "source", "created_at")
        .order_by("id")[:MAX_REPORTED_METADATA_ROWS]
    )
    evaluations = list(
        RuleEvaluation.objects.filter(audit_id=audit_id).order_by(
            "framework", "rule_id"
        )[:MAX_REPORTED_METADATA_ROWS]
    )
    analyzer_results = list(
        RawAnalyzerResult.objects.filter(audit_id=audit_id).order_by("analyzer_name")[
            :MAX_REPORTED_METADATA_ROWS
        ]
    )
    latest_job = (
        AnalysisJob.objects.filter(audit_id=audit_id)
        .order_by("-created_at", "-id")
        .first()
    )
    source_documents = list(
        SourceDocument.objects.filter(audit_id=audit_id).order_by(
            "logical_path", "id"
        )[:MAX_REPORTED_METADATA_ROWS]
    )
    agent_runs = list(
        AgentRun.objects.filter(
            audit_id=audit_id,
            objective=AgentRun.Objective.ASSESSMENT_PLAN_EXECUTION,
        )
        .select_related("assessment_plan", "runtime")
        .order_by("-created_at", "-id")[:MAX_REPORTED_AGENT_RUNS]
    )
    validation_results = list(
        DynamicValidationResult.objects.filter(audit_id=audit_id)
        .select_related("finding")
        .prefetch_related("evidence")
        .order_by("-created_at")[:MAX_REPORTED_FINDINGS]
    )
    validation_missions = list(
        FindingValidationMission.objects.filter(audit_id=audit_id)
        .select_related(
            "finding",
            "assessment_plan",
            "agent_run",
            "dynamic_validation_result",
        )
        .prefetch_related("evidence")
        .order_by("-created_at")[:MAX_REPORTED_FINDINGS]
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
        "dynamic_assessments": {
            "count": AgentRun.objects.filter(
                audit_id=audit_id,
                objective=AgentRun.Objective.ASSESSMENT_PLAN_EXECUTION,
            ).count(),
            "items": [_agent_run_data(run) for run in agent_runs],
            "bounded": True,
            "planner_is_execution_authority": False,
            "finding_authority": "DETERMINISTIC_RULES_ONLY",
            "dynamic_validations": [
                _validation_result_data(item)
                for item in _latest_relevant_validation_results(validation_results)
            ],
            "debug_raw_validation_trail": [
                _validation_result_data(item) for item in validation_results
            ],
            "finding_validation_missions": [
                _mission_data(mission)
                for mission in _latest_relevant_missions(validation_missions)
            ],
        },
        "limitations": (
            RUNTIME_REPORT_LIMITATIONS
            if (agent_runs or validation_results or validation_missions)
            else REPORT_LIMITATIONS
        ),
    }


def _agent_run_data(run: AgentRun) -> dict:
    plan = run.assessment_plan
    steps = list(
        run.steps.order_by("sequence_number").values(
            "id",
            "sequence_number",
            "plan_step_identifier",
            "tool_name",
            "status",
            "started_at",
            "finished_at",
            "duration_seconds",
            "retry_count",
            "failure_message",
        )[:MAX_REPORTED_AGENT_STEPS]
    )
    artifacts = list(
        run.artifacts.order_by("id").values(
            "id",
            "step_id",
            "artifact_type",
            "name",
            "content_type",
            "size_bytes",
            "sha256",
            "object_reference_id",
        )[:MAX_REPORTED_AGENT_ARTIFACTS]
    )
    evidence = list(
        run.evidence_records.order_by("id").values(
            "id",
            "finding_id",
            "agent_run_step_id",
            "agent_run_artifact_id",
            "evidence_type",
            "source",
            "snippet",
            "redacted",
            "sha256",
            "created_at",
        )[:MAX_REPORTED_AGENT_EVIDENCE]
    )
    capabilities = sorted(
        {
            row["tool_name"]
            for row in steps
            if row["tool_name"] != "assessment_plan_observation"
        }
    )
    return {
        "run_id": run.id,
        "status": run.status,
        "target_package": run.target_package,
        "started_at": _isoformat(run.started_at),
        "finished_at": _isoformat(run.finished_at),
        "duration_seconds": run.duration_seconds,
        "execution_channel": "RUN_SCOPED_TOOL_GATEWAY",
        "runtime": run.runtime.name if run.runtime_id else "Unavailable",
        "plan": {
            "id": run.assessment_plan_id,
            "kind": plan.plan_kind if plan is not None else "Unavailable",
            "adaptive_cycle": plan.adaptive_cycle if plan is not None else 0,
            "parent_plan_id": plan.parent_plan_id if plan is not None else None,
            "source_run_id": plan.source_run_id if plan is not None else None,
            "hash": run.approved_plan_hash,
            "planner_provider": plan.planner_provider if plan is not None else "Unavailable",
            "planner_model": plan.planner_model if plan is not None else "Unavailable",
            "objective": _redact_report_text(plan.objective if plan is not None else ""),
            "scope": _redact_report_text(plan.scope if plan is not None else ""),
            "approved_by_id": plan.approved_by_id if plan is not None else None,
            "approved_at": _isoformat(plan.approved_at) if plan is not None else None,
        },
        "capabilities_used": capabilities,
        "steps": [
            {
                **{key: value for key, value in row.items() if key != "failure_message"},
                "started_at": _isoformat(row["started_at"]),
                "finished_at": _isoformat(row["finished_at"]),
                "failure_message": _redact_report_text(row["failure_message"]),
                "artifact_count": sum(
                    1 for artifact in artifacts if artifact["step_id"] == row["id"]
                ),
                "evidence_count": sum(
                    1
                    for item in evidence
                    if item["agent_run_step_id"] == row["id"]
                ),
            }
            for row in steps
        ],
        "artifacts": [
            {
                **row,
                "name": _redact_report_text(row["name"], limit=255),
            }
            for row in artifacts
        ],
        "evidence": [
            {
                **row,
                "source": _redact_report_text(row["source"], limit=500),
                "snippet": _redact_report_text(row["snippet"]),
                "created_at": _isoformat(row["created_at"]),
            }
            for row in evidence
        ],
        "finding_ids": sorted(
            {row["finding_id"] for row in evidence if row["finding_id"] is not None}
        ),
        "provenance": {
            "plan": "CANONICAL_APPROVED_ASSESSMENT_PLAN_V1",
            "execution": "SEQUENTIAL_BOUNDED_EXECUTOR",
            "observations": "UNTRUSTED_APPLICATION_DATA",
            "findings": "DETERMINISTIC_RULE_EVALUATION",
        },
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
    linked_evidence = list(
        finding.evidence.order_by("id").values(
            "agent_run_id", "agent_run_step_id", "agent_run_artifact_id"
        )[:MAX_REPORTED_AGENT_EVIDENCE]
    )
    return {
        "id": finding.id,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "standard": finding.standard,
        "category": finding.category,
        "description": _redact_report_text(finding.description),
        "mappings": finding.mapping_data,
        "recommendation": _redact_report_text(finding.recommendation),
        "false_positive_guidance": _redact_report_text(
            finding.false_positive_guidance
        ),
        "requires_manual_validation": finding.requires_manual_validation,
        "status": finding.status,
        "evidence_count": finding.evidence.count(),
        "related_agent_run_ids": sorted(
            {row["agent_run_id"] for row in linked_evidence if row["agent_run_id"]}
        ),
        "related_agent_run_step_ids": sorted(
            {
                row["agent_run_step_id"]
                for row in linked_evidence
                if row["agent_run_step_id"]
            }
        ),
        "provenance": (
            "DETERMINISTIC_DYNAMIC_EVIDENCE"
            if finding.rule_id.startswith("MSAP-DYN-")
            else "DETERMINISTIC_STATIC_RULE"
        ),
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
        "agent_run_id": evidence.agent_run_id,
        "agent_run_step_id": evidence.agent_run_step_id,
        "agent_run_artifact_id": evidence.agent_run_artifact_id,
        "source": _redact_report_text(evidence.source, limit=500),
        "snippet": _redact_report_text(evidence.snippet),
        "redacted": evidence.redacted,
        "sha256": evidence.sha256,
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


def _redact_report_text(value, *, limit: int = REPORT_TEXT_LIMIT) -> str:
    text = str(value or "").replace("\x00", "")
    for pattern in REPORT_SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text[:limit]

"""Post-run deterministic evidence, scoring, and reporting integration."""

from __future__ import annotations

from collections import Counter
import logging
from typing import Any

from apps.appsec_rules.services.dynamic_evidence_evaluator import (
    evaluate_dynamic_evidence,
)
from apps.dynamic_analysis.models import AgentRun, AgentRunStep
from apps.findings.models import Finding
from apps.reports.models import Report
from apps.reports.services.json_report import generate_json_report
from apps.scoring.models import ComplianceScore, RiskScore


logger = logging.getLogger(__name__)


def resolve_completed_assessment(run: AgentRun | int) -> dict[str, Any]:
    """Resolve only deterministic post-processing for a terminal AgentRun."""

    run_id = run.pk if isinstance(run, AgentRun) else run
    run = AgentRun.objects.select_related("audit", "assessment_plan").get(pk=run_id)
    if run.status not in {
        AgentRun.Status.SUCCEEDED,
        AgentRun.Status.FAILED,
        AgentRun.Status.TIMEOUT,
    }:
        return {
            "status": "NOT_APPLICABLE",
            "reason": "AgentRun is not a completed assessment execution.",
        }
    rule_summary = evaluate_dynamic_evidence(run)
    report = generate_json_report(run.audit_id)
    summary = build_assessment_summary(run)
    logger.info(
        "assessment_results_resolved run_id=%s rules=%s findings=%s "
        "evidence=%s report_id=%s",
        run.id,
        rule_summary["rules_evaluated"],
        summary["run_finding_count"],
        summary["evidence_count"],
        report["report"]["id"],
    )
    return {
        "status": "COMPLETED",
        "deterministic_rules": rule_summary,
        "assessment_summary": summary,
        "report": {
            "id": report["report"]["id"],
            "type": report["report"]["report_type"],
            "status": "READY",
        },
    }


def build_assessment_summary(run: AgentRun | int) -> dict[str, Any]:
    run_id = run.pk if isinstance(run, AgentRun) else run
    run = AgentRun.objects.select_related("assessment_plan", "audit").get(pk=run_id)
    run_findings = list(
        Finding.objects.filter(evidence__agent_run=run)
        .distinct()
        .order_by("rule_id")
        .values(
            "id",
            "rule_id",
            "title",
            "severity",
            "confidence",
            "status",
            "category",
        )[:100]
    )
    audit_findings = list(
        Finding.objects.filter(audit_id=run.audit_id).values_list(
            "severity", flat=True
        )[:1000]
    )
    severity_counts = Counter(_severity_label(value) for value in audit_findings)
    risk = RiskScore.objects.filter(audit_id=run.audit_id).order_by("-created_at").first()
    compliance = (
        ComplianceScore.objects.filter(audit_id=run.audit_id, standard="MASVS")
        .order_by("-created_at")
        .first()
    )
    report = (
        Report.objects.filter(
            audit_id=run.audit_id,
            report_type=Report.ReportType.JSON,
        )
        .order_by("-created_at")
        .first()
    )
    step_counts = Counter(run.steps.values_list("status", flat=True))
    return {
        "contract_version": "msap.assessment-summary/v1",
        "audit_id": run.audit_id,
        "target_package": run.target_package,
        "assessment_status": run.status,
        "assessment_plan_id": run.assessment_plan_id,
        "plan_hash": run.approved_plan_hash,
        "execution_mode": run.execution_mode,
        "capability_envelope_hash": run.capability_envelope_hash,
        "agent_run_id": run.id,
        "steps_total": run.steps.count(),
        "steps_succeeded": step_counts[AgentRunStep.Status.SUCCEEDED],
        "step_status_counts": dict(step_counts),
        "tool_call_count": run.tool_call_count,
        "decision_count": run.decision_count,
        "model_call_count": run.model_call_count,
        "coverage": run.coverage_state,
        "termination_reason": run.termination_reason,
        "observation_count": run.steps.exclude(observation={}).count(),
        "artifact_count": run.artifacts.count(),
        "evidence_count": run.evidence_records.count(),
        "run_finding_count": len(run_findings),
        "audit_finding_count": len(audit_findings),
        "finding_severity_counts": {
            severity: severity_counts.get(severity, 0)
            for severity in ("Critical", "High", "Medium", "Low", "Informational")
        },
        "run_findings": run_findings,
        "risk": {
            "score": float(risk.score) if risk is not None else None,
            "severity": risk.severity if risk is not None else "Unavailable",
        },
        "compliance": {
            "standard": compliance.standard if compliance is not None else "MASVS",
            "score": float(compliance.score) if compliance is not None else None,
        },
        "report": {
            "id": report.id if report is not None else None,
            "status": "READY" if report is not None else "NOT_GENERATED",
            "type": "JSON",
        },
        "provenance": {
            "planner": "AI_OR_DETERMINISTIC_PLAN_PROVIDER",
            "execution": (
                "ADAPTIVE_DECISIONS_VIA_RUN_SCOPED_TOOL_GATEWAY"
                if run.execution_mode == AgentRun.ExecutionMode.ADAPTIVE_AGENT
                else "APPROVED_PLAN_VIA_RUN_SCOPED_TOOL_GATEWAY"
            ),
            "observations": "UNTRUSTED_APPLICATION_DATA",
            "findings": "DETERMINISTIC_RULES_ONLY",
            "scores": "DETERMINISTIC_SCORING_ONLY",
        },
    }


def _severity_label(value: str) -> str:
    normalized = str(value or "Informational").strip().lower()
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Informational",
        "informational": "Informational",
    }.get(normalized, "Informational")

"""Post-run deterministic evidence, scoring, and reporting integration."""

from __future__ import annotations

from collections import Counter
import logging
from typing import Any

from apps.appsec_rules.services.dynamic_evidence_evaluator import (
    evaluate_dynamic_evidence,
)
from apps.dynamic_analysis.models import AgentRun, AgentRunStep, DynamicValidationResult
from apps.dynamic_analysis.services.dynamic_validation import record_dynamic_validation
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
    validation_summary = _resolve_playbook_validations(run)
    try:
        from apps.dynamic_analysis.services.finding_validation_missions import (
            refresh_mission_from_run,
        )

        refresh_mission_from_run(run)
    except Exception:
        logger.warning(
            "finding_validation_mission_refresh_failed run_id=%s",
            run.id,
            exc_info=True,
        )
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
        "dynamic_validations": validation_summary,
        "assessment_summary": summary,
        "report": {
            "id": report["report"]["id"],
            "type": report["report"]["report_type"],
            "status": "READY",
        },
    }


def _resolve_playbook_validations(run: AgentRun) -> list[dict[str, Any]]:
    """Persist conservative finding-linked results from approved playbook steps."""
    plan = run.assessment_plan
    if plan is None or not isinstance(plan.normalized_plan, dict):
        return []
    step_tools = {
        tool.get("name")
        for step in plan.normalized_plan.get("steps", [])
        if isinstance(step, dict)
        for tool in step.get("tools", [])
        if isinstance(tool, dict)
    }
    mapping = {
        "launch_exported_activity": "EXPORTED_ACTIVITY_LAUNCH_VERIFICATION",
        "send_explicit_broadcast": "EXPORTED_RECEIVER_BROADCAST_VERIFICATION",
        "query_exported_provider": "EXPORTED_PROVIDER_ACCESS_VERIFICATION",
        "frida_attach": "DEBUGGABLE_APP_VERIFICATION",
        "frida_run_js": "DEBUGGABLE_APP_VERIFICATION",
    }
    source_finding = plan.source_finding if plan is not None else None
    lab_sources = {
        "__MSAP_ROOT_DETECTION_LAB_BYPASS_TEMPLATE__": "ROOT_DETECTION_LAB_BYPASS",
        "__MSAP_EMULATOR_DETECTION_LAB_BYPASS_TEMPLATE__": "EMULATOR_DETECTION_LAB_BYPASS",
        "__MSAP_ROOT_DETECTION_NATIVE_HOOK_TEMPLATE__": "ROOT_DETECTION_SCREEN_VALIDATION",
        "__MSAP_TLS_PINNING_OKHTTP_BYPASS_TEMPLATE__": "TLS_PINNING_FRIDA_BYPASS",
    }
    results: list[dict[str, Any]] = []
    for tool_name, playbook_id in mapping.items():
        if tool_name not in step_tools:
            continue
        if playbook_id == "DEBUGGABLE_APP_VERIFICATION" and tool_name == "frida_run_js":
            source = next((tool.get("arguments", {}).get("source") for step_row in plan.normalized_plan.get("steps", []) for tool in step_row.get("tools", []) if isinstance(tool, dict) and tool.get("name") == tool_name), None)
            playbook_id = lab_sources.get(source, playbook_id)
        rule_id = {"DEBUGGABLE_APP_VERIFICATION": "MSAP-AND-001", "EXPORTED_ACTIVITY_LAUNCH_VERIFICATION": "MSAP-AND-004", "EXPORTED_RECEIVER_BROADCAST_VERIFICATION": "MSAP-AND-006", "EXPORTED_PROVIDER_ACCESS_VERIFICATION": "MSAP-AND-007"}.get(playbook_id, "DYNAMIC-PLAYBOOK")
        if playbook_id == "ROOT_DETECTION_SCREEN_VALIDATION":
            source_finding = plan.source_finding
        finding = source_finding or (Finding.objects.filter(audit_id=run.audit_id, rule_id=rule_id).first() if rule_id != "DYNAMIC-PLAYBOOK" else None)
        if finding is None and playbook_id not in lab_sources.values():
            continue
        step = run.steps.filter(tool_name=tool_name).order_by("-sequence_number").first()
        evidence = {}
        for candidate in run.steps.order_by("sequence_number"):
            if candidate.status != AgentRunStep.Status.SUCCEEDED:
                continue
            if isinstance(candidate.output_summary, dict):
                evidence.update(candidate.output_summary)
            if isinstance(candidate.observation, dict):
                evidence.update(candidate.observation)
            if candidate.tool_name == "dump_ui" and isinstance(candidate.output_summary, dict):
                values = candidate.output_summary.get("text_values", [])
                if candidate.plan_step_identifier == "capture_rooted_before":
                    evidence["root_before_text_values"] = values
                elif candidate.plan_step_identifier == "capture_not_rooted_after":
                    evidence["root_after_text_values"] = values
            if candidate.tool_name in {"stop_proxy_capture", "get_proxy_flows"} and isinstance(candidate.output_summary, dict):
                phase = candidate.output_summary.get("phase")
                if phase == "pinning_baseline":
                    evidence["tls_baseline_flow_count"] = candidate.output_summary.get("flow_count", 0)
                    evidence["tls_baseline_successful_flow_count"] = candidate.output_summary.get("successful_tls_flow_count", 0)
                elif phase == "pinning_bypass":
                    evidence["tls_bypass_flow_count"] = candidate.output_summary.get("flow_count", 0)
                    evidence["tls_bypass_successful_flow_count"] = candidate.output_summary.get("successful_tls_flow_count", 0)
                    evidence["target_network_flow_exercised"] = True
        screenshots = [
            step.output_summary
            for step in run.steps.filter(tool_name="take_screenshot", status=AgentRunStep.Status.SUCCEEDED).order_by("sequence_number")
            if isinstance(step.output_summary, dict) and step.output_summary.get("sha256")
        ]
        if len(screenshots) >= 2:
            evidence["before_screenshot_sha256"] = screenshots[0]["sha256"]
            evidence["after_screenshot_sha256"] = screenshots[-1]["sha256"]
        if (
            step
            and step.status == AgentRunStep.Status.SUCCEEDED
            and isinstance(step.output_summary, dict)
        ):
            step_output = dict(step.output_summary)
            for key in ("before_screenshot_sha256", "after_screenshot_sha256"):
                if not step_output.get(key):
                    step_output.pop(key, None)
            evidence.update(step_output)
        existing = DynamicValidationResult.objects.filter(agent_run=run, finding=finding, playbook_id=playbook_id).first()
        if existing:
            result = existing
        else:
            result = record_dynamic_validation(finding=finding, audit=run.audit, playbook_id=playbook_id, evidence=evidence, agent_run=run, evidence_records=list(run.evidence_records.all()[:100]), confidence=0.9 if evidence else 0.0, rule_id=finding.rule_id if finding is not None else rule_id, scenario_id=str(plan.id if plan else ""))
        results.append({"id": result.id, "finding_id": result.finding_id, "rule_id": result.rule_id, "playbook_id": result.playbook_id, "validation_status": result.validation_status, "oracle_result": result.oracle_result, "limitations": result.limitations})
    return results


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
    dynamic_validations = list(
        DynamicValidationResult.objects.filter(agent_run=run)
        .values("id", "finding_id", "rule_id", "playbook_id", "validation_status", "oracle_result", "limitations")
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
        "dynamic_validations": dynamic_validations,
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

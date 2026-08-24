"""Audit-level Static -> Dynamic correlation for the simplified demo UX.

This module classifies every static finding of one audit into a small set of
auditor-facing buckets and produces concise PoC scenario cards.  It is
deterministic and does not spend AI calls: playbook catalog intelligence
drives the classification, and mission generation (the only AI touchpoint)
happens later through the existing FindingValidationMission flow with the
hard OpenAI budget still enforced.
"""
from __future__ import annotations

from typing import Any

from django.conf import settings
from django.utils import timezone

from apps.apk_files.models import APKFile
from apps.dynamic_analysis.models import FindingValidationMission
from apps.dynamic_analysis.services.finding_validation_missions import (
    FindingValidationMissionError,
    generate_finding_validation_mission,
)
from apps.dynamic_analysis.services.playbook_catalog import (
    executable_playbooks_for_finding,
    playbooks_for_finding,
)
from apps.findings.models import Finding

TERMINAL_RESULT_STATUSES = {
    FindingValidationMission.Status.CONFIRMED,
    FindingValidationMission.Status.NOT_REPRODUCED,
    FindingValidationMission.Status.INCONCLUSIVE,
    FindingValidationMission.Status.BLOCKED,
    FindingValidationMission.Status.FAILED,
}

RETRYABLE_STATUSES = {
    FindingValidationMission.Status.NOT_REPRODUCED,
    FindingValidationMission.Status.INCONCLUSIVE,
    FindingValidationMission.Status.BLOCKED,
    FindingValidationMission.Status.FAILED,
}

EVIDENCE_TITLE_MAP = {
    "screenshot": "Screenshot",
    "ui_hierarchy": "UI hierarchy",
    "logcat": "Bounded log excerpt",
    "frida_events": "Approved Frida event",
    "tool_output": "Tool output",
    "provider_response": "Provider response",
    "broadcast_result": "Broadcast result",
    "activity_launch": "Activity launch result",
    "dynamic_screenshot": "Screenshot",
    "dynamic_ui_hierarchy": "UI hierarchy",
    "dynamic_logcat_capture": "Runtime log capture",
    "dynamic_logcat_excerpt": "Runtime log excerpt",
    "dynamic_frida_status": "Frida status",
    "dynamic_frida_processes": "Frida process list",
    "dynamic_frida_attach": "Frida attach result",
    "dynamic_frida_events": "Frida events",
    "dynamic_tool_observation": "Tool observation",
    "assessment_plan_control_observation": "Plan control observation",
}

EVIDENCE_PREVIEW_TYPE_MAP = {
    "screenshot": "screenshot",
    "ui_hierarchy": "ui",
    "logcat": "logs",
    "frida_events": "runtime",
    "tool_output": "tool_output",
    "provider_response": "provider_response",
    "broadcast_result": "broadcast_result",
    "activity_launch": "activity_launch",
    "dynamic_screenshot": "screenshot",
    "dynamic_ui_hierarchy": "ui",
    "dynamic_logcat_capture": "logs",
    "dynamic_logcat_excerpt": "logs",
    "dynamic_frida_status": "runtime",
    "dynamic_frida_processes": "runtime",
    "dynamic_frida_attach": "runtime",
    "dynamic_frida_events": "runtime",
    "dynamic_tool_observation": "tool_output",
    "assessment_plan_control_observation": "tool_output",
}

TOOL_LABEL_MAP = {
    "get_device_status": "Check device readiness",
    "list_packages": "Confirm authorized applications",
    "launch_package": "Launch target app",
    "force_stop_package": "Close target application",
    "take_screenshot": "Capture screenshot",
    "start_logcat": "Start bounded log observation",
    "stop_logcat": "Stop bounded log observation",
    "get_logcat_excerpt": "Inspect runtime logs",
    "dump_ui": "Inspect application interface",
    "tap_coordinates": "Run approved UI interaction",
    "type_text": "Enter approved test input",
    "frida_status": "Check runtime instrumentation",
    "frida_ps": "Inspect target process state",
    "frida_attach": "Attach approved instrumentation",
    "frida_run_js": "Run controlled instrumentation proof",
    "reset_root_detection_demo": "Reset approved demo state",
    "launch_exported_activity": "Launch exported activity",
    "send_explicit_broadcast": "Send approved broadcast",
    "query_exported_provider": "Query exported provider",
}

OBSERVATION_SUMMARY_MAP = {
    "launch_package": "The target app was launched and is foregrounded.",
    "tap_coordinates": "Approved UI interaction executed.",
    "take_screenshot": "Screenshot captured.",
    "dump_ui": "UI hierarchy captured.",
    "frida_run_js": "Approved Frida runtime proof executed.",
    "get_logcat_excerpt": "Bounded logcat excerpt captured.",
    "start_logcat": "Bounded log observation window started.",
    "stop_logcat": "Bounded log observation window closed.",
    "frida_status": "Approved runtime instrumentation state recorded.",
    "get_device_status": "Device readiness recorded.",
}

RESULT_LABEL_MAP = {
    FindingValidationMission.Status.CONFIRMED: "Confirmed",
    FindingValidationMission.Status.NOT_REPRODUCED: "Not reproduced",
    FindingValidationMission.Status.INCONCLUSIVE: "Inconclusive",
    FindingValidationMission.Status.BLOCKED: "Blocked",
    FindingValidationMission.Status.NOT_DYNAMICALLY_TESTABLE: "Not dynamically testable",
    FindingValidationMission.Status.FAILED: "Failed",
    FindingValidationMission.Status.RUNNING: "Running",
    FindingValidationMission.Status.APPROVED: "Approved",
    FindingValidationMission.Status.VALIDATED: "Ready for approval",
    FindingValidationMission.Status.DRAFT: "Draft",
    FindingValidationMission.Status.GENERATED: "Generated",
}

RESULT_EXPLANATION_MAP = {
    FindingValidationMission.Status.CONFIRMED: (
        "The PoC executed and the deterministic oracle observed the signals "
        "required to confirm the static finding."
    ),
    FindingValidationMission.Status.NOT_REPRODUCED: (
        "The PoC executed, but the deterministic oracle did not observe the "
        "runtime behavior described by the static finding."
    ),
    FindingValidationMission.Status.INCONCLUSIVE: (
        "The PoC executed and collected evidence, but the deterministic oracle "
        "did not observe every signal required to confirm the finding."
    ),
    FindingValidationMission.Status.BLOCKED: (
        "The PoC could not complete because the lab, tool, or runtime "
        "prevented it."
    ),
    FindingValidationMission.Status.NOT_DYNAMICALLY_TESTABLE: (
        "Current MSAP tools cannot validate this finding dynamically."
    ),
    FindingValidationMission.Status.FAILED: (
        "The PoC execution failed before a conclusion could be produced."
    ),
    FindingValidationMission.Status.RUNNING: (
        "The PoC is executing. Evidence appears as each step completes."
    ),
    FindingValidationMission.Status.APPROVED: (
        "The PoC is approved and ready to run."
    ),
    FindingValidationMission.Status.VALIDATED: (
        "The PoC was generated and backend-validated. Auditor approval is the "
        "next step."
    ),
}


def friendly_action_label(tool_name: str) -> str:
    return TOOL_LABEL_MAP.get(str(tool_name), str(tool_name) or "Tool observation")


def observation_summary_for_tool(tool_name: str, observation: Any = None) -> str:
    label = OBSERVATION_SUMMARY_MAP.get(str(tool_name))
    if label:
        return label
    if isinstance(observation, dict):
        if observation.get("launched") is True:
            return "The target app was launched and is foregrounded."
        if observation.get("screenshot_created") is True:
            return "Screenshot captured."
        if observation.get("event_count") is not None:
            return f"{int(observation['event_count'])} approved runtime events recorded."
        if observation.get("line_count") is not None:
            return f"{int(observation['line_count'])} bounded log lines captured."
        if observation.get("node_count") is not None:
            return f"{int(observation['node_count'])} UI nodes captured."
    return "Tool observation captured."


def evidence_title(evidence_type: str) -> str:
    value = str(evidence_type or "").strip()
    if not value:
        return "Evidence"
    return EVIDENCE_TITLE_MAP.get(value, value)


def evidence_preview_type(evidence_type: str) -> str:
    return EVIDENCE_PREVIEW_TYPE_MAP.get(str(evidence_type), "tool_output")


def result_label(status: str) -> str:
    return RESULT_LABEL_MAP.get(str(status), str(status).replace("_", " ").title())


def result_explanation(status: str) -> str:
    return RESULT_EXPLANATION_MAP.get(
        str(status),
        "The validation mission is still in progress.",
    )


def scenario_summary_for_mission(mission: FindingValidationMission) -> str:
    """Short human sentence describing the generated PoC for one mission."""
    contract = mission.scenario_contract
    if not isinstance(contract, dict):
        return "No PoC scenario was generated."
    steps = contract.get("steps", [])
    if not steps:
        return "No runtime action will be executed."
    if mission.status == FindingValidationMission.Status.NOT_DYNAMICALLY_TESTABLE:
        return (
            str(contract.get("not_assessable_reason") or mission.limitations)
            or "No runtime action will be executed."
        )
    tool_names = [
        item.get("name") if isinstance(item, dict) else item
        for step in steps
        for item in (step.get("tools", []) if isinstance(step, dict) else [])
    ]
    labels = list(dict.fromkeys(friendly_action_label(tool) for tool in tool_names))
    if labels:
        return f"{len(steps)}-step PoC using {', '.join(labels[:4])}."
    return f"{len(steps)}-step PoC with approved Tool Gateway capabilities."


def _best_mission_for_finding(
    missions: list[FindingValidationMission],
    finding_id: int,
    playbook_id: str = "",
) -> FindingValidationMission | None:
    relevant = [mission for mission in missions if mission.finding_id == finding_id]
    if playbook_id:
        matched = [mission for mission in relevant if mission.playbook_id == playbook_id]
        if matched:
            relevant = matched
    if not relevant:
        return None

    terminal_confirmed = [
        mission
        for mission in relevant
        if mission.status
        in {
            FindingValidationMission.Status.CONFIRMED,
            FindingValidationMission.Status.NOT_REPRODUCED,
        }
    ]
    if terminal_confirmed:
        return terminal_confirmed[0]
    return relevant[0]


def _expected_evidence_labels(playbook: dict[str, Any]) -> list[str]:
    return [
        evidence_title(item)
        for item in playbook.get("required_evidence_inputs", [])
    ]


def _scenario_summary_from_playbook(playbook: dict[str, Any]) -> str:
    tools = playbook.get("supported_tools", [])
    parts = []
    if "reset_root_detection_demo" in tools:
        parts.append("reset the approved demo state")
    if "launch_package" in tools:
        parts.append("launch the target app")
    if "tap_coordinates" in tools or "launch_exported_activity" in tools:
        parts.append("execute the approved interaction")
    if "frida_run_js" in tools:
        parts.append("run the backend-owned Frida proof")
    if "take_screenshot" in tools:
        parts.append("capture before/after screenshots")
    if "dump_ui" in tools:
        parts.append("capture the UI hierarchy")
    if "get_logcat_excerpt" in tools:
        parts.append("capture a bounded log excerpt")
    if not parts:
        parts.append("collect bounded runtime evidence with approved tools")
    return "PoC: " + ", ".join(parts) + "."


def _classify(
    *,
    playbook: dict[str, Any] | None,
    mission: FindingValidationMission | None,
) -> str:
    if mission is not None and mission.status in {
        FindingValidationMission.Status.CONFIRMED,
        FindingValidationMission.Status.NOT_REPRODUCED,
    }:
        return "ALREADY_VALIDATED"
    if mission is not None and (
        mission.status == FindingValidationMission.Status.NOT_DYNAMICALLY_TESTABLE
    ):
        return "NOT_TESTABLE"
    if playbook is not None:
        status = playbook.get("current_capability_status", "")
        if status == "AVAILABLE" and playbook.get("supported_tools"):
            return "TESTABLE"
        if status == "PARTIAL" or playbook.get("requires_additional_approval"):
            return "NEEDS_CAPABILITY"
        return "NOT_TESTABLE"
    return "NOT_TESTABLE"


def _blocking_reason(
    *,
    playbook: dict[str, Any] | None,
    mission: FindingValidationMission | None,
    classification: str,
) -> str:
    if mission is not None:
        if mission.status == FindingValidationMission.Status.NOT_DYNAMICALLY_TESTABLE:
            return mission.limitations or (
                "Current MSAP tools cannot validate this finding dynamically."
            )
        if mission.status == FindingValidationMission.Status.BLOCKED:
            return mission.limitations or (
                "The previous PoC could not complete. Check lab readiness and retry."
            )
    if classification == "NEEDS_CAPABILITY":
        return (
            playbook.get("limitations")
            if playbook is not None
            else "This validation family requires a lab capability that is not "
            "available in the current approved Tool Gateway envelope."
        )
    return (
        playbook.get("limitations")
        if playbook is not None
        else "No supported runtime validation family maps to this static finding."
    )


def _candidate_reason(finding: Finding, playbook: dict[str, Any] | None) -> str:
    if playbook is None:
        return "Static-only evidence unless runtime exposure is observed."
    return (
        f"Static analysis indicates {finding.title.lower() or 'this behavior'}. "
        f"{playbook.get('description', 'A bounded runtime proof can confirm or '
        'refute the static signal with approved tools.')}"
    )


def _estimate_ai_calls() -> int:
    provider = getattr(settings, "MSAP_ASSESSMENT_PLANNER_PROVIDER", "DETERMINISTIC")
    return 1 if str(provider).upper() == "OPENAI" else 0


def _build_candidate(
    finding: Finding,
    playbook: dict[str, Any] | None,
    mission: FindingValidationMission | None,
) -> dict[str, Any]:
    classification = _classify(playbook=playbook, mission=mission)
    status = mission.status if mission else ""
    retryable = bool(
        mission and status in RETRYABLE_STATUSES and classification == "TESTABLE"
    )
    start_poc_available = classification == "TESTABLE" and (
        mission is None
        or status
        in {
            FindingValidationMission.Status.DRAFT,
            FindingValidationMission.Status.GENERATED,
            FindingValidationMission.Status.VALIDATED,
            FindingValidationMission.Status.APPROVED,
            FindingValidationMission.Status.RUNNING,
        }
        or retryable
    )
    blocking_reason = (
        _blocking_reason(
            playbook=playbook,
            mission=mission,
            classification=classification,
        )
        if classification in {"NOT_TESTABLE", "NEEDS_CAPABILITY"}
        or (mission and status == FindingValidationMission.Status.BLOCKED)
        else ""
    )
    next_step = {
        FindingValidationMission.Status.DRAFT: "review",
        FindingValidationMission.Status.GENERATED: "review",
        FindingValidationMission.Status.VALIDATED: "approve",
        FindingValidationMission.Status.APPROVED: "run",
        FindingValidationMission.Status.RUNNING: "monitor",
    }.get(status, "retry" if retryable else "generate" if classification == "TESTABLE" else "none")

    return {
        "finding_id": finding.pk,
        "finding_title": finding.title,
        "severity": finding.severity,
        "rule_id": finding.rule_id,
        "category": finding.category or "Static rule",
        "dynamic_testability": classification,
        "reason": _candidate_reason(finding, playbook),
        "recommended_poc_title": (
            playbook.get("title", "") if playbook is not None else ""
        ),
        "scenario_summary": (
            _scenario_summary_from_playbook(playbook)
            if playbook is not None
            else "Static-only evidence unless runtime exposure is observed."
        ),
        "expected_evidence": (
            _expected_evidence_labels(playbook)
            if playbook is not None
            else []
        ),
        "required_capabilities": [
            friendly_action_label(tool)
            for tool in (
                playbook.get("required_capabilities", [])
                if playbook is not None
                else []
            )
        ],
        "estimated_steps": (
            len(playbook.get("supported_tools", []))
            if playbook is not None
            else 0
        ),
        "estimated_ai_calls": (
            _estimate_ai_calls() if classification == "TESTABLE" else 0
        ),
        "existing_mission_id": mission.pk if mission else None,
        "current_validation_status": status,
        "start_poc_available": start_poc_available,
        "blocking_reason": blocking_reason,
        "next_step": next_step,
    }


def correlate_audit_findings(audit_id: int) -> dict[str, Any]:
    findings = list(
        Finding.objects.filter(audit_id=audit_id).order_by(
            "-severity", "-created_at"
        )[:200]
    )
    missions = list(
        FindingValidationMission.objects.filter(audit_id=audit_id)
        .select_related("finding")
        .order_by("-created_at")
    )
    candidates = []
    counts = {
        "total": len(findings),
        "dynamically_testable": 0,
        "not_testable": 0,
        "already_validated": 0,
        "needs_capability": 0,
    }
    target_package = ""
    apk = (
        APKFile.objects.filter(audit_id=audit_id)
        .order_by("-created_at")
        .first()
    )
    if apk is not None and apk.package_name:
        target_package = apk.package_name

    for finding in findings:
        playbook = None
        executable = executable_playbooks_for_finding(finding)
        if executable:
            playbook = executable[0]
        else:
            mapped = playbooks_for_finding(finding)
            playbook = mapped[0] if mapped else None
        mission = _best_mission_for_finding(
            missions,
            finding.pk,
            playbook.get("playbook_id", "") if playbook is not None else "",
        )
        candidate = _build_candidate(finding, playbook, mission)
        testability = candidate["dynamic_testability"]
        if testability == "ALREADY_VALIDATED":
            counts["already_validated"] += 1
        elif testability == "TESTABLE":
            counts["dynamically_testable"] += 1
        elif testability == "NEEDS_CAPABILITY":
            counts["needs_capability"] += 1
            counts["not_testable"] += 1
        else:
            counts["not_testable"] += 1
        candidates.append(candidate)

    candidates.sort(
        key=lambda item: (
            item["dynamic_testability"] != "TESTABLE",
            item["start_poc_available"] is False,
            item["severity"],
        )
    )
    return {
        "audit_id": audit_id,
        "target_package": target_package,
        "total_static_findings": counts["total"],
        "dynamically_testable_count": counts["dynamically_testable"],
        "not_testable_count": counts["not_testable"],
        "already_validated_count": counts["already_validated"],
        "needs_capability_count": counts["needs_capability"],
        "correlation_mode": "DETERMINISTIC_PLAYBOOK",
        "generated_at": timezone.now().isoformat(),
        "candidates": candidates,
    }


def start_candidate_poc(
    *,
    audit_id: int,
    finding_id: int,
    requested_by,
) -> dict[str, Any]:
    """Start the PoC journey for one correlation candidate.

    Reuses an existing mission when possible and only generates a new one
    through the existing budget-guarded FindingValidationMission flow.
    """
    finding = Finding.objects.filter(pk=finding_id, audit_id=audit_id).first()
    if finding is None:
        raise FindingValidationMissionError(
            "The correlation candidate does not belong to this audit.",
            code="CORRELATION_CANDIDATE_NOT_FOUND",
            http_status=404,
        )
    mapped = executable_playbooks_for_finding(finding)
    playbook = mapped[0] if mapped else (playbooks_for_finding(finding)[0] if playbooks_for_finding(finding) else None)
    mission = _best_mission_for_finding(
        list(
            FindingValidationMission.objects.filter(finding=finding).order_by("-created_at")
        ),
        finding.id,
        playbook.get("playbook_id", "") if playbook is not None else "",
    )
    if mission is None:
        mission = generate_finding_validation_mission(
            finding=finding,
            requested_by=requested_by,
        )
        next_step = (
            "not-testable"
            if mission.status == FindingValidationMission.Status.NOT_DYNAMICALLY_TESTABLE
            else "review"
        )
    elif mission.status == FindingValidationMission.Status.VALIDATED:
        next_step = "approve"
    elif mission.status == FindingValidationMission.Status.APPROVED:
        next_step = "run"
    elif mission.status == FindingValidationMission.Status.RUNNING:
        next_step = "monitor"
    elif mission.status in {
        FindingValidationMission.Status.CONFIRMED,
        FindingValidationMission.Status.NOT_REPRODUCED,
    }:
        next_step = "result"
    elif mission.status == FindingValidationMission.Status.NOT_DYNAMICALLY_TESTABLE:
        next_step = "not-testable"
    elif mission.status in RETRYABLE_STATUSES:
        mission = generate_finding_validation_mission(
            finding=finding,
            requested_by=requested_by,
        )
        next_step = (
            "not-testable"
            if mission.status == FindingValidationMission.Status.NOT_DYNAMICALLY_TESTABLE
            else "review"
        )
    else:
        next_step = "review"
    return {
        "mission": mission,
        "next_step": next_step,
    }

from __future__ import annotations

from typing import Any

from apps.dynamic_analysis.models import AgentRunStep, DynamicValidationResult
from apps.dynamic_analysis.services.playbook_catalog import validate_playbook_selection
from apps.dynamic_analysis.services.playbook_oracles import ORACLES

RESULT_CONTRACT_VERSION = "msap.dynamic-validation-result/v1"

CONFIRMED_WITH_WARNING = "CONFIRMED_WITH_WARNING"

REQUIRED_TOOLS_BY_PLAYBOOK = {
    "EXPORTED_ACTIVITY_LAUNCH_VERIFICATION": ("launch_exported_activity",),
    "EXPORTED_RECEIVER_BROADCAST_VERIFICATION": ("send_explicit_broadcast",),
    "EXPORTED_PROVIDER_ACCESS_VERIFICATION": ("query_exported_provider",),
    "DEBUGGABLE_APP_VERIFICATION": ("frida_status", "frida_attach"),
    "ROOT_SIGNAL_OBSERVATION": ("frida_status", "frida_attach", "frida_run_js"),
    "ROOT_DETECTION_LAB_BYPASS": ("frida_run_js", "take_screenshot"),
    "EMULATOR_DETECTION_LAB_BYPASS": ("frida_run_js", "take_screenshot"),
    "ROOT_DETECTION_SCREEN_VALIDATION": ("prepare_root_detection_demo", "frida_run_js", "dump_ui", "take_screenshot"),
    "TLS_PINNING_FRIDA_BYPASS": ("start_proxy_capture", "stop_proxy_capture", "frida_run_js", "take_screenshot"),
    "TLS_USER_CA_DYNAMIC_VALIDATION": ("get_logcat_excerpt",),
}

OPTIONAL_TOOLS_BY_PLAYBOOK = {
    "EXPORTED_ACTIVITY_LAUNCH_VERIFICATION": (
        "get_logcat_excerpt",
        "dump_ui",
        "take_screenshot",
    ),
    "EXPORTED_RECEIVER_BROADCAST_VERIFICATION": (
        "get_logcat_excerpt",
        "dump_ui",
        "take_screenshot",
    ),
    "EXPORTED_PROVIDER_ACCESS_VERIFICATION": (
        "get_logcat_excerpt",
        "dump_ui",
        "take_screenshot",
    ),
    "DEBUGGABLE_APP_VERIFICATION": (
        "get_logcat_excerpt",
        "dump_ui",
        "take_screenshot",
    ),
}

TOOL_LABELS = {
    "get_logcat_excerpt": "log excerpt collection",
    "dump_ui": "UI hierarchy capture",
    "take_screenshot": "screenshot capture",
    "send_explicit_broadcast": "explicit broadcast delivery",
    "launch_exported_activity": "exported activity launch",
    "query_exported_provider": "provider query",
    "frida_attach": "Frida attach",
    "frida_run_js": "Frida instrumentation",
}


def apply_evidence_gate(
    playbook_id: str,
    agent_run,
    oracle_result: dict[str, Any],
) -> dict[str, Any]:
    """Apply the required-vs-optional evidence gate for one agent run.

    Required tool evidence comes only from succeeded approved-plan steps. When
    no required tool produced evidence, a CONFIRMED verdict is downgraded to
    INCONCLUSIVE so a run with failed core steps can never confirm a finding.
    Failures of optional (supplementary) tools do not invalidate a conclusion;
    they surface as a deterministic ``CONFIRMED_WITH_WARNING`` verdict with a
    human-readable warning list.
    """
    result = dict(oracle_result)
    if result.get("status") not in {"CONFIRMED", "INCONCLUSIVE", "REFUTED"}:
        return result
    succeeded = {
        step.tool_name
        for step in (agent_run.steps.all() if agent_run is not None else [])
        if step.status == AgentRunStep.Status.SUCCEEDED
    }
    required = REQUIRED_TOOLS_BY_PLAYBOOK.get(playbook_id, ())
    if required and not set(required) <= succeeded:
        failed_tools = sorted(set(required) - succeeded)
        result["status"] = "INCONCLUSIVE"
        result["evidence_gate"] = {"required_evidence_failed": failed_tools}
        result["summary"] = (
            "Required evidence did not complete"
            + (f": {', '.join(failed_tools)}" if failed_tools else "")
            + ". The conclusion cannot be confirmed."
        )
        return result
    warnings = []
    planned_tools = {step.tool_name for step in agent_run.steps.all()} if agent_run is not None else set()
    for tool in OPTIONAL_TOOLS_BY_PLAYBOOK.get(playbook_id, ()):
        if tool not in succeeded and tool in planned_tools:
            label = TOOL_LABELS.get(tool, tool)
            warnings.append(f"{label} failed ({tool})")
    if warnings and result.get("status") == "CONFIRMED":
        result["verdict"] = CONFIRMED_WITH_WARNING
        result["warnings"] = warnings
        result["summary"] = (
            f"{result['summary']} Confirmed with warning: {'; '.join(warnings)}."
        )
    return result


def build_validation_result(
    *, source_finding_id: int, scenario_id: str, agent_run_id: int | None,
    oracle_result: dict[str, Any], evidence_ids: list[int],
    artifact_ids: list[int] | None = None, confidence: float = 0.0,
    summary: str = "", limitations: str = "",
) -> dict[str, Any]:
    """Create the backend-owned result envelope; model text cannot set result."""
    result = {
        "CONFIRMED": "SUPPORTED",
        CONFIRMED_WITH_WARNING: "SUPPORTED",
        "REFUTED": "REJECTED",
        "INCONCLUSIVE": "INCONCLUSIVE",
        "NOT_ASSESSABLE": "NOT_ASSESSABLE",
    }.get(str(oracle_result.get("status") or ""), "INCONCLUSIVE")
    if result == "SUPPORTED" and not evidence_ids:
        result = "INCONCLUSIVE"
    return {
        "contract_version": RESULT_CONTRACT_VERSION,
        "source_finding_id": source_finding_id,
        "scenario_id": scenario_id,
        "agent_run_id": agent_run_id,
        "result": result,
        "evidence_ids": list(evidence_ids),
        "artifact_ids": list(artifact_ids or []),
        "oracle_results": [oracle_result],
        "confidence": max(0.0, min(1.0, confidence)),
        "summary": summary[:1000],
        "limitations": limitations[:4000],
        "recommended_next_manual_step": "Collect additional target-correlated evidence." if result == "INCONCLUSIVE" else "",
    }


def evaluate_playbook(playbook_id: str, evidence: dict[str, Any]) -> dict[str, Any]:
    playbook = validate_playbook_selection(playbook_id)
    oracle = ORACLES[playbook["oracle_id"]]
    return oracle(evidence)


def record_dynamic_validation(*, finding=None, playbook_id: str, evidence: dict[str, Any], audit=None, agent_run=None, hypothesis=None, action_decision=None, evidence_records=None, confidence: float = 0.0, rule_id: str | None = None, scenario_id: str = "") -> DynamicValidationResult:
    playbook = validate_playbook_selection(playbook_id)
    oracle_result = evaluate_playbook(playbook_id, evidence)
    if agent_run is not None:
        oracle_result = apply_evidence_gate(playbook_id, agent_run, oracle_result)
    evidence_records = list(evidence_records or [])
    result_envelope = build_validation_result(
        source_finding_id=finding.pk if finding is not None else 0,
        scenario_id=scenario_id,
        agent_run_id=agent_run.pk if agent_run is not None else None,
        oracle_result=oracle_result,
        evidence_ids=[item.pk for item in evidence_records],
        confidence=confidence,
        summary=oracle_result["summary"],
        limitations=playbook["limitations"],
    )
    result = DynamicValidationResult.objects.create(
        audit=audit or finding.audit,
        finding=finding,
        rule_id=rule_id or (finding.rule_id if finding is not None else "DYNAMIC-PLAYBOOK"),
        playbook_id=playbook_id,
        agent_run=agent_run,
        hypothesis=hypothesis,
        action_decision=action_decision,
        oracle_id=playbook["oracle_id"],
        oracle_result={**oracle_result, "result_contract": result_envelope},
        validation_status=result_envelope["result"],
        confidence=max(0.0, min(1.0, confidence)),
        safe_summary=oracle_result["summary"][:1000],
        limitations=playbook["limitations"],
    )
    if evidence_records:
        result.evidence.set(evidence_records)
    return result

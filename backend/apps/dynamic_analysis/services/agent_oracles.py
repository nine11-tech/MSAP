from __future__ import annotations

import re
from typing import Any

from apps.dynamic_analysis.models import AgentHypothesis, AgentRun, AgentRunStep
from apps.evidence.models import Evidence


ORACLE_RESULT_STATUSES = {
    "SUPPORTED",
    "REJECTED",
    "INCONCLUSIVE",
    "NOT_APPLICABLE",
}
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"\b(password|passwd|bearer|authorization|token|secret|api[_ -]?key)\b\s*[:=]",
    re.IGNORECASE,
)
REDACTED_ASSIGNMENT_RE = re.compile(
    r"\b(password|passwd|bearer|authorization|token|secret|api[_ -]?key)\b[^\n]{0,40}\[redacted\]",
    re.IGNORECASE,
)
CRASH_RE = re.compile(r"\b(FATAL EXCEPTION|ANR in|Process .* has died)\b", re.IGNORECASE)


HYPOTHESIS_CATALOG = {
    AgentHypothesis.Family.SENSITIVE_LOG_EXPOSURE: {
        "hypothesis_id": "sensitive_log_exposure",
        "title": "Sensitive application data may be exposed through runtime logs",
        "description": (
            "Determine whether target-correlated bounded log evidence contains a "
            "high-confidence sensitive assignment pattern."
        ),
        "evidence_requirements": ["logcat"],
    },
    AgentHypothesis.Family.UI_SENSITIVE_DATA_EXPOSURE: {
        "hypothesis_id": "ui_sensitive_data_exposure",
        "title": "Sensitive values may be exposed in the parsed UI hierarchy",
        "description": (
            "Determine whether bounded target UI text contains an explicit "
            "security-sensitive assignment."
        ),
        "evidence_requirements": ["ui_hierarchy"],
    },
    AgentHypothesis.Family.RUNTIME_TAMPERING_RESILIENCE: {
        "hypothesis_id": "runtime_tampering_resilience",
        "title": "Controlled instrumentation may modify observable target behavior",
        "description": (
            "Determine whether the existing controlled proof emits a target event "
            "and correlated before/after evidence."
        ),
        "evidence_requirements": ["frida_events", "before_after_comparison"],
    },
    AgentHypothesis.Family.APPLICATION_RUNTIME_STABILITY: {
        "hypothesis_id": "application_runtime_stability",
        "title": "A bounded workflow may trigger target crash or error behavior",
        "description": (
            "Determine whether target-correlated log evidence contains a deterministic "
            "fatal exception or ANR marker."
        ),
        "evidence_requirements": ["logcat"],
    },
}


def initialize_hypotheses(run: AgentRun) -> list[AgentHypothesis]:
    families = run.capability_envelope.get("allowed_hypothesis_families", [])
    rows = []
    for family in families:
        definition = HYPOTHESIS_CATALOG.get(family)
        if definition is None:
            continue
        rows.append(
            AgentHypothesis(
                run=run,
                hypothesis_id=definition["hypothesis_id"],
                family=family,
                title=definition["title"],
                description=definition["description"],
                evidence_requirements=definition["evidence_requirements"],
            )
        )
    return AgentHypothesis.objects.bulk_create(rows)


def initial_coverage_state(run: AgentRun) -> dict[str, str]:
    allowed = set(run.capability_envelope.get("allowed_capabilities", []))
    return {
        "device_runtime_readiness": "NOT_STARTED",
        "application_interaction": "NOT_STARTED",
        "ui_exposure": "NOT_STARTED" if "dump_ui" in allowed else "NOT_ASSESSABLE_WITH_CURRENT_CAPABILITIES",
        "logging": "NOT_STARTED" if "get_logcat_excerpt" in allowed else "NOT_ASSESSABLE_WITH_CURRENT_CAPABILITIES",
        "runtime_instrumentation": "NOT_STARTED" if "frida_status" in allowed else "NOT_ASSESSABLE_WITH_CURRENT_CAPABILITIES",
        "runtime_stability": "NOT_STARTED" if "get_logcat_excerpt" in allowed else "NOT_ASSESSABLE_WITH_CURRENT_CAPABILITIES",
        "network_tls": "NOT_ASSESSABLE_WITH_CURRENT_CAPABILITIES",
        "local_storage": "NOT_ASSESSABLE_WITH_CURRENT_CAPABILITIES",
        "authentication_authorization": "NOT_ASSESSABLE_WITH_CURRENT_CAPABILITIES",
    }


def evaluate_run_oracles(run: AgentRun) -> list[dict[str, Any]]:
    results = []
    for hypothesis in run.hypotheses.all():
        result = _evaluate_hypothesis(hypothesis)
        if result is None:
            continue
        hypothesis.oracle_result = result
        hypothesis.status = _hypothesis_status(result["status"])
        hypothesis.confidence = float(result["confidence"])
        hypothesis.save(
            update_fields=["oracle_result", "status", "confidence", "updated_at"]
        )
        results.append(result)
    update_coverage(run)
    return results


def update_coverage(run: AgentRun) -> dict[str, str]:
    coverage = dict(run.coverage_state or initial_coverage_state(run))
    successful = {
        name: list(
            run.steps.filter(tool_name=name, status=AgentRunStep.Status.SUCCEEDED)
            .order_by("sequence_number")
        )
        for name in {
            "get_device_status",
            "launch_package",
            "dump_ui",
            "get_logcat_excerpt",
            "frida_status",
            "frida_run_js",
        }
    }
    if successful["get_device_status"]:
        data = successful["get_device_status"][-1].output_summary
        coverage["device_runtime_readiness"] = (
            "ASSESSED" if data.get("ready") else "INCONCLUSIVE"
        )
    if successful["launch_package"]:
        data = successful["launch_package"][-1].output_summary
        coverage["application_interaction"] = (
            "ASSESSED" if data.get("launched") else "INCONCLUSIVE"
        )
    if successful["dump_ui"]:
        data = successful["dump_ui"][-1].output_summary
        coverage["ui_exposure"] = (
            "ASSESSED" if data.get("node_count", 0) > 0 else "INCONCLUSIVE"
        )
        coverage["application_interaction"] = (
            "ASSESSED"
            if data.get("focused_package") == run.target_package
            else "INCONCLUSIVE"
        )
    if successful["get_logcat_excerpt"]:
        coverage["logging"] = "ASSESSED"
        coverage["runtime_stability"] = "ASSESSED"
    if successful["frida_status"]:
        data = successful["frida_status"][-1].output_summary
        coverage["runtime_instrumentation"] = (
            "IN_PROGRESS"
            if data.get("frida_server_reachable")
            else "INCONCLUSIVE"
        )
    if successful["frida_run_js"]:
        coverage["runtime_instrumentation"] = "ASSESSED"
    run.coverage_state = coverage
    run.save(update_fields=["coverage_state", "updated_at"])
    return coverage


def _evaluate_hypothesis(hypothesis: AgentHypothesis) -> dict[str, Any] | None:
    if hypothesis.family == AgentHypothesis.Family.SENSITIVE_LOG_EXPOSURE:
        return _log_oracle(hypothesis, stability=False)
    if hypothesis.family == AgentHypothesis.Family.APPLICATION_RUNTIME_STABILITY:
        return _log_oracle(hypothesis, stability=True)
    if hypothesis.family == AgentHypothesis.Family.UI_SENSITIVE_DATA_EXPOSURE:
        return _ui_oracle(hypothesis)
    if hypothesis.family == AgentHypothesis.Family.RUNTIME_TAMPERING_RESILIENCE:
        return _runtime_tampering_oracle(hypothesis)
    return None


def _log_oracle(
    hypothesis: AgentHypothesis,
    *,
    stability: bool,
) -> dict[str, Any] | None:
    steps = list(
        hypothesis.run.steps.filter(
            tool_name="get_logcat_excerpt",
            status=AgentRunStep.Status.SUCCEEDED,
        ).order_by("sequence_number")
    )
    if not steps:
        return None
    lines = []
    for step in steps:
        data = step.output_summary if isinstance(step.output_summary, dict) else {}
        lines.extend(line for line in data.get("lines", []) if isinstance(line, str))
    evidence_ids = _evidence_ids(steps)
    if stability:
        matched = any(CRASH_RE.search(line) for line in lines[:500])
        return _result(
            oracle_id="msap.oracle.application-runtime-stability/v1",
            status="SUPPORTED" if matched else "REJECTED",
            evidence_ids=evidence_ids,
            reason_code="TARGET_CRASH_MARKER_OBSERVED" if matched else "NO_TARGET_CRASH_MARKER_OBSERVED",
            summary=(
                "A deterministic crash or ANR marker was observed in bounded log evidence."
                if matched
                else "No deterministic crash or ANR marker was observed in the bounded log window."
            ),
            confidence=0.95 if matched else 0.8,
        )
    positive = any(
        REDACTED_ASSIGNMENT_RE.search(line)
        or (SENSITIVE_ASSIGNMENT_RE.search(line) and "[redacted]" in line.lower())
        for line in lines[:500]
    )
    ambiguous = any(SENSITIVE_ASSIGNMENT_RE.search(line) for line in lines[:500])
    status = "SUPPORTED" if positive else "INCONCLUSIVE" if ambiguous else "REJECTED"
    return _result(
        oracle_id="msap.oracle.sensitive-log-exposure/v1",
        status=status,
        evidence_ids=evidence_ids,
        reason_code=(
            "REDACTED_SENSITIVE_ASSIGNMENT_OBSERVED"
            if positive
            else "AMBIGUOUS_SENSITIVE_LOG_PATTERN"
            if ambiguous
            else "NO_SENSITIVE_ASSIGNMENT_OBSERVED"
        ),
        summary=(
            "A redacted sensitive-assignment category was observed in target-correlated logs."
            if positive
            else "A possible sensitive log marker requires manual review."
            if ambiguous
            else "No deterministic sensitive-assignment pattern was observed in the bounded log window."
        ),
        confidence=0.95 if positive else 0.5 if ambiguous else 0.8,
    )


def _ui_oracle(hypothesis: AgentHypothesis) -> dict[str, Any] | None:
    steps = list(
        hypothesis.run.steps.filter(
            tool_name="dump_ui",
            status=AgentRunStep.Status.SUCCEEDED,
        ).order_by("sequence_number")
    )
    if not steps:
        return None
    values = []
    for step in steps:
        data = step.output_summary if isinstance(step.output_summary, dict) else {}
        values.extend(value for value in data.get("text_values", []) if isinstance(value, str))
    positive = any(SENSITIVE_ASSIGNMENT_RE.search(value) for value in values[:500])
    return _result(
        oracle_id="msap.oracle.ui-sensitive-data-exposure/v1",
        status="SUPPORTED" if positive else "REJECTED",
        evidence_ids=_evidence_ids(steps),
        reason_code="SENSITIVE_UI_ASSIGNMENT_OBSERVED" if positive else "NO_SENSITIVE_UI_ASSIGNMENT_OBSERVED",
        summary=(
            "An explicit security-sensitive assignment was exposed in parsed target UI text."
            if positive
            else "No explicit security-sensitive assignment was observed in parsed target UI text."
        ),
        confidence=0.9 if positive else 0.75,
    )


def _runtime_tampering_oracle(hypothesis: AgentHypothesis) -> dict[str, Any] | None:
    steps = list(
        hypothesis.run.steps.filter(
            tool_name="frida_run_js",
            status=AgentRunStep.Status.SUCCEEDED,
        ).order_by("sequence_number")
    )
    if not steps:
        return None
    supported = False
    event_only = False
    for step in steps:
        data = step.output_summary if isinstance(step.output_summary, dict) else {}
        event = any(
            isinstance(item, dict)
            and item.get("type") == "ui_modification"
            and item.get("success") is True
            for item in data.get("events", [])[:200]
        )
        event_only = event_only or event
        supported = supported or bool(
            event
            and data.get("before_screenshot_sha256")
            and data.get("after_screenshot_sha256")
            and data["before_screenshot_sha256"] != data["after_screenshot_sha256"]
        )
    status = "SUPPORTED" if supported else "INCONCLUSIVE" if event_only else "REJECTED"
    return _result(
        oracle_id="msap.oracle.runtime-tampering-evidence/v1",
        status=status,
        evidence_ids=_evidence_ids(steps),
        reason_code=(
            "CONTROLLED_EVENT_AND_VISIBLE_CHANGE_OBSERVED"
            if supported
            else "CONTROLLED_EVENT_WITHOUT_CORRELATED_VISIBLE_CHANGE"
            if event_only
            else "CONTROLLED_INSTRUMENTATION_NOT_EVIDENCED"
        ),
        summary=(
            "Controlled target instrumentation and a correlated visible-state change were evidenced."
            if supported
            else "Controlled instrumentation output was incomplete and requires review."
            if event_only
            else "The controlled instrumentation proof did not produce the required evidence."
        ),
        confidence=0.98 if supported else 0.5 if event_only else 0.8,
    )


def _result(
    *,
    oracle_id: str,
    status: str,
    evidence_ids: list[int],
    reason_code: str,
    summary: str,
    confidence: float,
) -> dict[str, Any]:
    return {
        "oracle_id": oracle_id,
        "status": status if status in ORACLE_RESULT_STATUSES else "INCONCLUSIVE",
        "evidence_ids": evidence_ids[:50],
        "reason_code": reason_code,
        "safe_summary": summary[:500],
        "confidence": max(0.0, min(1.0, confidence)),
    }


def _hypothesis_status(oracle_status: str) -> str:
    return {
        "SUPPORTED": AgentHypothesis.Status.SUPPORTED,
        "REJECTED": AgentHypothesis.Status.REJECTED,
        "INCONCLUSIVE": AgentHypothesis.Status.INCONCLUSIVE,
        "NOT_APPLICABLE": AgentHypothesis.Status.BLOCKED,
    }.get(oracle_status, AgentHypothesis.Status.INCONCLUSIVE)


def _evidence_ids(steps: list[AgentRunStep]) -> list[int]:
    return list(
        Evidence.objects.filter(agent_run_step_id__in=[step.id for step in steps])
        .order_by("id")
        .values_list("id", flat=True)[:50]
    )

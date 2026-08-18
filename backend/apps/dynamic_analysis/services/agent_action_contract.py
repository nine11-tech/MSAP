from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import re
from typing import Any

from django.utils import timezone

from apps.dynamic_analysis.models import AgentActionDecision, AgentHypothesis, AgentRun
from apps.dynamic_analysis.services.agent_capability_envelope import (
    CapabilityEnvelopeError,
    validate_capability_envelope,
)
from apps.dynamic_analysis.services.agent_tools import (
    AgentToolError,
    BUILTIN_FRIDA_UI_PROOF,
    TOOL_MANIFEST,
    validate_agent_tool_arguments,
)
from apps.dynamic_analysis.services.frida_scripts import APPROVED_FRIDA_SOURCE_IDENTIFIERS
from apps.dynamic_analysis.services.assessment_plan_contract import EVIDENCE_TYPES


ACTION_DECISION_VERSION = "msap.agent-action-decision/v1"
ACTION_DECISION_FIELDS = {
    "contract_version",
    "decision_type",
    "hypothesis_id",
    "tool_name",
    "arguments",
    "rationale_summary",
    "expected_observation",
    "evidence_goal",
    "confidence",
}
MAX_DECISION_BYTES = 32 * 1024
HYPOTHESIS_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
FORBIDDEN_TEXT_RE = re.compile(
    r"(?:\badb\s+shell\b|\bpython\b|\bdocker\b|\bsubprocess\b|\bssh\b|"
    r"\bfilesystem\b|\bhost\s+path\b|\bauthorization\s+header\b|"
    r"\bapi[_ -]?key\b|\bcredential\b)",
    re.IGNORECASE,
)


class AgentActionDecisionError(RuntimeError):
    def __init__(self, message: str, *, code: str, http_status: int = 409):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


def validate_action_decision(
    value: Any,
    *,
    run: AgentRun,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != ACTION_DECISION_FIELDS:
        raise AgentActionDecisionError(
            "The action decision does not match its closed contract.",
            code="AGENT_DECISION_SCHEMA_INVALID",
        )
    try:
        encoded = _canonical_json(value)
    except (TypeError, ValueError):
        raise AgentActionDecisionError(
            "The action decision must be bounded JSON.",
            code="AGENT_DECISION_JSON_INVALID",
        ) from None
    if len(encoded.encode("utf-8")) > MAX_DECISION_BYTES:
        raise AgentActionDecisionError(
            "The action decision exceeds its size limit.",
            code="AGENT_DECISION_TOO_LARGE",
        )
    if value.get("contract_version") != ACTION_DECISION_VERSION:
        raise AgentActionDecisionError(
            "The action decision contract version is unsupported.",
            code="AGENT_DECISION_VERSION_INVALID",
        )

    decision_type = value.get("decision_type")
    if decision_type not in AgentActionDecision.DecisionType.values:
        raise AgentActionDecisionError(
            "The action decision type is unsupported.",
            code="AGENT_DECISION_TYPE_INVALID",
        )
    rationale = _bounded_text(value.get("rationale_summary"), 1000, required=True)
    expected = _bounded_text(value.get("expected_observation"), 1000)
    if FORBIDDEN_TEXT_RE.search(rationale) or FORBIDDEN_TEXT_RE.search(expected):
        raise AgentActionDecisionError(
            "The action decision contains a prohibited execution instruction.",
            code="AGENT_DECISION_PROHIBITED_TEXT",
        )
    confidence = value.get("confidence")
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 0.0 <= float(confidence) <= 1.0
    ):
        raise AgentActionDecisionError(
            "The action decision confidence must be between zero and one.",
            code="AGENT_DECISION_CONFIDENCE_INVALID",
        )
    evidence_goals = value.get("evidence_goal")
    if (
        not isinstance(evidence_goals, list)
        or len(evidence_goals) > 8
        or any(goal not in EVIDENCE_TYPES for goal in evidence_goals)
        or len(evidence_goals) != len(set(evidence_goals))
    ):
        raise AgentActionDecisionError(
            "The action decision evidence goals are invalid.",
            code="AGENT_DECISION_EVIDENCE_GOAL_INVALID",
        )

    hypothesis_id = value.get("hypothesis_id")
    hypothesis = None
    if hypothesis_id is not None:
        if not isinstance(hypothesis_id, str) or not HYPOTHESIS_ID_RE.fullmatch(
            hypothesis_id
        ):
            raise AgentActionDecisionError(
                "The action decision hypothesis identifier is invalid.",
                code="AGENT_DECISION_HYPOTHESIS_INVALID",
            )
        hypothesis = AgentHypothesis.objects.filter(
            run=run,
            hypothesis_id=hypothesis_id,
        ).first()
        if hypothesis is None:
            raise AgentActionDecisionError(
                "The action decision references an unknown run hypothesis.",
                code="AGENT_DECISION_HYPOTHESIS_UNKNOWN",
            )

    tool_name = value.get("tool_name")
    arguments = value.get("arguments")
    if decision_type == AgentActionDecision.DecisionType.TOOL_ACTION:
        if hypothesis is None:
            raise AgentActionDecisionError(
                "A tool action must reference a run hypothesis.",
                code="AGENT_DECISION_HYPOTHESIS_REQUIRED",
            )
        if not isinstance(tool_name, str) or tool_name not in TOOL_MANIFEST:
            raise AgentActionDecisionError(
                "The action decision references an unknown capability.",
                code="AGENT_DECISION_TOOL_UNKNOWN",
            )
        try:
            envelope = validate_capability_envelope(run.capability_envelope, run=run)
        except CapabilityEnvelopeError as exc:
            raise AgentActionDecisionError(str(exc), code=exc.code) from None
        if tool_name not in envelope["allowed_capabilities"]:
            raise AgentActionDecisionError(
                "The action decision capability is outside the approved envelope.",
                code="AGENT_DECISION_TOOL_OUTSIDE_ENVELOPE",
                http_status=403,
            )
        plan = run.assessment_plan
        normalized_plan = plan.normalized_plan if plan is not None else None
        if isinstance(normalized_plan, dict):
            planned_tools = [
                tool.get("name")
                for step in normalized_plan.get("steps", [])
                if isinstance(step, dict)
                and ("MSAP-AND-" in str(step.get("rationale", "")) or any(playbook in str(step.get("rationale", "")) for playbook in {
                    "ROOT_DETECTION_LAB_BYPASS", "EMULATOR_DETECTION_LAB_BYPASS", "ROOT_SIGNAL_OBSERVATION", "EMULATOR_SIGNAL_OBSERVATION"
                }) or any(
                    isinstance(item, dict) and item.get("name") in {
                        "launch_exported_activity", "send_explicit_broadcast", "query_exported_provider"
                    }
                    for item in step.get("tools", [])
                ))
                for tool in step.get("tools", [])
                if isinstance(tool, dict)
            ]
            if planned_tools:
                consumed = run.steps.count()
                expected = planned_tools[consumed] if consumed < len(planned_tools) else None
                if expected and tool_name != expected:
                    raise AgentActionDecisionError(
                        f"The approved finding-driven playbook requires {expected} next.",
                        code="AGENT_DECISION_PLAN_STEP_MISMATCH",
                        http_status=403,
                    )
        if tool_name in envelope["additional_approval_capabilities"]:
            raise AgentActionDecisionError(
                "The requested capability requires additional auditor approval.",
                code="AGENT_DECISION_NEEDS_AUDITOR",
                http_status=403,
            )
        if tool_name == "frida_run_js" and arguments.get("source") not in APPROVED_FRIDA_SOURCE_IDENTIFIERS:
            raise AgentActionDecisionError(
                "Agentic Frida execution is restricted to the controlled built-in proof.",
                code="AGENT_DECISION_FRIDA_SOURCE_REJECTED",
                http_status=403,
            )
        try:
            arguments = validate_agent_tool_arguments(
                tool_name,
                arguments,
                requested_by=run.requested_by,
            )
        except AgentToolError as exc:
            raise AgentActionDecisionError(
                "The action decision arguments do not match the capability schema.",
                code="AGENT_DECISION_ARGUMENTS_INVALID",
            ) from exc
        _authorize_arguments(run, tool_name, arguments, envelope)
    else:
        if tool_name not in {"", None} or arguments != {}:
            raise AgentActionDecisionError(
                "A non-tool decision cannot contain a tool call.",
                code="AGENT_DECISION_NON_TOOL_PAYLOAD_INVALID",
            )
        tool_name = ""
        arguments = {}

    return {
        "contract_version": ACTION_DECISION_VERSION,
        "decision_type": decision_type,
        "hypothesis_id": hypothesis_id,
        "tool_name": tool_name,
        "arguments": deepcopy(arguments),
        "rationale_summary": rationale,
        "expected_observation": expected,
        "evidence_goal": list(evidence_goals),
        "confidence": float(confidence),
    }


def persist_validated_decision(
    *,
    run: AgentRun,
    decision: dict[str, Any],
    provider: str,
    model: str,
    provider_metadata: dict[str, Any],
    decision_input_hash: str,
) -> AgentActionDecision:
    normalized = validate_action_decision(decision, run=run)
    hypothesis = (
        run.hypotheses.get(hypothesis_id=normalized["hypothesis_id"])
        if normalized["hypothesis_id"]
        else None
    )
    return AgentActionDecision.objects.create(
        run=run,
        hypothesis=hypothesis,
        sequence=run.decision_count + 1,
        contract_version=ACTION_DECISION_VERSION,
        decision_type=normalized["decision_type"],
        tool_name=normalized["tool_name"],
        arguments=normalized["arguments"],
        rationale_summary=normalized["rationale_summary"],
        expected_observation=normalized["expected_observation"],
        evidence_goals=normalized["evidence_goal"],
        confidence=normalized["confidence"],
        provider=provider,
        model=model,
        provider_metadata=_bounded_provider_metadata(provider_metadata),
        decision_input_hash=decision_input_hash,
        decision_output_hash=decision_hash(normalized),
        validation_status=AgentActionDecision.CheckStatus.PASSED,
        policy_status=AgentActionDecision.CheckStatus.PASSED,
        validated_at=timezone.now(),
    )


def decision_hash(value: dict[str, Any]) -> str:
    return sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def persisted_decision_payload(decision: AgentActionDecision) -> dict[str, Any]:
    return {
        "contract_version": decision.contract_version,
        "decision_type": decision.decision_type,
        "hypothesis_id": (
            decision.hypothesis.hypothesis_id if decision.hypothesis_id else None
        ),
        "tool_name": decision.tool_name,
        "arguments": decision.arguments,
        "rationale_summary": decision.rationale_summary,
        "expected_observation": decision.expected_observation,
        "evidence_goal": decision.evidence_goals,
        "confidence": decision.confidence,
    }


def _authorize_arguments(
    run: AgentRun,
    tool_name: str,
    arguments: dict[str, Any],
    envelope: dict[str, Any],
) -> None:
    if "package_name" in arguments and arguments["package_name"] != run.target_package:
        raise AgentActionDecisionError(
            "The action decision attempted to change the authorized target package.",
            code="AGENT_DECISION_TARGET_MISMATCH",
            http_status=403,
        )
    if "audit_id" in arguments and arguments["audit_id"] != run.audit_id:
        raise AgentActionDecisionError(
            "The action decision attempted to change the authorized audit.",
            code="AGENT_DECISION_AUDIT_MISMATCH",
            http_status=403,
        )
    policy = envelope["capability_argument_policy"][tool_name]
    if tool_name == "list_packages" and arguments.get("include_system") is not False:
        raise AgentActionDecisionError(
            "Agentic package inventory cannot include system packages.",
            code="AGENT_DECISION_ARGUMENT_POLICY_REJECTED",
            http_status=403,
        )
    if tool_name == "frida_run_js" and (
        arguments.get("source") not in policy.get("allowed_source_identifiers", [])
        or arguments.get("mode") not in policy["allowed_modes"]
    ):
        raise AgentActionDecisionError(
            "Agentic Frida execution is restricted to the controlled built-in proof.",
            code="AGENT_DECISION_FRIDA_SOURCE_REJECTED",
            http_status=403,
        )
    if tool_name in {"stop_logcat", "get_logcat_excerpt"}:
        collector_ids = {
            step.output_summary.get("collector_id")
            for step in run.steps.filter(
                tool_name="start_logcat",
                status="SUCCEEDED",
            )
            if isinstance(step.output_summary, dict)
        }
        if arguments.get("collector_id") not in collector_ids:
            raise AgentActionDecisionError(
                "The log collector does not belong to this AgentRun.",
                code="AGENT_DECISION_COLLECTOR_UNAUTHORIZED",
                http_status=403,
            )
    if policy.get("requires_authorized_target_foreground") and not _target_foreground(
        run
    ):
        raise AgentActionDecisionError(
            "Blind UI interaction is blocked until the authorized target is foregrounded.",
            code="AGENT_DECISION_TARGET_NOT_FOREGROUND",
            http_status=403,
        )


def _target_foreground(run: AgentRun) -> bool:
    for step in run.steps.filter(status="SUCCEEDED").order_by("-sequence_number")[:8]:
        output = step.output_summary if isinstance(step.output_summary, dict) else {}
        if step.tool_name == "dump_ui":
            return output.get("focused_package") == run.target_package
        if step.tool_name == "launch_package":
            return run.target_package in str(output.get("focused_app") or "")
        if step.tool_name == "force_stop_package":
            return False
    return False


def _bounded_text(value: Any, limit: int, *, required: bool = False) -> str:
    if not isinstance(value, str):
        raise AgentActionDecisionError(
            "The action decision contains an invalid text field.",
            code="AGENT_DECISION_TEXT_INVALID",
        )
    normalized = value.replace("\x00", "").strip()
    if required and not normalized:
        raise AgentActionDecisionError(
            "The action decision rationale summary is required.",
            code="AGENT_DECISION_TEXT_INVALID",
        )
    if len(normalized) > limit:
        raise AgentActionDecisionError(
            "The action decision contains an oversized text field.",
            code="AGENT_DECISION_TEXT_TOO_LARGE",
        )
    return normalized


def _bounded_provider_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    bounded: dict[str, Any] = {}
    for key in {"provider_status", "response_id"}:
        item = value.get(key)
        if isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", item):
            bounded[key] = item
    for key in {
        "retry_count",
        "latency_ms",
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "total_tokens",
    }:
        item = value.get(key)
        if not isinstance(item, bool) and isinstance(item, int) and item >= 0:
            bounded[key] = min(item, 1_000_000_000)
    return bounded


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

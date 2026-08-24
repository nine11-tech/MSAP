from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from typing import Any

from django.conf import settings

from apps.dynamic_analysis.models import AgentHypothesis, AssessmentPlan
from apps.dynamic_analysis.services.agent_tools import (
    ALL_TOOL_NAMES,
    TOOL_MANIFEST,
)
from apps.dynamic_analysis.services.frida_scripts import APPROVED_FRIDA_SOURCE_IDENTIFIERS
from apps.dynamic_analysis.services.assessment_execution_contract import (
    build_approved_execution_contract,
    validate_persisted_plan_contract,
)


CAPABILITY_ENVELOPE_VERSION = "msap.agent-capability-envelope/v1"

# This policy is backend-owned. A capability must also be present in the
# approved strategy, current manifest, audit authorization, and target scope.
AGENTIC_SAFE_CAPABILITIES = frozenset(
    {
        "get_device_status",
        "list_packages",
        "launch_package",
        "force_stop_package",
        "take_screenshot",
        "start_logcat",
        "stop_logcat",
        "get_logcat_excerpt",
        "start_proxy_capture",
        "stop_proxy_capture",
        "get_proxy_flows",
        "dump_ui",
        "tap_coordinates",
        "type_text",
        "reset_root_detection_demo",
        "prepare_root_detection_demo",
        "frida_status",
        "frida_ps",
        "frida_attach",
        "frida_run_js",
    }
)
PLAYBOOK_SAFE_CAPABILITIES = frozenset(
    {
        "launch_exported_activity",
        "send_explicit_broadcast",
        "query_exported_provider",
        "start_proxy_capture",
        "stop_proxy_capture",
        "get_proxy_flows",
    }
)
ALL_AGENTIC_SAFE_CAPABILITIES = AGENTIC_SAFE_CAPABILITIES | PLAYBOOK_SAFE_CAPABILITIES
DESTRUCTIVE_CAPABILITIES = frozenset(
    {"clear_package_data", "install_verified_apk", "frida_setup"}
)
ADDITIONAL_APPROVAL_CAPABILITIES = DESTRUCTIVE_CAPABILITIES | {"start_proxy_capture"}

ENVELOPE_FIELDS = {
    "contract_version",
    "approved_assessment_plan_id",
    "approved_plan_hash",
    "audit_id",
    "target_package",
    "objective",
    "scope",
    "allowed_capabilities",
    "capability_argument_policy",
    "destructive_capabilities",
    "additional_approval_capabilities",
    "maximum_decisions",
    "maximum_tool_calls",
    "maximum_run_duration_seconds",
    "maximum_consecutive_failures",
    "maximum_artifacts",
    "maximum_evidence_records",
    "maximum_observation_bytes",
    "maximum_model_provider_calls",
    "allowed_hypothesis_families",
    "envelope_hash",
}

RETRY_PRESERVED_LIMIT_FIELDS = frozenset(
    {
        "maximum_decisions",
        "maximum_tool_calls",
        "maximum_run_duration_seconds",
        "maximum_consecutive_failures",
        "maximum_artifacts",
        "maximum_evidence_records",
        "maximum_observation_bytes",
        "maximum_model_provider_calls",
    }
)


class CapabilityEnvelopeError(RuntimeError):
    def __init__(self, message: str, *, code: str):
        super().__init__(message)
        self.code = code


def build_capability_preview(plan: AssessmentPlan) -> dict[str, Any]:
    """Describe the backend-owned adaptive boundary without making it executable."""

    if (
        plan.validation_status != AssessmentPlan.ValidationStatus.PASSED
        or plan.policy_status != AssessmentPlan.PolicyStatus.PASSED
        or not isinstance(plan.normalized_plan, dict)
    ):
        return {}
    steps = plan.normalized_plan.get("steps")
    if not isinstance(steps, list):
        return {}
    strategy_capabilities = {
        tool.get("name")
        for step in steps
        if isinstance(step, dict)
        for tool in step.get("tools", [])
        if isinstance(tool, dict) and isinstance(tool.get("name"), str)
    }
    allowed_capabilities = sorted(
        strategy_capabilities & ALL_AGENTIC_SAFE_CAPABILITIES & ALL_TOOL_NAMES
    )
    return {
        "contract_version": CAPABILITY_ENVELOPE_VERSION,
        "allowed_capabilities": allowed_capabilities,
        "allowed_hypothesis_families": _hypothesis_families(
            allowed_capabilities
        ),
        "maximum_decisions": settings.MSAP_AGENT_MAX_DECISIONS,
        "maximum_tool_calls": settings.MSAP_AGENT_MAX_TOOL_CALLS,
        "maximum_run_duration_seconds": settings.MSAP_AGENT_MAX_DURATION_SECONDS,
        "maximum_provider_calls": settings.MSAP_AGENT_MAX_PROVIDER_CALLS,
        "additional_approval_capabilities": sorted(
            strategy_capabilities & ADDITIONAL_APPROVAL_CAPABILITIES
        ),
    }


def build_capability_envelope(plan: AssessmentPlan) -> dict[str, Any]:
    contract = build_approved_execution_contract(plan)
    canonical = contract["approved_plan"]
    return _build_capability_envelope(plan, canonical)


def rebuild_capability_envelope_for_retry(
    plan: AssessmentPlan,
    *,
    approved_envelope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Rebuild an approved envelope without granting a new approval.

    A safely failed legacy run may have left its plan in FAILED. The original
    approver and approval timestamp remain mandatory; this helper only
    reconstructs and hashes the envelope for retry eligibility.
    """

    if (
        plan.validation_status != AssessmentPlan.ValidationStatus.PASSED
        or plan.policy_status != AssessmentPlan.PolicyStatus.PASSED
        or plan.approved_by_id is None
        or plan.approved_at is None
        or plan.status not in {
            AssessmentPlan.Status.APPROVED,
            AssessmentPlan.Status.FAILED,
        }
    ):
        raise CapabilityEnvelopeError(
            "The assessment plan does not retain an approved retry boundary.",
            code="AGENT_RETRY_APPROVAL_INVALID",
        )
    canonical = validate_persisted_plan_contract(plan)
    rebuilt = _build_capability_envelope(plan, canonical)
    if approved_envelope is None:
        return rebuilt

    approved = validate_capability_envelope(approved_envelope)
    for field in RETRY_PRESERVED_LIMIT_FIELDS:
        approved_limit = approved[field]
        current_limit = rebuilt[field]
        if (
            isinstance(approved_limit, bool)
            or not isinstance(approved_limit, int)
            or approved_limit < 1
        ):
            raise CapabilityEnvelopeError(
                "The approved retry limits are invalid.",
                code="AGENT_RETRY_ENVELOPE_LIMIT_INVALID",
            )
        rebuilt[field] = min(approved_limit, current_limit)
    rebuilt["envelope_hash"] = _envelope_hash(rebuilt)
    return rebuilt


def _build_capability_envelope(
    plan: AssessmentPlan,
    canonical: dict[str, Any],
) -> dict[str, Any]:
    strategy_capabilities = {
        tool["name"]
        for step in canonical["steps"]
        for tool in step["tools"]
    }
    allowed_capabilities = sorted(
        strategy_capabilities & ALL_AGENTIC_SAFE_CAPABILITIES & ALL_TOOL_NAMES
    )
    if not allowed_capabilities:
        raise CapabilityEnvelopeError(
            "The approved strategy contains no adaptive-safe capabilities.",
            code="AGENT_CAPABILITY_ENVELOPE_EMPTY",
        )

    envelope: dict[str, Any] = {
        "contract_version": CAPABILITY_ENVELOPE_VERSION,
        "approved_assessment_plan_id": plan.id,
        "approved_plan_hash": plan.plan_hash,
        "audit_id": plan.audit_id,
        "target_package": plan.target_package,
        "objective": plan.objective,
        "scope": plan.scope,
        "allowed_capabilities": allowed_capabilities,
        "capability_argument_policy": {
            name: _argument_policy(name, plan)
            for name in allowed_capabilities
        },
        "destructive_capabilities": sorted(
            strategy_capabilities & DESTRUCTIVE_CAPABILITIES
        ),
        "additional_approval_capabilities": sorted(
            strategy_capabilities & ADDITIONAL_APPROVAL_CAPABILITIES
        ),
        "maximum_decisions": settings.MSAP_AGENT_MAX_DECISIONS,
        "maximum_tool_calls": settings.MSAP_AGENT_MAX_TOOL_CALLS,
        "maximum_run_duration_seconds": settings.MSAP_AGENT_MAX_DURATION_SECONDS,
        "maximum_consecutive_failures": settings.MSAP_AGENT_MAX_CONSECUTIVE_FAILURES,
        "maximum_artifacts": settings.MSAP_AGENT_MAX_ARTIFACTS,
        "maximum_evidence_records": settings.MSAP_AGENT_MAX_EVIDENCE_RECORDS,
        "maximum_observation_bytes": (
            settings.MSAP_ASSESSMENT_EXECUTION_MAX_OBSERVATION_BYTES
        ),
        "maximum_model_provider_calls": settings.MSAP_AGENT_MAX_PROVIDER_CALLS,
        "allowed_hypothesis_families": _hypothesis_families(
            allowed_capabilities
        ),
    }
    envelope["envelope_hash"] = _envelope_hash(envelope)
    return envelope


def _hypothesis_families(allowed_capabilities: list[str]) -> list[str]:
    allowed = set(allowed_capabilities)
    families: list[str] = []
    if {"start_logcat", "get_logcat_excerpt"} <= allowed:
        families.extend(
            [
                AgentHypothesis.Family.SENSITIVE_LOG_EXPOSURE,
                AgentHypothesis.Family.APPLICATION_RUNTIME_STABILITY,
            ]
        )
    if "dump_ui" in allowed:
        families.append(AgentHypothesis.Family.UI_SENSITIVE_DATA_EXPOSURE)
    if "frida_run_js" in allowed or {"frida_status", "frida_attach"} <= allowed:
        families.append(AgentHypothesis.Family.RUNTIME_TAMPERING_RESILIENCE)
    if allowed & {"launch_exported_activity", "send_explicit_broadcast", "query_exported_provider"}:
        families.append(AgentHypothesis.Family.APPLICATION_RUNTIME_STABILITY)
    return sorted(set(families))


def validate_capability_envelope(
    value: Any,
    *,
    run=None,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != ENVELOPE_FIELDS:
        raise CapabilityEnvelopeError(
            "The capability envelope does not match its closed contract.",
            code="AGENT_CAPABILITY_ENVELOPE_INVALID",
        )
    envelope = deepcopy(value)
    if envelope["contract_version"] != CAPABILITY_ENVELOPE_VERSION:
        raise CapabilityEnvelopeError(
            "The capability envelope version is unsupported.",
            code="AGENT_CAPABILITY_ENVELOPE_VERSION_INVALID",
        )
    if envelope.get("envelope_hash") != _envelope_hash(envelope):
        raise CapabilityEnvelopeError(
            "The capability envelope failed its integrity check.",
            code="AGENT_CAPABILITY_ENVELOPE_HASH_MISMATCH",
        )
    allowed = envelope.get("allowed_capabilities")
    policies = envelope.get("capability_argument_policy")
    if (
        not isinstance(allowed, list)
        or not allowed
        or allowed != sorted(set(allowed))
        or not set(allowed) <= ALL_AGENTIC_SAFE_CAPABILITIES
        or not set(allowed) <= ALL_TOOL_NAMES
        or not isinstance(policies, dict)
        or set(policies) != set(allowed)
    ):
        raise CapabilityEnvelopeError(
            "The capability envelope references an unauthorized capability.",
            code="AGENT_CAPABILITY_ENVELOPE_CAPABILITY_INVALID",
        )
    if run is not None:
        plan = run.assessment_plan
        if (
            plan is None
            or envelope["approved_assessment_plan_id"] != plan.id
            or envelope["approved_plan_hash"] != plan.plan_hash
            or envelope["approved_plan_hash"] != run.approved_plan_hash
            or envelope["envelope_hash"] != run.capability_envelope_hash
            or envelope["audit_id"] != run.audit_id
            or envelope["target_package"] != run.target_package
            or envelope["objective"] != plan.objective
            or envelope["scope"] != plan.scope
        ):
            raise CapabilityEnvelopeError(
                "The run capability envelope no longer matches the approved strategy.",
                code="AGENT_CAPABILITY_ENVELOPE_AUTHORIZATION_FAILED",
            )
    return envelope


def _argument_policy(name: str, plan: AssessmentPlan) -> dict[str, Any]:
    policy: dict[str, Any] = {
        "input_schema": deepcopy(TOOL_MANIFEST[name].input_schema),
        "target_package": plan.target_package,
        "audit_id": plan.audit_id,
    }
    if name == "list_packages":
        policy["include_system"] = False
    if name in {"tap_coordinates", "type_text"}:
        policy["requires_authorized_target_foreground"] = True
    if name in {"launch_exported_activity", "send_explicit_broadcast", "query_exported_provider"}:
        policy["manifest_inventory_required"] = True
        policy["read_only"] = True
    if name == "frida_run_js":
        sources = [
            tool.get("arguments", {}).get("source")
            for step in (plan.normalized_plan or {}).get("steps", [])
            if isinstance(step, dict)
            for tool in step.get("tools", [])
            if isinstance(tool, dict) and tool.get("name") == "frida_run_js"
        ]
        policy.update(
            {
                "allowed_source_identifiers": sorted(set(sources) & set(APPROVED_FRIDA_SOURCE_IDENTIFIERS)),
                "allowed_modes": ["attach"],
            }
        )
    return policy


def _envelope_hash(envelope: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in envelope.items() if key != "envelope_hash"}
    canonical = json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return sha256(canonical.encode("utf-8")).hexdigest()

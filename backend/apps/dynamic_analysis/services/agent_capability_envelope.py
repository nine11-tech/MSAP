from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from typing import Any

from django.conf import settings

from apps.dynamic_analysis.models import AgentHypothesis, AssessmentPlan
from apps.dynamic_analysis.services.agent_tools import (
    BUILTIN_FRIDA_UI_PROOF,
    TOOL_MANIFEST,
)
from apps.dynamic_analysis.services.assessment_execution_contract import (
    build_approved_execution_contract,
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
        "dump_ui",
        "tap_coordinates",
        "type_text",
        "frida_status",
        "frida_ps",
        "frida_attach",
        "frida_run_js",
    }
)
DESTRUCTIVE_CAPABILITIES = frozenset(
    {"clear_package_data", "install_verified_apk", "frida_setup"}
)
ADDITIONAL_APPROVAL_CAPABILITIES = DESTRUCTIVE_CAPABILITIES

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


class CapabilityEnvelopeError(RuntimeError):
    def __init__(self, message: str, *, code: str):
        super().__init__(message)
        self.code = code


def build_capability_envelope(plan: AssessmentPlan) -> dict[str, Any]:
    contract = build_approved_execution_contract(plan)
    canonical = contract["approved_plan"]
    strategy_capabilities = {
        tool["name"]
        for step in canonical["steps"]
        for tool in step["tools"]
    }
    allowed_capabilities = sorted(
        strategy_capabilities & AGENTIC_SAFE_CAPABILITIES & set(TOOL_MANIFEST)
    )
    if not allowed_capabilities:
        raise CapabilityEnvelopeError(
            "The approved strategy contains no adaptive-safe capabilities.",
            code="AGENT_CAPABILITY_ENVELOPE_EMPTY",
        )

    hypothesis_families: list[str] = []
    if {"start_logcat", "get_logcat_excerpt"} <= set(allowed_capabilities):
        hypothesis_families.extend(
            [
                AgentHypothesis.Family.SENSITIVE_LOG_EXPOSURE,
                AgentHypothesis.Family.APPLICATION_RUNTIME_STABILITY,
            ]
        )
    if "dump_ui" in allowed_capabilities:
        hypothesis_families.append(AgentHypothesis.Family.UI_SENSITIVE_DATA_EXPOSURE)
    if {"frida_status", "frida_run_js"} <= set(allowed_capabilities):
        hypothesis_families.append(
            AgentHypothesis.Family.RUNTIME_TAMPERING_RESILIENCE
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
        "allowed_hypothesis_families": sorted(set(hypothesis_families)),
    }
    envelope["envelope_hash"] = _envelope_hash(envelope)
    return envelope


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
        or not set(allowed) <= AGENTIC_SAFE_CAPABILITIES
        or not set(allowed) <= set(TOOL_MANIFEST)
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
    if name == "frida_run_js":
        policy.update(
            {
                "allowed_source_identifiers": [BUILTIN_FRIDA_UI_PROOF],
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

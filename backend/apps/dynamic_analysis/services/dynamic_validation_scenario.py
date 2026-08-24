"""Closed, versioned contract for static-finding-driven validation.

This document is the boundary between model reasoning and the existing plan
executor. It is deliberately data-only: it contains no executable shell,
ADB, or Frida source.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any

from apps.dynamic_analysis.services.agent_tools import TOOL_MANIFEST

CONTRACT_VERSION = "msap.dynamic-validation-scenario/v1"
SCENARIO_FAMILIES = {
    "LOGGING_VALIDATION",
    "UI_EXPOSURE_VALIDATION",
    "RUNTIME_TAMPERING_VALIDATION",
    "TLS_INTERCEPTION_VALIDATION",
    "BASIC_RUNTIME_REACHABILITY",
    "NOT_ASSESSABLE_WITH_CURRENT_TOOLS",
}
RESULTS = {"SUPPORTED", "REJECTED", "INCONCLUSIVE", "NOT_ASSESSABLE", "FAILED"}
MAX_STEPS = 12
MAX_BRANCHES = 8
MAX_TEXT = 1000
PROHIBITED_TERMS = {
    "shell", "adb shell", "arbitrary", "host filesystem", "database",
    "private key", "host secret", "read secret", "copy secret",
    "dump credential", "dump token", "dump password",
}


class DynamicValidationScenarioError(ValueError):
    pass


def validate_scenario(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DynamicValidationScenarioError("Scenario must be an object.")
    required = {
        "contract_version", "audit_id", "target_package", "source_finding_id",
        "finding_rule_id", "finding_title", "validation_goal", "validation_hypothesis",
        "validation_strategy", "supported_tool_capabilities", "required_evidence_types",
        "steps", "troubleshooting_branches", "stop_conditions", "not_assessable_reason",
        "destructive_actions_required", "approval_required", "max_decisions",
        "max_tool_calls", "max_duration_seconds",
    }
    if set(value) != required:
        raise DynamicValidationScenarioError("Scenario fields must match the v1 contract exactly.")
    if value["contract_version"] != CONTRACT_VERSION:
        raise DynamicValidationScenarioError("Unsupported dynamic validation scenario version.")
    if any(not isinstance(value[key], int) or isinstance(value[key], bool) or value[key] < 1 for key in ("audit_id", "source_finding_id")):
        raise DynamicValidationScenarioError("Scenario identities must be positive integers.")
    if not isinstance(value["target_package"], str) or "." not in value["target_package"]:
        raise DynamicValidationScenarioError("Scenario target package is invalid.")
    if not isinstance(value["validation_strategy"], str) or value["validation_strategy"] not in SCENARIO_FAMILIES:
        raise DynamicValidationScenarioError("Scenario family is not approved.")
    if not all(isinstance(value[key], str) and value[key].strip() for key in ("finding_rule_id", "finding_title", "validation_goal", "validation_hypothesis")):
        raise DynamicValidationScenarioError("Finding and validation text is required.")
    for key in ("supported_tool_capabilities", "required_evidence_types", "steps", "troubleshooting_branches", "stop_conditions"):
        if not isinstance(value[key], list):
            raise DynamicValidationScenarioError(f"{key} must be a list.")
    if not all(isinstance(tool, str) and tool in TOOL_MANIFEST for tool in value["supported_tool_capabilities"]):
        raise DynamicValidationScenarioError("Scenario contains an unknown Tool Gateway capability.")
    if not value["required_evidence_types"] and value["validation_strategy"] != "NOT_ASSESSABLE_WITH_CURRENT_TOOLS":
        raise DynamicValidationScenarioError("Executable scenarios require evidence types.")
    if not 1 <= len(value["steps"]) <= MAX_STEPS:
        raise DynamicValidationScenarioError("Scenario step budget exceeded.")
    if len(value["troubleshooting_branches"]) > MAX_BRANCHES:
        raise DynamicValidationScenarioError("Troubleshooting branch budget exceeded.")
    for key in ("max_decisions", "max_tool_calls", "max_duration_seconds"):
        if not isinstance(value[key], int) or isinstance(value[key], bool) or value[key] < 1 or value[key] > {"max_decisions": 3, "max_tool_calls": 20, "max_duration_seconds": 600}[key]:
            raise DynamicValidationScenarioError(f"{key} is outside the bounded policy.")
    if value["approval_required"] is not True or not isinstance(value["destructive_actions_required"], bool):
        raise DynamicValidationScenarioError("Approval and destructive-action flags are invalid.")
    if value["validation_strategy"] == "NOT_ASSESSABLE_WITH_CURRENT_TOOLS" and not value["not_assessable_reason"]:
        raise DynamicValidationScenarioError("Not-assessable scenarios require a reason.")
    if not value["stop_conditions"]:
        raise DynamicValidationScenarioError("Scenarios require at least one bounded stop condition.")
    serialized = str(value).lower()
    if any(term in serialized for term in PROHIBITED_TERMS):
        raise DynamicValidationScenarioError("Scenario contains a prohibited access or execution instruction.")
    for step in value["steps"]:
        if not isinstance(step, dict) or not isinstance(step.get("tools", []), list):
            raise DynamicValidationScenarioError("Each scenario step must declare a tool list.")
        step_tools = [item.get("name") if isinstance(item, dict) else item for item in step.get("tools", [])]
        if any(tool not in TOOL_MANIFEST for tool in step_tools):
            raise DynamicValidationScenarioError("Scenario step contains an unknown Tool Gateway tool.")
    for branch in value["troubleshooting_branches"]:
        if not isinstance(branch, dict) or not isinstance(branch.get("allowed_actions", []), list):
            raise DynamicValidationScenarioError("Troubleshooting branches must declare allowed actions.")
        if any(tool not in TOOL_MANIFEST for tool in branch.get("allowed_actions", [])):
            raise DynamicValidationScenarioError("Troubleshooting branch contains an unknown Tool Gateway tool.")
    return deepcopy(value)


def scenario_from_finding(*, audit_id: int, target_package: str, finding: dict[str, Any], family: str, tools: list[str], evidence: list[str], steps: list[dict[str, Any]], reason: str = "", hypothesis: str | None = None, goal: str | None = None) -> dict[str, Any]:
    scenario = {
        "contract_version": CONTRACT_VERSION,
        "audit_id": audit_id,
        "target_package": target_package,
        "source_finding_id": finding["finding_id"],
        "finding_rule_id": finding["rule_id"],
        "finding_title": finding["title"],
        "validation_goal": goal or f"Validate the runtime behavior associated with {finding['rule_id']}.",
        "validation_hypothesis": hypothesis or f"The behavior described by static finding {finding['rule_id']} can be observed with bounded approved runtime evidence.",
        "validation_strategy": family,
        "supported_tool_capabilities": tools,
        "required_evidence_types": evidence,
        "steps": steps,
        "troubleshooting_branches": [
            {"issue": "launch_failed", "max_retries": 1, "allowed_actions": ["get_device_status", "launch_package", "take_screenshot"]},
            {"issue": "ui_dump_empty", "max_retries": 1, "allowed_actions": ["dump_ui", "take_screenshot"]},
            {"issue": "target_not_foregrounded", "max_retries": 1, "allowed_actions": ["launch_package", "dump_ui"]},
        ],
        "stop_conditions": ["target authorization mismatch", "budget exhausted", "unrelated app remains foregrounded", "required evidence unavailable"],
        "not_assessable_reason": reason,
        "destructive_actions_required": False,
        "approval_required": True,
        "max_decisions": 3,
        "max_tool_calls": 12,
        "max_duration_seconds": 180,
    }
    return validate_scenario(scenario)

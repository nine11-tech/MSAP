from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import re
from typing import Any

from apps.dynamic_analysis.services.agent_tools import (
    PACKAGE_NAME_RE,
    TOOL_MANIFEST,
)
from apps.dynamic_analysis.services.frida_scripts import APPROVED_FRIDA_SOURCE_IDENTIFIERS


ASSESSMENT_PLAN_CONTRACT_VERSION = "msap.assessment-plan/v1"
MAX_PLAN_STEPS = 12
MAX_PLAN_BYTES = 64 * 1024
MAX_TOOLS_PER_STEP = 8
MAX_TOOL_ARGUMENT_BYTES = 40 * 1024
MAX_EVIDENCE_REQUIREMENTS = 6
MAX_STEP_TIMEOUT_SECONDS = MAX_TOOLS_PER_STEP * max(
    spec.timeout_seconds for spec in TOOL_MANIFEST.values()
)

EVIDENCE_TYPES = (
    "screenshot",
    "ui_hierarchy",
    "logcat",
    "frida_events",
    "tool_output",
    "before_after_comparison",
)

ACTION_GATEWAY_TOOL_SEQUENCE = "gateway_tool_sequence"
ACTION_OBSERVATION_ANALYSIS = "observation_analysis"
ACTION_IDENTIFIERS = (
    ACTION_GATEWAY_TOOL_SEQUENCE,
    ACTION_OBSERVATION_ANALYSIS,
)

PLAN_FIELDS = {
    "contract_version",
    "planner_provider",
    "planner_model",
    "audit_id",
    "target_package",
    "assessment_objective",
    "scope",
    "constraints",
    "traceability",
    "steps",
}
CONSTRAINT_FIELDS = {
    "approval_required",
    "execution_channel",
    "max_steps",
    "max_tools_per_step",
    "max_argument_bytes",
}
TRACEABILITY_FIELDS = {"planner_input_hash", "source_plan_hash"}
STEP_FIELDS = {
    "sequence",
    "step_id",
    "action_id",
    "objective",
    "rationale",
    "tools",
    "expected_observation",
    "success_condition",
    "evidence_requirements",
    "dependencies",
    "requires_explicit_approval",
    "resource_limits",
}
TOOL_CALL_FIELDS = {"name", "arguments"}
RESOURCE_LIMIT_FIELDS = {
    "max_tool_calls",
    "max_total_timeout_seconds",
    "timeout_source",
}

STEP_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
PROVIDER_ID_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,31}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

UNSAFE_INSTRUCTION_PATTERNS = (
    re.compile(
        r"\b(?:adb\s+shell|arbitrary\s+adb|shell\s+command|subprocess|"
        r"docker(?:\s+socket)?|host\s+filesystem|environment\s+variables?|"
        r"host[- ]agent\s+(?:token|credentials?|authentication)|api[-_ ]?keys?|"
        r"ssh\s+keys?|repository\s+access)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:request|obtain|retrieve|read|copy|upload|send|exfiltrate)\b"
        r".{0,48}\b(?:credentials?|passwords?|secrets?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:bypass|disable|remove|weaken)\b.{0,48}\b(?:gateway|security\s+controls?|"
        r"run[- ]scoped\s+authorization|rbac|approval|policy\s+validation)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:create|start|invoke)\s+(?:an?\s+)?AgentRun\b|"
        r"\b(?:call|invoke|execute)\b.{0,32}\b(?:tool\s+gateway|gateway\s+directly|tool\s+directly)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|\s)(?:/bin/(?:sh|bash)|/(?:etc|home|root|proc|sys|tmp|usr|var)/|"
        r"[A-Za-z]:\\)",
        re.IGNORECASE,
    ),
    re.compile(r"(?:^|\s)(?:python(?:3(?:\.\d+)?)?|bash|zsh|powershell|cmd)\s+(?:-|/|[^\s]+\.(?:py|sh|exe)\b)", re.IGNORECASE),
    re.compile(r"(?:^|\s)frida(?:-ps)?\s+-[A-Za-z]", re.IGNORECASE),
    re.compile(r"\.\./|\$\(|`|&&|\|\||;\s*(?:sh|bash|cmd|python)\b", re.IGNORECASE),
    re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[^}]+\})|%[A-Z_][A-Z0-9_]*%|\b(?:os\.environ|process\.env)\b", re.IGNORECASE),
    re.compile(r"/var/run/docker\.sock|BEGIN (?:OPENSSH|RSA) PRIVATE KEY|\bid_rsa\b", re.IGNORECASE),
    re.compile(r"\b(?:postgres(?:ql)?|database|minio|mysql)\s+(?:credentials?|password|secret|token|keys?)\b", re.IGNORECASE),
    re.compile(
        r"\b(?:while\s*\(\s*true|while\s+true|for\s*\(\s*;\s*;\s*\)|"
        r"infinite\s+loop|unbounded\s+(?:loop|timeout|execution))\b",
        re.IGNORECASE,
    ),
)
SAFE_PROHIBITION_PREFIX_RE = re.compile(
    r"^\s*(?:do\s+not|never)\s+"
    r"(?:access|bypass|call|create|disable|execute|infer|invoke|read|remove|"
    r"request|reveal|run|start|use|weaken|write)\b",
    re.IGNORECASE,
)
PROHIBITION_ESCAPE_RE = re.compile(
    r"[;:`]|\$\(|&&|\|\||\b(?:but|except|however|instead|then|unless)\b",
    re.IGNORECASE,
)


class AssessmentPlanContractError(ValueError):
    """A canonical planner/executor contract is structurally invalid."""


def canonical_json_hash(value: Any) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise AssessmentPlanContractError(
            "Assessment plan values must be JSON-compatible."
        ) from None
    return sha256(encoded).hexdigest()


def normalize_assessment_plan_contract(
    normalized_intent: dict[str, Any],
    *,
    audit_id: int,
    planner_provider: str,
    planner_model: str,
    planner_input_hash: str,
) -> dict[str, Any]:
    """Adapt validated legacy planner intent into the canonical v1 contract."""

    canonical_steps: list[dict[str, Any]] = []
    for step in normalized_intent["steps"]:
        tools = deepcopy(step["tools"])
        tool_names = [tool["name"] for tool in tools]
        canonical_steps.append(
            {
                **deepcopy(step),
                "action_id": (
                    ACTION_GATEWAY_TOOL_SEQUENCE
                    if tools
                    else ACTION_OBSERVATION_ANALYSIS
                ),
                "requires_explicit_approval": "clear_package_data" in tool_names,
                "resource_limits": {
                    "max_tool_calls": len(tools),
                    "max_total_timeout_seconds": sum(
                        TOOL_MANIFEST[name].timeout_seconds for name in tool_names
                    ),
                    "timeout_source": "TOOL_MANIFEST",
                },
            }
        )

    canonical = {
        "contract_version": ASSESSMENT_PLAN_CONTRACT_VERSION,
        "planner_provider": planner_provider,
        "planner_model": planner_model,
        "audit_id": audit_id,
        "target_package": normalized_intent["target_package"],
        "assessment_objective": normalized_intent["assessment_objective"],
        "scope": normalized_intent["scope"],
        "constraints": {
            "approval_required": True,
            "execution_channel": "RUN_SCOPED_TOOL_GATEWAY",
            "max_steps": MAX_PLAN_STEPS,
            "max_tools_per_step": MAX_TOOLS_PER_STEP,
            "max_argument_bytes": MAX_TOOL_ARGUMENT_BYTES,
        },
        "traceability": {
            "planner_input_hash": planner_input_hash,
            "source_plan_hash": canonical_json_hash(normalized_intent),
        },
        "steps": canonical_steps,
    }
    return validate_canonical_assessment_plan(canonical)


def validate_canonical_assessment_plan(value: Any) -> dict[str, Any]:
    """Validate and copy the versioned planner-intent contract.

    This is structural validation. It proves that the document has the closed,
    bounded MSAP shape and references known capability identifiers. It does not
    authorize an audit, target, user, or eventual tool call.
    """

    if not isinstance(value, dict):
        raise AssessmentPlanContractError(
            "The canonical assessment plan must be a JSON object."
        )
    _bounded_json(value, MAX_PLAN_BYTES, "Canonical assessment plan")
    _require_exact_fields(value, PLAN_FIELDS, "Canonical assessment plan")
    if value["contract_version"] != ASSESSMENT_PLAN_CONTRACT_VERSION:
        raise AssessmentPlanContractError("Unsupported assessment plan contract version.")
    if (
        not isinstance(value["planner_provider"], str)
        or PROVIDER_ID_RE.fullmatch(value["planner_provider"]) is None
    ):
        raise AssessmentPlanContractError("Planner provider identity is invalid.")
    _bounded_text(value["planner_model"], 128, "Planner model")
    if isinstance(value["audit_id"], bool) or not isinstance(value["audit_id"], int) or value["audit_id"] < 1:
        raise AssessmentPlanContractError("Audit identity must be a positive integer.")
    if not isinstance(value["target_package"], str) or PACKAGE_NAME_RE.fullmatch(value["target_package"]) is None:
        raise AssessmentPlanContractError("Target package identity is invalid.")
    _bounded_safe_text(value["assessment_objective"], 500, "Assessment objective")
    _bounded_safe_text(value["scope"], 2000, "Assessment scope")
    _validate_constraints(value["constraints"])
    _validate_traceability(value["traceability"])

    steps = value["steps"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_PLAN_STEPS:
        raise AssessmentPlanContractError(
            f"Canonical plan must contain 1 to {MAX_PLAN_STEPS} steps."
        )
    identifiers: set[str] = set()
    canonical_steps: list[dict[str, Any]] = []
    for expected_sequence, raw_step in enumerate(steps, start=1):
        canonical_step = _validate_canonical_step(raw_step, expected_sequence)
        step_id = canonical_step["step_id"]
        if step_id in identifiers:
            raise AssessmentPlanContractError(
                "Canonical plan step identifiers must be unique."
            )
        identifiers.add(step_id)
        canonical_steps.append(canonical_step)

    by_id = {step["step_id"]: step for step in canonical_steps}
    for step in canonical_steps:
        unknown = sorted(set(step["dependencies"]) - set(by_id))
        if unknown:
            raise AssessmentPlanContractError(
                f"Step {step['step_id']} references an unknown dependency."
            )
    _validate_dependency_graph(by_id)
    sequence_by_id = {step["step_id"]: step["sequence"] for step in canonical_steps}
    for step in canonical_steps:
        if any(sequence_by_id[item] >= step["sequence"] for item in step["dependencies"]):
            raise AssessmentPlanContractError(
                "Canonical plan dependencies must reference earlier ordered steps."
            )

    normalized = deepcopy(value)
    normalized["steps"] = canonical_steps
    return normalized


def validate_value_against_schema(
    value: Any,
    schema: dict[str, Any],
    field: str,
) -> None:
    """Validate the small JSON-schema subset used by the real tool manifest."""

    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(value, dict):
            raise AssessmentPlanContractError(f"{field} must be an object.")
        properties = schema.get("properties", {})
        required = set(schema.get("required", []))
        missing = sorted(required - set(value))
        if missing:
            raise AssessmentPlanContractError(
                f"{field} is missing required arguments: {', '.join(missing)}."
            )
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                raise AssessmentPlanContractError(
                    f"{field} contains unknown arguments: {', '.join(unknown)}."
                )
        for key, item in value.items():
            if key in properties:
                validate_value_against_schema(item, properties[key], f"{field}.{key}")
        return
    if expected_type == "string":
        if not isinstance(value, str):
            raise AssessmentPlanContractError(f"{field} must be a string.")
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 1_000_000):
            raise AssessmentPlanContractError(f"{field} is outside the bounded length.")
        if "enum" in schema and value not in schema["enum"]:
            raise AssessmentPlanContractError(f"{field} is not an allowed value.")
        if "const" in schema and value != schema["const"]:
            raise AssessmentPlanContractError(
                f"{field} does not match the required confirmation value."
            )
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise AssessmentPlanContractError(
                f"{field} does not match the required safe format."
            )
        return
    if expected_type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise AssessmentPlanContractError(f"{field} must be an integer.")
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            raise AssessmentPlanContractError(f"{field} is outside the bounded range.")
        return
    if expected_type == "boolean":
        if not isinstance(value, bool):
            raise AssessmentPlanContractError(f"{field} must be a boolean.")
        if "const" in schema and value is not schema["const"]:
            raise AssessmentPlanContractError(
                f"{field} does not match the required confirmation value."
            )
        return
    raise AssessmentPlanContractError(
        f"{field} uses an unsupported planner schema type."
    )


def reject_unsafe_instruction(value: str, *, field: str) -> None:
    clauses = re.split(r"(?<=[.!?])\s+|[\r\n]+", value)
    for clause in clauses:
        if not any(pattern.search(clause) for pattern in UNSAFE_INSTRUCTION_PATTERNS):
            continue
        if (
            SAFE_PROHIBITION_PREFIX_RE.search(clause)
            and PROHIBITION_ESCAPE_RE.search(clause) is None
        ):
            continue
        raise AssessmentPlanContractError(
            f"{field} contains an unsupported execution instruction."
        )


def _validate_canonical_step(raw_step: Any, expected_sequence: int) -> dict[str, Any]:
    if not isinstance(raw_step, dict):
        raise AssessmentPlanContractError(
            "Every canonical assessment step must be a JSON object."
        )
    _require_exact_fields(raw_step, STEP_FIELDS, "Canonical plan step")
    if raw_step["sequence"] != expected_sequence or isinstance(raw_step["sequence"], bool):
        raise AssessmentPlanContractError(
            "Canonical plan step sequences must be contiguous and ordered from 1."
        )
    step_id = raw_step["step_id"]
    if not isinstance(step_id, str) or STEP_ID_RE.fullmatch(step_id) is None:
        raise AssessmentPlanContractError(
            "Canonical plan step identifiers must be stable lowercase identifiers."
        )
    action_id = raw_step["action_id"]
    if action_id not in ACTION_IDENTIFIERS:
        raise AssessmentPlanContractError("Canonical plan action identifier is unsupported.")
    objective = _bounded_safe_text(raw_step["objective"], 500, "Step objective")
    rationale = _bounded_safe_text(raw_step["rationale"], 2000, "Step rationale")
    tools = _validate_canonical_tools(raw_step["tools"])
    expected_action = ACTION_GATEWAY_TOOL_SEQUENCE if tools else ACTION_OBSERVATION_ANALYSIS
    if action_id != expected_action:
        raise AssessmentPlanContractError(
            "Canonical plan action identifier does not match its structured tools."
        )
    expected_observation = _bounded_safe_text(
        raw_step["expected_observation"], 1000, "Expected observation"
    )
    success_condition = _bounded_safe_text(
        raw_step["success_condition"], 1000, "Success condition"
    )
    evidence = raw_step["evidence_requirements"]
    if (
        not isinstance(evidence, list)
        or not 1 <= len(evidence) <= MAX_EVIDENCE_REQUIREMENTS
        or any(not isinstance(item, str) or item not in EVIDENCE_TYPES for item in evidence)
        or len(evidence) != len(set(evidence))
    ):
        raise AssessmentPlanContractError(
            "Evidence requirements must be unique bounded supported values."
        )
    dependencies = raw_step["dependencies"]
    if (
        not isinstance(dependencies, list)
        or len(dependencies) > MAX_PLAN_STEPS
        or any(not isinstance(item, str) or STEP_ID_RE.fullmatch(item) is None for item in dependencies)
        or len(dependencies) != len(set(dependencies))
    ):
        raise AssessmentPlanContractError(
            "Step dependencies must be unique stable identifiers."
        )
    if step_id in dependencies:
        raise AssessmentPlanContractError("A canonical plan step cannot depend on itself.")
    requires_approval = raw_step["requires_explicit_approval"]
    if not isinstance(requires_approval, bool):
        raise AssessmentPlanContractError(
            "Step explicit-approval requirement must be boolean."
        )
    expected_approval = any(tool["name"] == "clear_package_data" for tool in tools)
    if requires_approval is not expected_approval:
        raise AssessmentPlanContractError(
            "Step explicit-approval requirement does not match its capabilities."
        )
    _validate_resource_limits(raw_step["resource_limits"], tools)
    return {
        **deepcopy(raw_step),
        "objective": objective,
        "rationale": rationale,
        "tools": tools,
        "expected_observation": expected_observation,
        "success_condition": success_condition,
        "evidence_requirements": list(evidence),
        "dependencies": list(dependencies),
    }


def _validate_canonical_tools(tools: Any) -> list[dict[str, Any]]:
    if not isinstance(tools, list) or len(tools) > MAX_TOOLS_PER_STEP:
        raise AssessmentPlanContractError(
            f"Each canonical step may reference at most {MAX_TOOLS_PER_STEP} tools."
        )
    normalized: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for tool_call in tools:
        if not isinstance(tool_call, dict):
            raise AssessmentPlanContractError(
                "Canonical tool references must be structured JSON objects."
            )
        _require_exact_fields(tool_call, TOOL_CALL_FIELDS, "Canonical tool reference")
        name = tool_call["name"]
        if not isinstance(name, str) or name not in TOOL_MANIFEST:
            raise AssessmentPlanContractError(
                "The canonical plan references an unknown tool capability."
            )
        if name in seen_names:
            raise AssessmentPlanContractError(
                "A canonical step cannot reference the same tool more than once."
            )
        seen_names.add(name)
        arguments = tool_call["arguments"]
        if not isinstance(arguments, dict):
            raise AssessmentPlanContractError(f"Arguments for {name} must be an object.")
        _bounded_json(arguments, MAX_TOOL_ARGUMENT_BYTES, f"Arguments for {name}")
        validate_value_against_schema(
            arguments,
            TOOL_MANIFEST[name].input_schema,
            f"{name}.arguments",
        )
        if name == "frida_run_js" and arguments.get("source") not in APPROVED_FRIDA_SOURCE_IDENTIFIERS:
            raise AssessmentPlanContractError(
                "The planner contract permits only the controlled built-in Frida proof."
            )
        for argument_name, argument_value in arguments.items():
            if isinstance(argument_value, str) and not (
                name == "frida_run_js"
                and argument_name == "source"
                and argument_value in APPROVED_FRIDA_SOURCE_IDENTIFIERS
            ):
                reject_unsafe_instruction(
                    argument_value,
                    field=f"{name}.{argument_name}",
                )
        normalized.append({"name": name, "arguments": deepcopy(arguments)})
    return normalized


def _validate_constraints(value: Any) -> None:
    if not isinstance(value, dict):
        raise AssessmentPlanContractError("Plan constraints must be a JSON object.")
    _require_exact_fields(value, CONSTRAINT_FIELDS, "Plan constraints")
    expected = {
        "approval_required": True,
        "execution_channel": "RUN_SCOPED_TOOL_GATEWAY",
        "max_steps": MAX_PLAN_STEPS,
        "max_tools_per_step": MAX_TOOLS_PER_STEP,
        "max_argument_bytes": MAX_TOOL_ARGUMENT_BYTES,
    }
    if value != expected:
        raise AssessmentPlanContractError(
            "Canonical plan constraints cannot expand backend execution limits."
        )


def _validate_traceability(value: Any) -> None:
    if not isinstance(value, dict):
        raise AssessmentPlanContractError("Plan traceability must be a JSON object.")
    _require_exact_fields(value, TRACEABILITY_FIELDS, "Plan traceability")
    if any(not isinstance(value[field], str) or SHA256_RE.fullmatch(value[field]) is None for field in TRACEABILITY_FIELDS):
        raise AssessmentPlanContractError(
            "Plan traceability hashes must be SHA-256 values."
        )


def _validate_resource_limits(value: Any, tools: list[dict[str, Any]]) -> None:
    if not isinstance(value, dict):
        raise AssessmentPlanContractError("Step resource limits must be a JSON object.")
    _require_exact_fields(value, RESOURCE_LIMIT_FIELDS, "Step resource limits")
    expected_calls = len(tools)
    expected_timeout = sum(
        TOOL_MANIFEST[tool["name"]].timeout_seconds for tool in tools
    )
    if (
        value["max_tool_calls"] != expected_calls
        or isinstance(value["max_tool_calls"], bool)
        or value["max_total_timeout_seconds"] != expected_timeout
        or isinstance(value["max_total_timeout_seconds"], bool)
        or not 0 <= expected_timeout <= MAX_STEP_TIMEOUT_SECONDS
        or value["timeout_source"] != "TOOL_MANIFEST"
    ):
        raise AssessmentPlanContractError(
            "Step resource limits must be derived from the current tool manifest."
        )


def _bounded_safe_text(value: Any, max_length: int, field: str) -> str:
    text = _bounded_text(value, max_length, field)
    reject_unsafe_instruction(text, field=field)
    return text


def _bounded_text(value: Any, max_length: int, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise AssessmentPlanContractError(
            f"{field} must contain 1 to {max_length} characters."
        )
    if any(ord(character) < 32 and character not in "\n\t" for character in value):
        raise AssessmentPlanContractError(f"{field} contains control characters.")
    return value.strip()


def _bounded_json(value: Any, max_bytes: int, field: str) -> None:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise AssessmentPlanContractError(
            f"{field} must contain JSON-compatible values."
        ) from None
    if len(encoded) > max_bytes:
        raise AssessmentPlanContractError(f"{field} exceeds its bounded size limit.")


def _require_exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    unknown = sorted(set(value) - expected)
    missing = sorted(expected - set(value))
    if unknown:
        raise AssessmentPlanContractError(
            f"{label} contains unknown fields: {', '.join(unknown)}."
        )
    if missing:
        raise AssessmentPlanContractError(
            f"{label} is missing required fields: {', '.join(missing)}."
        )


def _validate_dependency_graph(steps: dict[str, dict[str, Any]]) -> None:
    state: dict[str, int] = {}

    def visit(step_id: str) -> None:
        if state.get(step_id) == 1:
            raise AssessmentPlanContractError(
                "Canonical plan dependencies must be acyclic."
            )
        if state.get(step_id) == 2:
            return
        state[step_id] = 1
        for dependency in steps[step_id]["dependencies"]:
            visit(dependency)
        state[step_id] = 2

    for identifier in steps:
        visit(identifier)

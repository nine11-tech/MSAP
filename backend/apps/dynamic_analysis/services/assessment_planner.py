from __future__ import annotations

from abc import ABC, abstractmethod
from copy import deepcopy
from hashlib import sha256
import json
import re
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.dynamic_analysis.models import AssessmentPlan, AssessmentPlanStep, DynamicDevice
from apps.dynamic_analysis.services.agent_tools import (
    BUILTIN_FRIDA_UI_PROOF,
    TOOL_MANIFEST,
    public_tool_manifest,
)
from apps.dynamic_analysis.services.assessment_execution_contract import (
    AssessmentExecutionContractError,
    validate_persisted_plan_contract,
)
from apps.dynamic_analysis.services.assessment_plan_contract import (
    EVIDENCE_TYPES,
    MAX_EVIDENCE_REQUIREMENTS,
    MAX_PLAN_BYTES,
    MAX_PLAN_STEPS,
    MAX_TOOL_ARGUMENT_BYTES,
    MAX_TOOLS_PER_STEP,
    AssessmentPlanContractError,
    normalize_assessment_plan_contract,
    reject_unsafe_instruction,
)
from apps.findings.models import Finding


MAX_CONTEXT_FINDINGS = 25
MAX_CONTEXT_APKS = 10
MAX_CONTEXT_DEVICES = 5
OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"

PLAN_FIELDS = {
    "target_package",
    "assessment_objective",
    "scope",
    "steps",
}
STEP_FIELDS = {
    "sequence",
    "step_id",
    "objective",
    "rationale",
    "tools",
    "expected_observation",
    "success_condition",
    "evidence_requirements",
    "dependencies",
}
TOOL_CALL_FIELDS = {"name", "arguments"}
STEP_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
PACKAGE_NAME_RE = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)+$"
)


class AssessmentPlannerError(RuntimeError):
    code = "ASSESSMENT_PLANNER_ERROR"
    http_status = 400

    def __init__(self, message: str, *, code: str | None = None, http_status: int | None = None):
        super().__init__(message)
        if code is not None:
            self.code = code
        if http_status is not None:
            self.http_status = http_status


class PlannerProviderError(AssessmentPlannerError):
    code = "PLANNER_PROVIDER_UNAVAILABLE"
    http_status = 502


class PlanValidationError(AssessmentPlannerError):
    code = "PLAN_VALIDATION_FAILED"
    http_status = 400


def _planner_tool_schema() -> dict[str, Any]:
    variants = []
    for name, spec in TOOL_MANIFEST.items():
        argument_schema = deepcopy(spec.input_schema)
        # Strict Structured Outputs requires object properties to be required.
        # This provider-facing schema is intentionally no looser than the real
        # gateway schema; backend policy validation still uses the original.
        properties = argument_schema.get("properties", {})
        if properties:
            argument_schema["required"] = list(properties)
        variants.append(
            {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "const": name},
                    "arguments": argument_schema,
                },
                "required": ["name", "arguments"],
                "additionalProperties": False,
            }
        )
    return {"anyOf": variants}


PLANNER_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "target_package": {"type": "string", "maxLength": 255},
        "assessment_objective": {"type": "string", "maxLength": 500},
        "scope": {"type": "string", "maxLength": 2000},
        "steps": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_PLAN_STEPS,
            "items": {
                "type": "object",
                "properties": {
                    "sequence": {"type": "integer", "minimum": 1, "maximum": MAX_PLAN_STEPS},
                    "step_id": {"type": "string", "pattern": STEP_ID_RE.pattern, "maxLength": 64},
                    "objective": {"type": "string", "maxLength": 500},
                    "rationale": {"type": "string", "maxLength": 2000},
                    "tools": {
                        "type": "array",
                        "maxItems": MAX_TOOLS_PER_STEP,
                        "items": _planner_tool_schema(),
                    },
                    "expected_observation": {"type": "string", "maxLength": 1000},
                    "success_condition": {"type": "string", "maxLength": 1000},
                    "evidence_requirements": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": MAX_EVIDENCE_REQUIREMENTS,
                        "items": {"type": "string", "enum": list(EVIDENCE_TYPES)},
                    },
                    "dependencies": {
                        "type": "array",
                        "maxItems": MAX_PLAN_STEPS,
                        "items": {"type": "string", "pattern": STEP_ID_RE.pattern, "maxLength": 64},
                    },
                },
                "required": sorted(STEP_FIELDS),
                "additionalProperties": False,
            },
        },
    },
    "required": sorted(PLAN_FIELDS),
    "additionalProperties": False,
}


class PlannerProvider(ABC):
    name: str
    model: str

    @abstractmethod
    def generate(self, planner_input: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError


class DeterministicPlannerProvider(PlannerProvider):
    name = AssessmentPlan.PlannerProvider.DETERMINISTIC
    model = "msap-deterministic-planner-v1"

    def generate(self, planner_input: dict[str, Any]) -> dict[str, Any]:
        audit_id = planner_input["audit"]["id"]
        package_name = planner_input["target_package"]
        objective = planner_input["assessment_objective"]
        scope = planner_input["scope"]
        return {
            "target_package": package_name,
            "assessment_objective": objective,
            "scope": scope,
            "steps": [
                {
                    "sequence": 1,
                    "step_id": "establish_readiness",
                    "objective": "Establish managed-device and target availability.",
                    "rationale": "A bounded readiness baseline prevents later observations from being attributed to an unavailable device or missing package.",
                    "tools": [
                        {"name": "get_device_status", "arguments": {}},
                        {"name": "list_packages", "arguments": {"include_system": False}},
                    ],
                    "expected_observation": "The managed Android device is reachable and the authorized target appears in the bounded package inventory.",
                    "success_condition": "Device readiness is reported and the target package can be identified without changing application state.",
                    "evidence_requirements": ["tool_output"],
                    "dependencies": [],
                },
                {
                    "sequence": 2,
                    "step_id": "capture_baseline",
                    "objective": "Launch the authorized target and capture its baseline visual state.",
                    "rationale": "A screenshot and parsed UI hierarchy provide comparison points for later runtime observations.",
                    "tools": [
                        {"name": "launch_package", "arguments": {"package_name": package_name}},
                        {
                            "name": "take_screenshot",
                            "arguments": {"capture_reason": "instrumentation_before", "audit_id": audit_id},
                        },
                        {"name": "dump_ui", "arguments": {"package_name": package_name}},
                    ],
                    "expected_observation": "The target is foregrounded with a non-empty screenshot and parsed UI hierarchy.",
                    "success_condition": "Foreground package, screenshot digest, UI digest, and non-zero UI node count are available.",
                    "evidence_requirements": ["screenshot", "ui_hierarchy", "tool_output"],
                    "dependencies": ["establish_readiness"],
                },
                {
                    "sequence": 3,
                    "step_id": "inspect_runtime",
                    "objective": "Confirm Frida availability and locate the target runtime process.",
                    "rationale": "Instrumentation should only be planned when the real client/server versions agree and the authorized process is observable.",
                    "tools": [
                        {"name": "frida_status", "arguments": {"package_name": package_name}},
                        {"name": "frida_ps", "arguments": {}},
                    ],
                    "expected_observation": "Frida RPC is connected and the target process has a real PID in the bounded process inventory.",
                    "success_condition": "Client/server agreement, attach capability, target PID, and process count are recorded.",
                    "evidence_requirements": ["tool_output"],
                    "dependencies": ["capture_baseline"],
                },
                {
                    "sequence": 4,
                    "step_id": "define_hypothesis",
                    "objective": "Define a bounded runtime instrumentation hypothesis from the available context.",
                    "rationale": "The future execution agent should test one observable proposition and must not infer a vulnerability from static context alone.",
                    "tools": [],
                    "expected_observation": "A testable proposition links an authorized runtime action to an expected visible and structured observation.",
                    "success_condition": "The hypothesis is evidence-oriented, bounded, and contains no vulnerability verdict.",
                    "evidence_requirements": ["tool_output"],
                    "dependencies": ["inspect_runtime"],
                },
                {
                    "sequence": 5,
                    "step_id": "test_instrumentation",
                    "objective": "Test the hypothesis with the controlled runtime UI modification proof.",
                    "rationale": "The built-in proof is an allowlisted instrumentation primitive that can demonstrate code execution inside the selected application process.",
                    "tools": [
                        {
                            "name": "frida_attach",
                            "arguments": {"package_name": package_name, "mode": "attach", "timeout": 10},
                        },
                        {
                            "name": "frida_run_js",
                            "arguments": {
                                "package_name": package_name,
                                "mode": "attach",
                                "source": BUILTIN_FRIDA_UI_PROOF,
                                "timeout": 12,
                                "capture_logcat": True,
                                "capture_screenshot": False,
                            },
                        },
                    ],
                    "expected_observation": "Attach succeeds and a structured ui_modification event reports a verified visible property change.",
                    "success_condition": "The script starts, loads, emits the expected structured event, completes, and detaches cleanly.",
                    "evidence_requirements": ["frida_events", "logcat", "tool_output"],
                    "dependencies": ["define_hypothesis"],
                },
                {
                    "sequence": 6,
                    "step_id": "compare_evidence",
                    "objective": "Capture the resulting state and compare it with the baseline.",
                    "rationale": "Before/after digests and visible UI values provide stronger evidence than a successful process return alone.",
                    "tools": [
                        {
                            "name": "take_screenshot",
                            "arguments": {"capture_reason": "instrumentation_after", "audit_id": audit_id},
                        },
                        {"name": "dump_ui", "arguments": {"package_name": package_name}},
                        {"name": "force_stop_package", "arguments": {"package_name": package_name}},
                    ],
                    "expected_observation": "Before/after screenshot or UI digests differ consistently with the Frida event, and bounded log evidence is available.",
                    "success_condition": "The evidence comparison is complete, cleanup succeeds, and no vulnerability verdict is asserted.",
                    "evidence_requirements": [
                        "screenshot",
                        "ui_hierarchy",
                        "logcat",
                        "frida_events",
                        "before_after_comparison",
                    ],
                    "dependencies": ["test_instrumentation"],
                },
            ],
        }


class OpenAIPlannerProvider(PlannerProvider):
    name = AssessmentPlan.PlannerProvider.OPENAI

    def __init__(self, *, opener=None):
        self.model = settings.MSAP_ASSESSMENT_PLANNER_MODEL
        self._opener = opener or urllib_request.urlopen

    def generate(self, planner_input: dict[str, Any]) -> dict[str, Any]:
        api_key = settings.MSAP_ASSESSMENT_PLANNER_OPENAI_API_KEY
        if not api_key:
            raise PlannerProviderError(
                "The OpenAI assessment planner is not configured.",
                code="PLANNER_PROVIDER_NOT_CONFIGURED",
                http_status=503,
            )
        payload = {
            "model": self.model,
            "input": [
                {
                    "role": "system",
                    "content": [
                        {
                            "type": "input_text",
                            "text": (
                                "You are the MSAP assessment planner. Produce a plan only. "
                                "Never execute tools, request credentials, provide commands, "
                                "or reference capabilities outside the supplied manifest. "
                                "Do not assert vulnerability or malware verdicts."
                            ),
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": json.dumps(planner_input, sort_keys=True, separators=(",", ":")),
                        }
                    ],
                },
            ],
            "reasoning": {"effort": settings.MSAP_ASSESSMENT_PLANNER_REASONING_EFFORT},
            "max_output_tokens": settings.MSAP_ASSESSMENT_PLANNER_MAX_OUTPUT_TOKENS,
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "msap_assessment_plan",
                    "schema": PLANNER_OUTPUT_SCHEMA,
                    "strict": True,
                }
            },
        }
        request = urllib_request.Request(
            OPENAI_RESPONSES_URL,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with self._opener(
                request,
                timeout=settings.MSAP_ASSESSMENT_PLANNER_TIMEOUT_SECONDS,
            ) as response:
                raw_response = response.read(MAX_PLAN_BYTES * 2)
        except (urllib_error.HTTPError, urllib_error.URLError, TimeoutError, OSError):
            raise PlannerProviderError(
                "The configured planner provider did not return a usable plan."
            ) from None
        try:
            response_data = json.loads(raw_response.decode("utf-8"))
            output_text = _response_output_text(response_data)
            generated = json.loads(output_text)
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            raise PlannerProviderError(
                "The configured planner provider returned malformed structured output.",
                code="PLANNER_PROVIDER_INVALID_RESPONSE",
            ) from None
        if not isinstance(generated, dict):
            raise PlannerProviderError(
                "The configured planner provider returned malformed structured output.",
                code="PLANNER_PROVIDER_INVALID_RESPONSE",
            )
        return generated


class AssessmentPlannerService:
    def __init__(self, provider: PlannerProvider | None = None):
        self.provider = provider or configured_planner_provider()

    def generate(
        self,
        *,
        audit: Audit,
        target_package: str,
        objective: str,
        scope: str,
        requested_by,
    ) -> AssessmentPlan:
        target_package = _validated_target_package(audit, target_package)
        objective = _safe_text("assessment_objective", objective, max_length=500)
        scope = _safe_text("scope", scope, max_length=2000)
        planner_input = build_planner_input(
            audit=audit,
            target_package=target_package,
            objective=objective,
            scope=scope,
        )
        input_hash = _json_hash(planner_input)
        try:
            generated = self.provider.generate(planner_input)
        except AssessmentPlannerError:
            raise
        except Exception:
            raise PlannerProviderError(
                "The configured planner provider failed unexpectedly."
            ) from None
        normalized = validate_generated_plan(
            generated,
            audit=audit,
            target_package=target_package,
            objective=objective,
            scope=scope,
            planner_provider=self.provider.name,
            planner_model=self.provider.model,
            planner_input_hash=input_hash,
        )
        with transaction.atomic():
            plan = AssessmentPlan.objects.create(
                audit=audit,
                target_package=target_package,
                planner_provider=self.provider.name,
                planner_model=self.provider.model,
                objective=objective,
                scope=scope,
                status=AssessmentPlan.Status.GENERATED,
                validation_status=AssessmentPlan.ValidationStatus.PASSED,
                generated_plan=generated,
                normalized_plan=normalized,
                planner_input_hash=input_hash,
                plan_hash=_json_hash(normalized),
                validation_errors=[],
                created_by=requested_by,
            )
            _replace_plan_steps(plan, normalized, status=AssessmentPlanStep.Status.PROPOSED)
        return plan

    def validate(self, plan: AssessmentPlan) -> AssessmentPlan:
        if plan.status not in {
            AssessmentPlan.Status.GENERATED,
            AssessmentPlan.Status.VALIDATED,
        }:
            raise PlanValidationError(
                "Only a generated assessment plan can be validated.",
                code="PLAN_STATE_INVALID",
            )
        try:
            normalized = validate_generated_plan(
                plan.generated_plan,
                audit=plan.audit,
                target_package=plan.target_package,
                objective=plan.objective,
                scope=plan.scope,
                planner_provider=plan.planner_provider,
                planner_model=plan.planner_model,
                planner_input_hash=plan.planner_input_hash,
            )
        except PlanValidationError as exc:
            plan.status = AssessmentPlan.Status.REJECTED
            plan.validation_status = AssessmentPlan.ValidationStatus.FAILED
            plan.validation_errors = [str(exc)[:500]]
            plan.validated_at = timezone.now()
            plan.save(
                update_fields=[
                    "status",
                    "validation_status",
                    "validation_errors",
                    "validated_at",
                    "updated_at",
                ]
            )
            raise
        with transaction.atomic():
            plan.normalized_plan = normalized
            plan.plan_hash = _json_hash(normalized)
            plan.status = AssessmentPlan.Status.VALIDATED
            plan.validation_status = AssessmentPlan.ValidationStatus.PASSED
            plan.validation_errors = []
            plan.validated_at = timezone.now()
            plan.save(
                update_fields=[
                    "normalized_plan",
                    "plan_hash",
                    "status",
                    "validation_status",
                    "validation_errors",
                    "validated_at",
                    "updated_at",
                ]
            )
            _replace_plan_steps(
                plan,
                normalized,
                status=AssessmentPlanStep.Status.VALIDATED,
            )
        return plan

    @staticmethod
    def approve(plan: AssessmentPlan, *, approved_by) -> AssessmentPlan:
        # Preserve the existing idempotent approval behavior. Historical plans
        # remain readable; only a new VALIDATED -> APPROVED transition must pass
        # the D1 canonical integrity gate.
        if plan.status == AssessmentPlan.Status.APPROVED:
            return plan
        if (
            plan.status != AssessmentPlan.Status.VALIDATED
            or plan.validation_status != AssessmentPlan.ValidationStatus.PASSED
        ):
            raise PlanValidationError(
                "Only a validated assessment plan can be approved.",
                code="PLAN_NOT_VALIDATED",
            )
        try:
            validate_persisted_plan_contract(plan)
        except AssessmentExecutionContractError:
            raise PlanValidationError(
                "The validated assessment plan failed its canonical integrity check.",
                code="PLAN_CONTRACT_INVALID",
            ) from None
        with transaction.atomic():
            plan.status = AssessmentPlan.Status.APPROVED
            plan.approved_by = approved_by
            plan.approved_at = timezone.now()
            plan.save(
                update_fields=["status", "approved_by", "approved_at", "updated_at"]
            )
            plan.steps.update(status=AssessmentPlanStep.Status.APPROVED)
        return plan


def configured_planner_provider() -> PlannerProvider:
    provider_name = settings.MSAP_ASSESSMENT_PLANNER_PROVIDER.upper()
    if provider_name == AssessmentPlan.PlannerProvider.DETERMINISTIC:
        return DeterministicPlannerProvider()
    if provider_name == AssessmentPlan.PlannerProvider.OPENAI:
        return OpenAIPlannerProvider()
    raise PlannerProviderError(
        "The configured assessment planner provider is unsupported.",
        code="PLANNER_PROVIDER_UNSUPPORTED",
        http_status=503,
    )


def build_planner_input(
    *,
    audit: Audit,
    target_package: str,
    objective: str,
    scope: str,
) -> dict[str, Any]:
    apk_rows = list(
        APKFile.objects.filter(audit=audit, package_name=target_package)
        .select_related("storage_reference")
        .order_by("-created_at")[:MAX_CONTEXT_APKS]
    )
    findings = list(
        Finding.objects.filter(audit=audit)
        .order_by("-created_at")
        .values(
            "rule_id",
            "title",
            "severity",
            "confidence",
            "category",
            "requires_manual_validation",
        )[:MAX_CONTEXT_FINDINGS]
    )
    devices = list(
        DynamicDevice.objects.order_by("-last_seen_at", "serial")[:MAX_CONTEXT_DEVICES]
    )
    return {
        "planner_mode": "PLAN_ONLY",
        "audit": {
            "id": audit.id,
            "name": audit.name[:255],
            "status": audit.status,
            "project_id": audit.project_id,
        },
        "target_package": target_package,
        "assessment_objective": objective,
        "scope": scope,
        "available_tools": public_tool_manifest(),
        "device_capabilities": [
            {
                "serial": device.serial,
                "status": device.status,
                "android_version": device.android_version or "unavailable",
                "api_level": device.api_level,
                "abi": device.abi,
                "root_available": device.is_rooted,
                "selinux": device.selinux_mode or "unavailable",
                "frida_available": device.has_frida,
                "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
            }
            for device in devices
        ],
        "apk_context": [
            {
                "apk_file_id": apk.id,
                "package_name": apk.package_name,
                "version_name": apk.version_name or "unavailable",
                "sha256": apk.sha256 or "unavailable",
                "size_bytes": apk.size_bytes,
                "storage_status": (
                    apk.storage_reference.storage_status
                    if apk.storage_reference_id
                    else "unavailable"
                ),
            }
            for apk in apk_rows
        ],
        "existing_findings": findings,
        "context_availability": {
            "device_capabilities": bool(devices),
            "apk_context": bool(apk_rows),
            "existing_findings": bool(findings),
        },
        "planner_constraints": {
            "maximum_steps": MAX_PLAN_STEPS,
            "allowed_evidence_types": list(EVIDENCE_TYPES),
            "tool_execution_permitted": False,
            "vulnerability_verdict_permitted": False,
        },
    }


def validate_generated_plan(
    generated: Any,
    *,
    audit: Audit,
    target_package: str,
    objective: str,
    scope: str,
    planner_provider: str = "LEGACY_ADAPTER",
    planner_model: str = "legacy-structured-planner",
    planner_input_hash: str | None = None,
) -> dict[str, Any]:
    """Validate untrusted provider intent and return the canonical v1 plan.

    The first phase below is schema/shape validation. Contextual audit, target,
    and destructive-operation checks are deliberately delegated to
    ``validate_plan_policy`` before the legacy intent is adapted to the stable
    planner/executor contract.
    """

    if not isinstance(generated, dict):
        raise PlanValidationError("Planner output must be a JSON object.")
    try:
        serialized = json.dumps(generated, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        raise PlanValidationError("Planner output must contain JSON-compatible values.") from None
    if len(serialized.encode("utf-8")) > MAX_PLAN_BYTES:
        raise PlanValidationError("Planner output exceeds the bounded size limit.")
    _require_exact_fields(generated, PLAN_FIELDS, "plan")
    generated_package = _safe_text(
        "target_package", generated["target_package"], max_length=255
    )
    if PACKAGE_NAME_RE.fullmatch(generated_package) is None:
        raise PlanValidationError("Invalid Android package name.")
    _safe_text("assessment_objective", generated["assessment_objective"], max_length=500)
    _safe_text("scope", generated["scope"], max_length=2000)
    steps = generated["steps"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_PLAN_STEPS:
        raise PlanValidationError(f"Plan must contain 1 to {MAX_PLAN_STEPS} steps.")

    normalized_steps = []
    identifiers: set[str] = set()
    sequences: set[int] = set()
    for raw_step in steps:
        if not isinstance(raw_step, dict):
            raise PlanValidationError("Every plan step must be a JSON object.")
        _require_exact_fields(raw_step, STEP_FIELDS, "plan step")
        sequence = raw_step["sequence"]
        if isinstance(sequence, bool) or not isinstance(sequence, int) or not 1 <= sequence <= len(steps):
            raise PlanValidationError("Step sequence must be a bounded positive integer.")
        if sequence in sequences:
            raise PlanValidationError("Plan step sequences must be unique.")
        sequences.add(sequence)
        step_id = raw_step["step_id"]
        if not isinstance(step_id, str) or not STEP_ID_RE.fullmatch(step_id):
            raise PlanValidationError("Plan step identifiers must be stable lowercase identifiers.")
        if step_id in identifiers:
            raise PlanValidationError("Plan step identifiers must be unique.")
        identifiers.add(step_id)
        normalized_tools = _validate_step_tools(raw_step["tools"])
        evidence = raw_step["evidence_requirements"]
        if (
            not isinstance(evidence, list)
            or not 1 <= len(evidence) <= MAX_EVIDENCE_REQUIREMENTS
            or any(not isinstance(item, str) or item not in EVIDENCE_TYPES for item in evidence)
            or len(evidence) != len(set(evidence))
        ):
            raise PlanValidationError("Evidence requirements must be unique bounded supported values.")
        dependencies = raw_step["dependencies"]
        if (
            not isinstance(dependencies, list)
            or len(dependencies) > MAX_PLAN_STEPS
            or any(not isinstance(item, str) or not STEP_ID_RE.fullmatch(item) for item in dependencies)
            or len(dependencies) != len(set(dependencies))
        ):
            raise PlanValidationError("Step dependencies must be unique stable identifiers.")
        if step_id in dependencies:
            raise PlanValidationError("A plan step cannot depend on itself.")
        normalized_steps.append(
            {
                "sequence": sequence,
                "step_id": step_id,
                "objective": _safe_text("step objective", raw_step["objective"], max_length=500),
                "rationale": _safe_text("step rationale", raw_step["rationale"], max_length=2000),
                "tools": normalized_tools,
                "expected_observation": _safe_text(
                    "expected observation", raw_step["expected_observation"], max_length=1000
                ),
                "success_condition": _safe_text(
                    "success condition", raw_step["success_condition"], max_length=1000
                ),
                "evidence_requirements": list(evidence),
                "dependencies": list(dependencies),
            }
        )

    normalized_steps.sort(key=lambda item: item["sequence"])
    if [step["sequence"] for step in normalized_steps] != list(range(1, len(steps) + 1)):
        raise PlanValidationError("Plan step sequences must be contiguous from 1.")
    by_id = {step["step_id"]: step for step in normalized_steps}
    for step in normalized_steps:
        unknown = sorted(set(step["dependencies"]) - set(by_id))
        if unknown:
            raise PlanValidationError(
                f"Step {step['step_id']} references an unknown dependency."
            )
    _validate_dependency_graph(by_id)
    sequence_by_id = {step["step_id"]: step["sequence"] for step in normalized_steps}
    for step in normalized_steps:
        if any(sequence_by_id[item] >= step["sequence"] for item in step["dependencies"]):
            raise PlanValidationError("Plan dependencies must reference earlier ordered steps.")
    normalized_intent = {
        "target_package": generated_package,
        "assessment_objective": generated["assessment_objective"].strip(),
        "scope": generated["scope"].strip(),
        "steps": normalized_steps,
    }
    validate_plan_policy(
        normalized_intent,
        audit=audit,
        target_package=target_package,
        objective=objective,
        scope=scope,
    )
    if planner_input_hash is None:
        planner_input_hash = _json_hash(
            {
                "audit_id": audit.id,
                "target_package": target_package,
                "assessment_objective": objective,
                "scope": scope,
            }
        )
    try:
        return normalize_assessment_plan_contract(
            normalized_intent,
            audit_id=audit.id,
            planner_provider=planner_provider,
            planner_model=planner_model,
            planner_input_hash=planner_input_hash,
        )
    except AssessmentPlanContractError as exc:
        raise PlanValidationError(str(exc)) from None


def validate_plan_policy(
    normalized_intent: dict[str, Any],
    *,
    audit: Audit,
    target_package: str,
    objective: str,
    scope: str,
) -> None:
    """Apply current audit/target/tool policy after structural validation.

    This D1 boundary intentionally remains smaller than the future D3 policy
    engine. In particular, recognizing a capability identifier here is never
    permission to execute it through the gateway.
    """

    _validated_target_package(audit, target_package)
    if normalized_intent["target_package"] != target_package:
        raise PlanValidationError(
            "Planner target package does not match the authorized package."
        )
    if normalized_intent["assessment_objective"] != objective:
        raise PlanValidationError(
            "Planner objective does not match the requested objective."
        )
    if normalized_intent["scope"] != scope:
        raise PlanValidationError("Planner scope does not match the requested scope.")
    for step in normalized_intent["steps"]:
        for tool_call in step["tools"]:
            _validate_tool_policy(
                tool_call["name"],
                tool_call["arguments"],
                audit=audit,
                target_package=target_package,
                objective=objective,
                scope=scope,
            )


def _validate_step_tools(
    tools: Any,
) -> list[dict[str, Any]]:
    if not isinstance(tools, list) or len(tools) > MAX_TOOLS_PER_STEP:
        raise PlanValidationError(
            f"Each step may reference at most {MAX_TOOLS_PER_STEP} tools."
        )
    normalized = []
    seen_names: set[str] = set()
    for tool_call in tools:
        if not isinstance(tool_call, dict):
            raise PlanValidationError("Planned tools must be structured JSON objects.")
        _require_exact_fields(tool_call, TOOL_CALL_FIELDS, "planned tool")
        name = tool_call["name"]
        if not isinstance(name, str) or name not in TOOL_MANIFEST:
            raise PlanValidationError("The plan references a tool outside the gateway allowlist.")
        if name in seen_names:
            raise PlanValidationError("A plan step cannot reference the same tool more than once.")
        seen_names.add(name)
        arguments = tool_call["arguments"]
        if not isinstance(arguments, dict):
            raise PlanValidationError(f"Arguments for {name} must be a JSON object.")
        try:
            argument_size = len(
                json.dumps(
                    arguments,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("utf-8")
            )
        except (TypeError, ValueError):
            raise PlanValidationError(
                f"Arguments for {name} must contain JSON-compatible values."
            ) from None
        if argument_size > MAX_TOOL_ARGUMENT_BYTES:
            raise PlanValidationError(
                f"Arguments for {name} exceed the bounded size limit."
            )
        _validate_value_against_schema(arguments, TOOL_MANIFEST[name].input_schema, f"{name}.arguments")
        normalized.append({"name": name, "arguments": deepcopy(arguments)})
    return normalized


def _validate_tool_policy(
    name: str,
    arguments: dict[str, Any],
    *,
    audit: Audit,
    target_package: str,
    objective: str,
    scope: str,
) -> None:
    package_argument = arguments.get("package_name")
    if package_argument is not None and package_argument != target_package:
        raise PlanValidationError(f"{name} must target the audit-authorized package.")
    audit_id = arguments.get("audit_id")
    if audit_id is not None and audit_id != audit.id:
        raise PlanValidationError(f"{name} must use the selected audit.")
    apk_file_id = arguments.get("apk_file_id")
    if apk_file_id is not None and not APKFile.objects.filter(pk=apk_file_id, audit=audit).exists():
        raise PlanValidationError("Planned APK installation must reference an APK owned by the audit.")
    if name == "frida_run_js" and arguments.get("source") != BUILTIN_FRIDA_UI_PROOF:
        raise PlanValidationError(
            "The planner may reference only the controlled built-in Frida proof script."
        )
    if name == "clear_package_data":
        destructive_scope = re.search(
            r"\b(?:clear|reset|erase)\b.{0,40}\b(?:data|state)\b",
            f"{objective} {scope}",
            re.IGNORECASE,
        )
        if arguments.get("confirm") is not True or destructive_scope is None:
            raise PlanValidationError(
                "clear_package_data requires explicit objective-controlled data-reset scope."
            )
    for key, value in arguments.items():
        if isinstance(value, str) and not (
            name == "frida_run_js" and key == "source" and value == BUILTIN_FRIDA_UI_PROOF
        ):
            _reject_unsafe_instructions(value, field=f"{name}.{key}")


def _validate_value_against_schema(value: Any, schema: dict[str, Any], field: str) -> None:
    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(value, dict):
            raise PlanValidationError(f"{field} must be an object.")
        properties = schema.get("properties", {})
        required = set(schema.get("required", []))
        missing = sorted(required - set(value))
        if missing:
            raise PlanValidationError(f"{field} is missing required arguments: {', '.join(missing)}.")
        if schema.get("additionalProperties") is False:
            unknown = sorted(set(value) - set(properties))
            if unknown:
                raise PlanValidationError(f"{field} contains unknown arguments: {', '.join(unknown)}.")
        for key, item in value.items():
            if key in properties:
                _validate_value_against_schema(item, properties[key], f"{field}.{key}")
        return
    if expected_type == "string":
        if not isinstance(value, str):
            raise PlanValidationError(f"{field} must be a string.")
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 1_000_000):
            raise PlanValidationError(f"{field} is outside the bounded length.")
        if "enum" in schema and value not in schema["enum"]:
            raise PlanValidationError(f"{field} is not an allowed value.")
        if "const" in schema and value != schema["const"]:
            raise PlanValidationError(f"{field} does not match the required confirmation value.")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise PlanValidationError(f"{field} does not match the required safe format.")
        return
    if expected_type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise PlanValidationError(f"{field} must be an integer.")
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            raise PlanValidationError(f"{field} is outside the bounded range.")
        return
    if expected_type == "boolean":
        if not isinstance(value, bool):
            raise PlanValidationError(f"{field} must be a boolean.")
        if "const" in schema and value is not schema["const"]:
            raise PlanValidationError(f"{field} does not match the required confirmation value.")
        return
    raise PlanValidationError(f"{field} uses an unsupported planner schema type.")


def _validated_target_package(audit: Audit, target_package: str) -> str:
    if not isinstance(target_package, str) or not PACKAGE_NAME_RE.fullmatch(target_package):
        raise PlanValidationError("Invalid Android package name.")
    if not APKFile.objects.filter(audit=audit, package_name=target_package).exists():
        raise PlanValidationError(
            "The target package is not authorized by the selected audit.",
            code="UNAUTHORIZED_TARGET_PACKAGE",
        )
    return target_package


def _safe_text(field: str, value: Any, *, max_length: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise PlanValidationError(f"{field} must contain 1 to {max_length} characters.")
    if any(ord(character) < 32 and character not in "\n\t" for character in value):
        raise PlanValidationError(f"{field} contains control characters.")
    _reject_unsafe_instructions(value, field=field)
    return value.strip()


def _reject_unsafe_instructions(value: str, *, field: str) -> None:
    try:
        reject_unsafe_instruction(value, field=field)
    except AssessmentPlanContractError as exc:
        raise PlanValidationError(str(exc)) from None


def _require_exact_fields(value: dict[str, Any], expected: set[str], label: str) -> None:
    unknown = sorted(set(value) - expected)
    missing = sorted(expected - set(value))
    if unknown:
        raise PlanValidationError(f"{label} contains unknown fields: {', '.join(unknown)}.")
    if missing:
        raise PlanValidationError(f"{label} is missing required fields: {', '.join(missing)}.")


def _validate_dependency_graph(steps: dict[str, dict[str, Any]]) -> None:
    state: dict[str, int] = {}

    def visit(step_id: str) -> None:
        if state.get(step_id) == 1:
            raise PlanValidationError("Plan dependencies must be acyclic.")
        if state.get(step_id) == 2:
            return
        state[step_id] = 1
        for dependency in steps[step_id]["dependencies"]:
            visit(dependency)
        state[step_id] = 2

    for identifier in steps:
        visit(identifier)


def _replace_plan_steps(
    plan: AssessmentPlan,
    normalized: dict[str, Any],
    *,
    status: str,
) -> None:
    plan.steps.all().delete()
    AssessmentPlanStep.objects.bulk_create(
        [
            AssessmentPlanStep(
                plan=plan,
                sequence=step["sequence"],
                step_identifier=step["step_id"],
                objective=step["objective"],
                rationale=step["rationale"],
                required_tools=[tool["name"] for tool in step["tools"]],
                tool_arguments={tool["name"]: tool["arguments"] for tool in step["tools"]},
                expected_observation=step["expected_observation"],
                success_condition=step["success_condition"],
                evidence_requirements=step["evidence_requirements"],
                dependencies=step["dependencies"],
                status=status,
            )
            for step in normalized["steps"]
        ]
    )


def _response_output_text(response_data: dict[str, Any]) -> str:
    for item in response_data.get("output", []):
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []):
            if isinstance(content, dict) and content.get("type") == "output_text":
                text = content.get("text")
                if isinstance(text, str) and text:
                    return text
    raise ValueError("No structured output text")


def _json_hash(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(canonical.encode("utf-8")).hexdigest()

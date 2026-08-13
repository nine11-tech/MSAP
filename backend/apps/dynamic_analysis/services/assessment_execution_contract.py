from __future__ import annotations

from copy import deepcopy
from typing import Any

from apps.dynamic_analysis.models import AssessmentPlan
from apps.dynamic_analysis.services.assessment_plan_contract import (
    ASSESSMENT_PLAN_CONTRACT_VERSION,
    AssessmentPlanContractError,
    canonical_json_hash,
    validate_canonical_assessment_plan,
)


APPROVED_EXECUTION_CONTRACT_VERSION = "msap.approved-assessment-plan/v1"
APPROVED_CONTRACT_FIELDS = {
    "contract_version",
    "assessment_plan_contract_version",
    "plan_id",
    "plan_hash",
    "approved_at",
    "approved_by_id",
    "execution_boundary",
    "approved_plan",
}
EXECUTION_BOUNDARY = {
    "channel": "RUN_SCOPED_TOOL_GATEWAY",
    "tool_authorization_required": True,
    "tool_identifiers_are_permissions": False,
    "raw_text_execution_permitted": False,
}


class AssessmentExecutionContractError(ValueError):
    """An approved plan cannot safely be projected for a future executor."""


def validate_persisted_plan_contract(plan: Any) -> dict[str, Any]:
    """Validate canonical-plan integrity without granting execution permission."""

    persisted = _persisted_plan(plan)
    return _validate_persisted_record(persisted)


def build_approved_execution_contract(plan: Any) -> dict[str, Any]:
    """Build the only contract shape a future execution agent may consume.

    The function accepts a validated database model only. It deliberately does
    not parse provider output or raw LLM text, execute tools, or authorize any
    individual tool call. Every eventual call remains subject to the existing
    run-scoped gateway, RBAC, manifest schema, and audit policy checks.
    """

    persisted = _persisted_plan(plan)
    canonical = _validate_persisted_record(persisted)
    if (
        persisted.status != AssessmentPlan.Status.APPROVED
        or persisted.validation_status != AssessmentPlan.ValidationStatus.PASSED
        or persisted.policy_status != AssessmentPlan.PolicyStatus.PASSED
        or persisted.approved_by_id is None
        or persisted.approved_at is None
    ):
        raise AssessmentExecutionContractError(
            "Only an explicitly approved assessment plan can become executor input."
        )
    return {
        "contract_version": APPROVED_EXECUTION_CONTRACT_VERSION,
        "assessment_plan_contract_version": canonical["contract_version"],
        "plan_id": persisted.pk,
        "plan_hash": persisted.plan_hash,
        "approved_at": persisted.approved_at.isoformat(),
        "approved_by_id": persisted.approved_by_id,
        "execution_boundary": deepcopy(EXECUTION_BOUNDARY),
        "approved_plan": deepcopy(canonical),
    }


def validate_approved_execution_contract(value: Any) -> dict[str, Any]:
    """Validate the immutable executor input without consulting raw planner output."""

    if not isinstance(value, dict) or set(value) != APPROVED_CONTRACT_FIELDS:
        raise AssessmentExecutionContractError(
            "The approved execution contract has an invalid closed shape."
        )
    if value.get("contract_version") != APPROVED_EXECUTION_CONTRACT_VERSION:
        raise AssessmentExecutionContractError(
            "The approved execution contract version is unsupported."
        )
    if value.get("assessment_plan_contract_version") != ASSESSMENT_PLAN_CONTRACT_VERSION:
        raise AssessmentExecutionContractError(
            "The assessment plan contract version is unsupported."
        )
    plan_id = value.get("plan_id")
    approved_by_id = value.get("approved_by_id")
    if (
        isinstance(plan_id, bool)
        or not isinstance(plan_id, int)
        or plan_id < 1
        or isinstance(approved_by_id, bool)
        or not isinstance(approved_by_id, int)
        or approved_by_id < 1
    ):
        raise AssessmentExecutionContractError(
            "The approved execution contract identity is invalid."
        )
    if value.get("execution_boundary") != EXECUTION_BOUNDARY:
        raise AssessmentExecutionContractError(
            "The approved execution contract cannot expand its execution boundary."
        )
    canonical = validate_canonical_assessment_plan(value.get("approved_plan"))
    plan_hash = value.get("plan_hash")
    if not isinstance(plan_hash, str) or canonical_json_hash(canonical) != plan_hash:
        raise AssessmentExecutionContractError(
            "The approved execution contract failed its integrity check."
        )
    if canonical["contract_version"] != value["assessment_plan_contract_version"]:
        raise AssessmentExecutionContractError(
            "The approved execution contract contains inconsistent versions."
        )
    return deepcopy(value)


def approved_tool_call_for_run_step(run: Any, step: Any) -> dict[str, Any]:
    """Resolve one exact call from a stored approved contract and run-step identity."""

    contract = validate_approved_execution_contract(run.execution_contract)
    if (
        contract["plan_id"] != run.assessment_plan_id
        or contract["plan_hash"] != run.approved_plan_hash
    ):
        raise AssessmentExecutionContractError(
            "The agent run does not match its approved plan contract."
        )
    plan_step = next(
        (
            item
            for item in contract["approved_plan"]["steps"]
            if item["step_id"] == step.plan_step_identifier
        ),
        None,
    )
    if plan_step is None or plan_step["sequence"] != step.plan_step_sequence:
        raise AssessmentExecutionContractError(
            "The agent run step is not present in the approved plan."
        )
    index = step.tool_call_index - 1
    tools = plan_step["tools"]
    if step.is_control_step or index < 0 or index >= len(tools):
        raise AssessmentExecutionContractError(
            "The agent run step is not an executable approved tool call."
        )
    return deepcopy(tools[index])


def _persisted_plan(plan: Any) -> AssessmentPlan:
    if not isinstance(plan, AssessmentPlan):
        raise AssessmentExecutionContractError(
            "Executor input must be a persisted AssessmentPlan, not raw planner text."
        )
    if plan.pk is None:
        raise AssessmentExecutionContractError(
            "Executor input must be a persisted AssessmentPlan."
        )
    try:
        return AssessmentPlan.objects.get(pk=plan.pk)
    except AssessmentPlan.DoesNotExist:
        raise AssessmentExecutionContractError(
            "Executor input must reference an existing AssessmentPlan."
        ) from None


def _validate_persisted_record(plan: AssessmentPlan) -> dict[str, Any]:
    try:
        canonical = validate_canonical_assessment_plan(plan.normalized_plan)
    except AssessmentPlanContractError as exc:
        raise AssessmentExecutionContractError(
            "The persisted assessment plan contract is invalid."
        ) from exc
    if canonical["contract_version"] != ASSESSMENT_PLAN_CONTRACT_VERSION:
        raise AssessmentExecutionContractError(
            "The persisted assessment plan contract version is unsupported."
        )
    if (
        canonical["audit_id"] != plan.audit_id
        or canonical["target_package"] != plan.target_package
        or canonical["assessment_objective"] != plan.objective
        or canonical["scope"] != plan.scope
        or canonical["planner_provider"] != plan.planner_provider
        or canonical["planner_model"] != plan.planner_model
        or canonical["traceability"]["planner_input_hash"]
        != plan.planner_input_hash
    ):
        raise AssessmentExecutionContractError(
            "The persisted assessment plan does not match its canonical contract."
        )
    if not plan.plan_hash or canonical_json_hash(canonical) != plan.plan_hash:
        raise AssessmentExecutionContractError(
            "The persisted assessment plan failed its integrity check."
        )
    return canonical

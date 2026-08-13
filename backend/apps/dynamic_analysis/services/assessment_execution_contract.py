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
        "execution_boundary": {
            "channel": "RUN_SCOPED_TOOL_GATEWAY",
            "tool_authorization_required": True,
            "tool_identifiers_are_permissions": False,
            "raw_text_execution_permitted": False,
        },
        "approved_plan": deepcopy(canonical),
    }


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

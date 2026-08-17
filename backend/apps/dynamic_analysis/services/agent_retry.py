from __future__ import annotations

from dataclasses import dataclass

from apps.api.roles import user_role
from apps.dynamic_analysis.models import AgentActionDecision, AgentRun, AssessmentPlan
from apps.dynamic_analysis.services.agent_capability_envelope import (
    CapabilityEnvelopeError,
    RETRY_PRESERVED_LIMIT_FIELDS,
    rebuild_capability_envelope_for_retry,
    validate_capability_envelope,
)
from apps.dynamic_analysis.services.assessment_execution_contract import (
    AssessmentExecutionContractError,
    validate_persisted_plan_contract,
)
from apps.dynamic_analysis.services.assessment_executor import (
    AssessmentExecutionError,
    AssessmentExecutor,
)
from apps.dynamic_analysis.services.assessment_planner import (
    AssessmentPlannerError,
    validate_generated_plan,
)


PRE_EXECUTION_TERMINATION_REASONS = frozenset(
    {"PROVIDER_FAILURE", "DECISION_SECURITY_REJECTED"}
)


@dataclass(frozen=True)
class AdaptiveRetryability:
    retryable: bool
    reason: str
    pre_execution_failure: bool
    plan_approval_preserved: bool


def adaptive_retryability(run: AgentRun, *, requested_by) -> AdaptiveRetryability:
    if run.pk is not None:
        run = AgentRun.objects.select_related(
            "assessment_plan",
            "assessment_plan__audit",
            "assessment_plan__approved_by",
        ).get(pk=run.pk)
    pre_execution = is_pre_execution_provider_failure(run)
    plan = run.assessment_plan
    approval_preserved = bool(
        plan is not None
        and plan.approved_by_id is not None
        and plan.approved_at is not None
    )

    def denied(reason: str) -> AdaptiveRetryability:
        return AdaptiveRetryability(
            retryable=False,
            reason=reason,
            pre_execution_failure=pre_execution,
            plan_approval_preserved=approval_preserved,
        )

    if user_role(requested_by) not in {"ADMIN", "ANALYST"}:
        return denied("ADAPTIVE_RETRY_PERMISSION_DENIED")
    if not pre_execution:
        return denied("ADAPTIVE_RETRY_FAILURE_NOT_PRE_EXECUTION")
    if plan is None:
        return denied("ADAPTIVE_RETRY_PLAN_MISSING")
    if AgentRun.objects.filter(
        assessment_plan=plan,
        objective_input__retry_of_agent_run_id=run.id,
    ).exists():
        return denied("ADAPTIVE_RETRY_ALREADY_USED")

    decisions = list(run.action_decisions.all())
    if run.decision_count != len(decisions):
        return denied("ADAPTIVE_RETRY_DECISION_STATE_MISMATCH")
    if decisions and any(
        decision.execution_status != AgentActionDecision.ExecutionStatus.REJECTED
        or decision.run_step_id is not None
        or decision.executed_at is not None
        for decision in decisions
    ):
        return denied("ADAPTIVE_RETRY_DECISION_EXECUTED")
    if run.tool_call_count != 0 or run.steps.exists():
        return denied("ADAPTIVE_RETRY_GATEWAY_ACTION_EXISTS")
    if run.evidence_records.exists():
        return denied("ADAPTIVE_RETRY_EVIDENCE_EXISTS")
    if run.artifacts.exists():
        return denied("ADAPTIVE_RETRY_ARTIFACT_EXISTS")
    if (
        not approval_preserved
        or plan.status not in {
            AssessmentPlan.Status.APPROVED,
            AssessmentPlan.Status.FAILED,
        }
        or plan.validation_status != AssessmentPlan.ValidationStatus.PASSED
        or plan.policy_status != AssessmentPlan.PolicyStatus.PASSED
    ):
        return denied("ADAPTIVE_RETRY_APPROVAL_INVALID")
    if not run.approved_plan_hash or run.approved_plan_hash != plan.plan_hash:
        return denied("ADAPTIVE_RETRY_PLAN_HASH_MISMATCH")

    try:
        canonical = validate_persisted_plan_contract(plan)
        current = validate_generated_plan(
            plan.generated_plan,
            audit=plan.audit,
            target_package=plan.target_package,
            objective=plan.objective,
            scope=plan.scope,
            planner_provider=plan.planner_provider,
            planner_model=plan.planner_model,
            planner_input_hash=plan.planner_input_hash,
        )
        if current != canonical or current != plan.normalized_plan:
            return denied("ADAPTIVE_RETRY_POLICY_CHANGED")
        AssessmentExecutor._validate_live_authorization(plan, canonical)
        validate_capability_envelope(run.capability_envelope, run=run)
        envelope = rebuild_capability_envelope_for_retry(
            plan,
            approved_envelope=run.capability_envelope,
        )
    except AssessmentPlannerError:
        return denied("ADAPTIVE_RETRY_POLICY_CHANGED")
    except AssessmentExecutionError:
        return denied("ADAPTIVE_RETRY_AUTHORIZATION_CHANGED")
    except AssessmentExecutionContractError:
        return denied("ADAPTIVE_RETRY_PLAN_HASH_MISMATCH")
    except CapabilityEnvelopeError:
        return denied("ADAPTIVE_RETRY_ENVELOPE_INVALID")

    changed_non_limit_field = any(
        envelope[field] != run.capability_envelope[field]
        for field in envelope
        if field not in RETRY_PRESERVED_LIMIT_FIELDS | {"envelope_hash"}
    )
    expanded_limit = any(
        envelope[field] > run.capability_envelope[field]
        for field in RETRY_PRESERVED_LIMIT_FIELDS
    )
    if changed_non_limit_field or expanded_limit:
        return denied("ADAPTIVE_RETRY_ENVELOPE_CHANGED")
    return AdaptiveRetryability(
        retryable=True,
        reason="ADAPTIVE_RETRY_ALLOWED",
        pre_execution_failure=True,
        plan_approval_preserved=True,
    )


def is_pre_execution_provider_failure(run: AgentRun) -> bool:
    return bool(
        run.execution_mode == AgentRun.ExecutionMode.ADAPTIVE_AGENT
        and run.status == AgentRun.Status.FAILED
        and run.termination_reason in PRE_EXECUTION_TERMINATION_REASONS
        and run.tool_call_count == 0
        and not run.steps.exists()
        and not run.evidence_records.exists()
        and not run.artifacts.exists()
    )

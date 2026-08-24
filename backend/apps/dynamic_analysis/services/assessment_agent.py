from __future__ import annotations

from hashlib import sha256
import json
import logging
from time import monotonic
from typing import Any, Callable

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.api.roles import user_role
from apps.dynamic_analysis.models import (
    AgentActionDecision,
    AgentHypothesis,
    AgentRun,
    AgentRuntime,
    AgentRunStep,
    AssessmentPlan,
    AssessmentPlanStep,
)
from apps.dynamic_analysis.services.agent_action_contract import (
    AgentActionDecisionError,
    persist_validated_decision,
)
from apps.dynamic_analysis.services.agent_capability_envelope import (
    CapabilityEnvelopeError,
    build_capability_envelope,
    rebuild_capability_envelope_for_retry,
    validate_capability_envelope,
)
from apps.dynamic_analysis.services.agent_decision_provider import (
    AgentDecisionProvider,
    build_agent_state_context,
    configured_agent_decision_provider,
)
from apps.dynamic_analysis.services.agent_gateway import (
    AgentGatewayRequestError,
    execute_run_tool_call,
)
from apps.dynamic_analysis.services.agent_oracles import (
    evaluate_run_oracles,
    initial_coverage_state,
    initialize_hypotheses,
)
from apps.dynamic_analysis.services.agent_retry import (
    adaptive_retryability,
    is_pre_execution_provider_failure,
)
from apps.dynamic_analysis.services.agent_tools import TOOL_MANIFEST
from apps.dynamic_analysis.services.assessment_execution_contract import (
    AssessmentExecutionContractError,
    build_approved_execution_contract,
    validate_approved_execution_contract,
)
from apps.dynamic_analysis.services.assessment_executor import (
    AssessmentExecutionError,
    AssessmentExecutionPermissionError,
    AssessmentExecutor,
)
from apps.dynamic_analysis.services.assessment_planner import PlannerProviderError
from apps.dynamic_analysis.services.openai_budget import (
    KIND_DECISION,
    OpenAIBudgetExhausted,
    record_response_id,
    release_call,
    reserve_call,
)
from apps.dynamic_analysis.services.generated_frida_scripts import (
    is_generated_frida_source_identifier,
)


logger = logging.getLogger(__name__)
security_logger = logging.getLogger("msap.security")


class AssessmentAgentError(AssessmentExecutionError):
    pass


class AssessmentAgent:
    """Bounded iterative assessment inside an approved capability envelope."""

    def __init__(
        self,
        *,
        decision_provider: AgentDecisionProvider | None = None,
        gateway_executor: Callable[..., dict[str, Any]] = execute_run_tool_call,
        clock: Callable[[], float] = monotonic,
    ):
        self.decision_provider = decision_provider
        self.gateway_executor = gateway_executor
        self.clock = clock
        self.observation_recorder = AssessmentExecutor()

    def create_run(
        self,
        *,
        plan: AssessmentPlan,
        requested_by,
        decision_provider_name: str | None = None,
        retry_of_run: AgentRun | None = None,
    ) -> AgentRun:
        if user_role(requested_by) not in {"ADMIN", "ANALYST"}:
            raise AssessmentExecutionPermissionError()
        resolved_provider_name = (
            decision_provider_name or settings.MSAP_AGENT_DECISION_PROVIDER
        ).upper()
        provider = self.decision_provider or configured_agent_decision_provider(
            resolved_provider_name,
            model=(
                plan.planner_model
                if resolved_provider_name == AssessmentPlan.PlannerProvider.OPENAI
                and plan.planner_provider == AssessmentPlan.PlannerProvider.OPENAI
                else None
            ),
        )
        try:
            with transaction.atomic():
                persisted = AssessmentPlan.objects.select_for_update().get(pk=plan.pk)
                retry_source = None
                if retry_of_run is not None:
                    retry_source = (
                        AgentRun.objects.select_for_update()
                        .get(pk=retry_of_run.pk)
                    )
                    if retry_source.assessment_plan_id != persisted.id:
                        raise AssessmentAgentError(
                            "The failed run does not belong to this assessment plan.",
                            code="ADAPTIVE_RETRY_PLAN_MISMATCH",
                        )
                    retryability = adaptive_retryability(
                        retry_source,
                        requested_by=requested_by,
                    )
                    if not retryability.retryable:
                        raise AssessmentAgentError(
                            "This adaptive assessment run is not safe to retry.",
                            code=retryability.reason,
                        )
                    if (
                        provider.name != retry_source.decision_provider
                        or provider.model != retry_source.decision_model
                    ):
                        raise AssessmentAgentError(
                            "The adaptive retry provider configuration changed.",
                            code="ADAPTIVE_RETRY_PROVIDER_CHANGED",
                        )
                    if persisted.status == AssessmentPlan.Status.FAILED:
                        persisted.status = AssessmentPlan.Status.APPROVED
                        persisted.save(update_fields=["status", "updated_at"])
                        persisted.steps.update(
                            status=AssessmentPlanStep.Status.APPROVED,
                            updated_at=timezone.now(),
                        )
                contract = build_approved_execution_contract(persisted)
                AssessmentExecutor._validate_live_authorization(
                    persisted,
                    contract["approved_plan"],
                )
                envelope = (
                    rebuild_capability_envelope_for_retry(
                        persisted,
                        approved_envelope=retry_source.capability_envelope,
                    )
                    if retry_source is not None
                    else build_capability_envelope(persisted)
                )
                runtime = AssessmentExecutor._select_runtime(
                    AgentRuntime.RuntimeType.INTERNAL_CONTROLLER
                )
                if runtime is None:
                    raise AssessmentAgentError(
                        "No enabled execution runtime is available.",
                        code="ASSESSMENT_RUNTIME_UNAVAILABLE",
                        http_status=503,
                    )
                runtime_tools = set((runtime.capabilities or {}).get("tools", []))
                if not set(envelope["allowed_capabilities"]) <= runtime_tools:
                    raise AssessmentAgentError(
                        "The selected runtime does not expose the approved adaptive envelope.",
                        code="AGENT_RUNTIME_CAPABILITY_MISMATCH",
                        http_status=503,
                    )
                if (
                    retry_source is None
                    and AgentRun.objects.filter(assessment_plan=persisted).exists()
                ):
                    raise AssessmentAgentError(
                        "This approved assessment plan already has an execution run.",
                        code="ASSESSMENT_PLAN_ALREADY_EXECUTED",
                    )
                run = AgentRun.objects.create(
                    audit=persisted.audit,
                    runtime=runtime,
                    assessment_plan=persisted,
                    approved_plan_hash=persisted.plan_hash,
                    target_package=persisted.target_package,
                    execution_contract=contract,
                    execution_mode=AgentRun.ExecutionMode.ADAPTIVE_AGENT,
                    capability_envelope=envelope,
                    capability_envelope_hash=envelope["envelope_hash"],
                    decision_provider=provider.name,
                    decision_model=provider.model,
                    objective=AgentRun.Objective.ASSESSMENT_PLAN_EXECUTION,
                    objective_input={
                        "assessment_plan_id": persisted.id,
                        "approved_plan_hash": persisted.plan_hash,
                        "capability_envelope_hash": envelope["envelope_hash"],
                        "execution_mode": AgentRun.ExecutionMode.ADAPTIVE_AGENT,
                        **(
                            {"retry_of_agent_run_id": retry_source.id}
                            if retry_source is not None
                            else {}
                        ),
                    },
                    requested_by=requested_by,
                )
                initialize_hypotheses(run)
                run.coverage_state = initial_coverage_state(run)
                run.save(update_fields=["coverage_state", "updated_at"])
                persisted.status = AssessmentPlan.Status.EXECUTING
                persisted.save(update_fields=["status", "updated_at"])
        except AssessmentPlan.DoesNotExist:
            raise AssessmentAgentError(
                "The approved assessment plan no longer exists.",
                code="ASSESSMENT_PLAN_NOT_FOUND",
                http_status=404,
            ) from None
        except AgentRun.DoesNotExist:
            raise AssessmentAgentError(
                "The failed adaptive assessment run no longer exists.",
                code="ADAPTIVE_RETRY_RUN_NOT_FOUND",
                http_status=404,
            ) from None
        except (AssessmentExecutionContractError, CapabilityEnvelopeError) as exc:
            raise AssessmentAgentError(
                str(exc),
                code=(
                    "ASSESSMENT_PLAN_NOT_EXECUTABLE"
                    if isinstance(exc, AssessmentExecutionContractError)
                    else exc.code
                ),
            ) from None
        except IntegrityError:
            raise AssessmentAgentError(
                "This approved assessment plan already has an execution run.",
                code="ASSESSMENT_PLAN_ALREADY_EXECUTED",
            ) from None
        self.decision_provider = provider
        security_logger.info(
            "assessment_agent_created run_id=%s plan_id=%s plan_hash=%s envelope_hash=%s provider=%s model=%s",
            run.id,
            persisted.id,
            persisted.plan_hash,
            run.capability_envelope_hash,
            run.decision_provider,
            run.decision_model,
        )
        return run

    def execute(self, run_id: int) -> AgentRun:
        run = self._start_run(run_id)
        if run.status == AgentRun.Status.CANCELLED:
            return run
        provider = self.decision_provider or configured_agent_decision_provider(
            run.decision_provider,
            model=run.decision_model,
        )
        if provider.name != run.decision_provider or provider.model != run.decision_model:
            return self._finish(
                run,
                status=AgentRun.Status.FAILED,
                termination_reason="PROVIDER_CONFIGURATION_CHANGED",
                message="The persisted adaptive decision provider configuration changed.",
            )
        envelope = validate_capability_envelope(run.capability_envelope, run=run)
        deadline = self.clock() + envelope["maximum_run_duration_seconds"]

        while True:
            run.refresh_from_db()
            if run.cancellation_requested_at is not None:
                return self._finish(
                    run,
                    status=AgentRun.Status.CANCELLED,
                    termination_reason="CANCELLED_BY_AUDITOR",
                    message="Adaptive assessment cancelled by an authorized operator.",
                )
            if self.clock() >= deadline:
                return self._finish(
                    run,
                    status=AgentRun.Status.TIMEOUT,
                    termination_reason="TOTAL_TIME_BUDGET_EXHAUSTED",
                    message="The adaptive assessment reached its total duration bound.",
                )
            # The paid model budget is distinct from the bounded execution
            # budget. After Economy has spent its paid calls, the provider
            # continues only through the immutable approved playbook sequence.
            allow_local_provider_fallback = (
                provider.name == "OPENAI"
                and run.model_call_count >= envelope["maximum_model_provider_calls"]
                and bool(run.assessment_plan_id)
            )
            budget_reason = self._budget_stop_reason(
                run,
                envelope,
                allow_local_provider_fallback=allow_local_provider_fallback,
            )
            if budget_reason:
                return self._finish(
                    run,
                    status=(
                        AgentRun.Status.FAILED
                        if budget_reason == "CONSECUTIVE_FAILURE_LIMIT_REACHED"
                        else AgentRun.Status.SUCCEEDED
                    ),
                    termination_reason=budget_reason,
                )
            provider_call_was_reserved = False
            try:
                state = build_agent_state_context(run)
                state_hash = _json_hash(state)
                if not allow_local_provider_fallback:
                    AgentRun.objects.filter(pk=run.pk).update(
                        model_call_count=run.model_call_count + 1,
                        updated_at=timezone.now(),
                    )
                    run.model_call_count += 1
                # The backend-enforced OpenAI budget is the authoritative cap.
                # Reservations are made before the request is sent and rolled
                # back only when a local schema preflight proves no request was
                # sent. Provider failures, schema rejections, and invalid
                # outputs after a real request still count against the budget.
                if provider.name == "OPENAI":
                    reserve_call(KIND_DECISION)
                    provider_call_was_reserved = True
                raw_decision = provider.next_action(state)
                if provider_call_was_reserved:
                    record_response_id(
                        (provider.last_metadata or {}).get("response_id")
                    )
                decision = persist_validated_decision(
                    run=run,
                    decision=raw_decision,
                    provider=provider.name,
                    model=provider.model,
                    provider_metadata=provider.last_metadata,
                    decision_input_hash=state_hash,
                )
            except OpenAIBudgetExhausted as exc:
                if provider_call_was_reserved:
                    release_call(KIND_DECISION)
                return self._finish(
                    run,
                    status=AgentRun.Status.FAILED,
                    termination_reason="OPENAI_BUDGET_EXHAUSTED",
                    message=str(exc),
                )
            except PlannerProviderError as exc:
                if (
                    exc.code == "PROVIDER_SCHEMA_LOCAL_REJECTED"
                    and provider.last_metadata.get("provider_request_sent") is False
                ):
                    if provider_call_was_reserved:
                        release_call(KIND_DECISION)
                        provider_call_was_reserved = False
                    run.model_call_count = max(0, run.model_call_count - 1)
                    run.save(update_fields=["model_call_count", "updated_at"])
                return self._finish(
                    run,
                    status=AgentRun.Status.FAILED,
                    termination_reason="PROVIDER_FAILURE",
                    message=str(exc),
                    provider_failure={
                        "code": exc.code,
                        **_safe_provider_metadata(provider.last_metadata),
                    },
                )
            except AgentActionDecisionError as exc:
                self._record_rejected_decision(
                    run=run,
                    provider=provider,
                    state_hash=state_hash,
                    raw_decision=locals().get("raw_decision"),
                    error=exc,
                )
                return self._finish(
                    run,
                    status=AgentRun.Status.FAILED,
                    termination_reason="DECISION_SECURITY_REJECTED",
                    message=str(exc),
                )

            run.decision_count = decision.sequence
            run.save(update_fields=["decision_count", "updated_at"])
            if decision.hypothesis_id:
                AgentHypothesis.objects.filter(
                    pk=decision.hypothesis_id,
                    status=AgentHypothesis.Status.UNTESTED,
                ).update(status=AgentHypothesis.Status.ACTIVE)

            if decision.decision_type == AgentActionDecision.DecisionType.COMPLETE:
                return self._finish(
                    run,
                    status=AgentRun.Status.SUCCEEDED,
                    termination_reason="MODEL_COMPLETE",
                )
            if decision.decision_type == AgentActionDecision.DecisionType.NEEDS_AUDITOR:
                decision.execution_status = AgentActionDecision.ExecutionStatus.NOT_EXECUTED
                decision.save(update_fields=["execution_status"])
                return self._finish(
                    run,
                    status=AgentRun.Status.PAUSED,
                    termination_reason="NEEDS_AUDITOR",
                    message=decision.rationale_summary,
                )

            step = AgentRunStep.objects.create(
                run=run,
                sequence_number=decision.sequence,
                tool_name=decision.tool_name,
                plan_step_identifier=f"adaptive_{decision.sequence}",
                tool_call_index=1,
                dependencies=[],
                evidence_requirements=decision.evidence_goals,
                input_summary=decision.arguments,
                timeout_seconds=TOOL_MANIFEST[decision.tool_name].timeout_seconds,
                max_retries=0,
            )
            decision.run_step = step
            decision.save(update_fields=["run_step"])
            try:
                result = self.gateway_executor(
                    run_id=run.id,
                    action_decision_id=decision.id,
                    tool_name=decision.tool_name,
                    arguments=decision.arguments,
                )
                step.refresh_from_db()
                self.observation_recorder._record_successful_observation(
                    run,
                    step,
                    result["output"],
                )
                decision.refresh_from_db()
                decision.observation_hash = _json_hash(step.observation)
                decision.save(update_fields=["observation_hash"])
                run.consecutive_failure_count = 0
                run.save(update_fields=["consecutive_failure_count", "updated_at"])
                evaluate_run_oracles(run)
            except AgentGatewayRequestError as exc:
                step.refresh_from_db()
                if step.status == AgentRunStep.Status.PENDING:
                    step.status = AgentRunStep.Status.FAILED
                    step.failure_message = str(exc)[:500]
                    step.finished_at = timezone.now()
                    step.save(update_fields=["status", "failure_message", "finished_at"])
                self.observation_recorder._record_failed_observation(run, step)
                AgentActionDecision.objects.filter(pk=decision.pk).update(
                    execution_status=AgentActionDecision.ExecutionStatus.FAILED,
                    failure_code=exc.code[:64],
                    observation_hash=_json_hash(step.observation),
                    executed_at=timezone.now(),
                )
                run.consecutive_failure_count += 1
                run.save(update_fields=["consecutive_failure_count", "updated_at"])
                evaluate_run_oracles(run)
                if (
                    decision.tool_name == "frida_run_js"
                    and isinstance(decision.arguments, dict)
                    and is_generated_frida_source_identifier(
                        decision.arguments.get("source")
                    )
                ):
                    return self._finish(
                        run,
                        status=AgentRun.Status.PAUSED,
                        termination_reason="FRIDA_SCRIPT_NEEDS_REVIEW",
                        message=(
                            "The auditor-approved generated Frida script failed. "
                            "Review the recorded error, generate or edit a narrower "
                            "script proposal, approve it, then resume the assessment."
                        ),
                    )

    def _start_run(self, run_id: int) -> AgentRun:
        with transaction.atomic():
            run = AgentRun.objects.select_for_update().get(pk=run_id)
            if (
                run.objective != AgentRun.Objective.ASSESSMENT_PLAN_EXECUTION
                or run.execution_mode != AgentRun.ExecutionMode.ADAPTIVE_AGENT
            ):
                raise AssessmentAgentError(
                    "The run is not an adaptive approved assessment.",
                    code="AGENT_RUN_MODE_INVALID",
                )
            if run.status == AgentRun.Status.CANCELLED:
                return run
            if run.status != AgentRun.Status.QUEUED:
                raise AssessmentAgentError(
                    "The adaptive assessment run is not queued for execution.",
                    code="AGENT_RUN_STATE_INVALID",
                )
            if user_role(run.requested_by) not in {"ADMIN", "ANALYST"}:
                raise AssessmentExecutionPermissionError()
            contract = validate_approved_execution_contract(run.execution_contract)
            validate_capability_envelope(run.capability_envelope, run=run)
            plan = run.assessment_plan
            if (
                plan is None
                or plan.status != AssessmentPlan.Status.EXECUTING
                or contract["plan_hash"] != plan.plan_hash
                or contract["approved_plan"] != plan.normalized_plan
            ):
                raise AssessmentAgentError(
                    "The approved adaptive strategy failed its integrity check.",
                    code="AGENT_PLAN_INTEGRITY_FAILED",
                )
            AssessmentExecutor._validate_live_authorization(
                plan,
                contract["approved_plan"],
            )
            run.status = AgentRun.Status.RUNNING
            run.started_at = timezone.now()
            run.save(update_fields=["status", "started_at", "updated_at"])
            AssessmentPlanStep.objects.filter(plan_id=run.assessment_plan_id).update(
                status=AssessmentPlanStep.Status.EXECUTING,
                updated_at=timezone.now(),
            )
        return run

    @staticmethod
    def _budget_stop_reason(
        run: AgentRun,
        envelope: dict[str, Any],
        *,
        allow_local_provider_fallback: bool = False,
    ) -> str:
        if run.decision_count >= envelope["maximum_decisions"]:
            return "DECISION_BUDGET_EXHAUSTED"
        if run.tool_call_count >= envelope["maximum_tool_calls"]:
            return "TOOL_CALL_BUDGET_EXHAUSTED"
        if (
            run.model_call_count >= envelope["maximum_model_provider_calls"]
            and not allow_local_provider_fallback
        ):
            return "PROVIDER_CALL_BUDGET_EXHAUSTED"
        if run.consecutive_failure_count >= envelope["maximum_consecutive_failures"]:
            return "CONSECUTIVE_FAILURE_LIMIT_REACHED"
        if run.artifacts.count() >= envelope["maximum_artifacts"]:
            return "ARTIFACT_BUDGET_EXHAUSTED"
        if run.evidence_records.count() >= envelope["maximum_evidence_records"]:
            return "EVIDENCE_BUDGET_EXHAUSTED"
        return ""

    @staticmethod
    def _all_hypotheses_terminal(run: AgentRun) -> bool:
        active_collectors = run.steps.filter(
            tool_name="start_logcat",
            status=AgentRunStep.Status.SUCCEEDED,
        ).count() > run.steps.filter(
            tool_name="stop_logcat",
            status=AgentRunStep.Status.SUCCEEDED,
        ).count()
        if active_collectors:
            return False
        target_may_be_running = run.steps.filter(
            tool_name="launch_package",
            status=AgentRunStep.Status.SUCCEEDED,
        ).count() > run.steps.filter(
            tool_name="force_stop_package",
            status=AgentRunStep.Status.SUCCEEDED,
        ).count()
        if (
            target_may_be_running
            and "force_stop_package"
            in run.capability_envelope.get("allowed_capabilities", [])
        ):
            return False
        statuses = set(run.hypotheses.values_list("status", flat=True))
        return bool(statuses) and not statuses & {
            AgentHypothesis.Status.UNTESTED,
            AgentHypothesis.Status.ACTIVE,
        }

    @staticmethod
    def _record_rejected_decision(
        *,
        run: AgentRun,
        provider: AgentDecisionProvider,
        state_hash: str,
        raw_decision: Any,
        error: AgentActionDecisionError,
    ) -> None:
        output_hash = _json_hash(raw_decision) if _json_compatible(raw_decision) else sha256(b"invalid").hexdigest()
        AgentActionDecision.objects.create(
            run=run,
            sequence=run.decision_count + 1,
            contract_version="rejected",
            decision_type=AgentActionDecision.DecisionType.COMPLETE,
            rationale_summary="Provider decision rejected by backend validation.",
            expected_observation="",
            provider=provider.name,
            model=provider.model,
            provider_metadata=_safe_provider_metadata(provider.last_metadata),
            decision_input_hash=state_hash,
            decision_output_hash=output_hash,
            validation_status=AgentActionDecision.CheckStatus.FAILED,
            policy_status=AgentActionDecision.CheckStatus.FAILED,
            execution_status=AgentActionDecision.ExecutionStatus.REJECTED,
            failure_code=error.code[:64],
            validated_at=timezone.now(),
        )
        AgentRun.objects.filter(pk=run.pk).update(
            decision_count=run.decision_count + 1,
            updated_at=timezone.now(),
        )

    @staticmethod
    def _finish(
        run: AgentRun,
        *,
        status: str,
        termination_reason: str,
        message: str = "",
        provider_failure: dict[str, Any] | None = None,
    ) -> AgentRun:
        now = timezone.now()
        run.refresh_from_db()
        run.status = status
        run.finished_at = now
        run.termination_reason = termination_reason
        if status in {AgentRun.Status.FAILED, AgentRun.Status.TIMEOUT}:
            run.failure_category = (
                AgentRun.FailureCategory.TIMEOUT
                if status == AgentRun.Status.TIMEOUT
                else AgentRun.FailureCategory.OPENAI_BUDGET_EXHAUSTED
                if termination_reason == "OPENAI_BUDGET_EXHAUSTED"
                else AgentRun.FailureCategory.AI_PROVIDER_FAILURE
                if termination_reason == "PROVIDER_FAILURE"
                and run.tool_call_count == 0
                and not run.steps.exists()
                else AgentRun.FailureCategory.AI_DECISION_REJECTED
                if termination_reason == "DECISION_SECURITY_REJECTED"
                and run.tool_call_count == 0
                and not run.steps.exists()
                else AgentRun.FailureCategory.TOOL_EXECUTION_FAILED
            )
        run.failure_message = message[:500]
        run.result_summary = AssessmentAgent._result_summary(
            run,
            provider_failure=provider_failure,
        )
        run.save(
            update_fields=[
                "status",
                "finished_at",
                "duration_seconds",
                "termination_reason",
                "failure_category",
                "failure_message",
                "result_summary",
                "updated_at",
            ]
        )
        if status == AgentRun.Status.PAUSED:
            return run
        pre_execution_failure = is_pre_execution_provider_failure(run)
        plan_status = {
            AgentRun.Status.SUCCEEDED: AssessmentPlan.Status.COMPLETED,
            AgentRun.Status.CANCELLED: AssessmentPlan.Status.CANCELLED,
        }.get(
            status,
            AssessmentPlan.Status.APPROVED
            if pre_execution_failure
            else AssessmentPlan.Status.FAILED,
        )
        AssessmentPlan.objects.filter(pk=run.assessment_plan_id).update(
            status=plan_status,
            updated_at=now,
        )
        step_status = (
            AssessmentPlanStep.Status.COMPLETED
            if status == AgentRun.Status.SUCCEEDED
            else AssessmentPlanStep.Status.APPROVED
            if pre_execution_failure
            else AssessmentPlanStep.Status.CANCELLED
            if status == AgentRun.Status.CANCELLED
            else AssessmentPlanStep.Status.FAILED
        )
        AssessmentPlanStep.objects.filter(plan_id=run.assessment_plan_id).update(
            status=step_status,
            updated_at=now,
        )
        if status in {AgentRun.Status.SUCCEEDED, AgentRun.Status.FAILED, AgentRun.Status.TIMEOUT}:
            try:
                from apps.dynamic_analysis.services.assessment_results import (
                    resolve_completed_assessment,
                )

                post_processing = resolve_completed_assessment(run)
            except Exception as exc:
                logger.error(
                    "adaptive_assessment_post_processing_failed run_id=%s error_type=%s",
                    run.id,
                    type(exc).__name__,
                )
                post_processing = {"status": "FAILED", "reason": "Post-processing failed safely."}
            run.refresh_from_db()
            summary = AssessmentAgent._result_summary(
                run,
                provider_failure=provider_failure,
            )
            summary["post_processing"] = post_processing
            run.result_summary = summary
            run.save(update_fields=["result_summary", "updated_at"])
        security_logger.info(
            "assessment_agent_completed run_id=%s status=%s termination=%s decisions=%s tool_calls=%s evidence=%s",
            run.id,
            run.status,
            run.termination_reason,
            run.decision_count,
            run.tool_call_count,
            run.evidence_records.count(),
        )
        return run

    @staticmethod
    def _result_summary(
        run: AgentRun,
        *,
        provider_failure: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        hypothesis_counts = {
            status: run.hypotheses.filter(status=status).count()
            for status in AgentHypothesis.Status.values
        }
        return {
            "objective": AgentRun.Objective.ASSESSMENT_PLAN_EXECUTION,
            "assessment_plan_id": run.assessment_plan_id,
            "approved_plan_hash": run.approved_plan_hash,
            "capability_envelope_hash": run.capability_envelope_hash,
            "target_package": run.target_package,
            "execution_mode": AgentRun.ExecutionMode.ADAPTIVE_AGENT,
            "execution_channel": "RUN_SCOPED_TOOL_GATEWAY",
            "decision_provider": run.decision_provider,
            "decision_model": run.decision_model,
            "decision_count": run.decision_count,
            "model_call_count": run.model_call_count,
            "tool_call_count": run.tool_call_count,
            "artifact_count": run.artifacts.count(),
            "evidence_count": run.evidence_records.count(),
            "hypothesis_status_counts": hypothesis_counts,
            "coverage": run.coverage_state,
            "termination_reason": run.termination_reason,
            "provider_failure": provider_failure or {},
            "pre_execution_failure": is_pre_execution_provider_failure(run),
            "no_device_action_performed": bool(
                run.tool_call_count == 0 and not run.steps.exists()
            ),
            "plan_approval_preserved": bool(
                run.assessment_plan is not None
                and run.assessment_plan.approved_by_id is not None
                and run.assessment_plan.approved_at is not None
            ),
            "observations_are_untrusted_data": True,
            "findings_authority": "DETERMINISTIC_BACKEND_ONLY",
        }


def _safe_provider_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    result = {}
    for key in {
        "provider_status",
        "provider_http_status",
        "provider_error_type",
        "provider_error_code",
        "provider_error_param",
        "response_id",
        "retry_count",
        "latency_ms",
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "total_tokens",
    }:
        item = value.get(key)
        if isinstance(item, (str, int)) and not isinstance(item, bool):
            result[key] = item
    return result


def _json_hash(value: Any) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def _json_compatible(value: Any) -> bool:
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        return False
    return True

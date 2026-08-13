from __future__ import annotations

import logging

from django.db import transaction
from django.utils import timezone

from apps.dynamic_analysis.models import (
    AgentRun,
    AgentRunStep,
    DynamicDevice,
)
from apps.dynamic_analysis.services.agent_controller import (
    AgentController,
    resolve_runtime_arguments,
)
from apps.dynamic_analysis.services.agent_tools import (
    AgentToolError,
    TOOL_MANIFEST,
    execute_agent_tool,
)


logger = logging.getLogger(__name__)
security_logger = logging.getLogger("msap.security")


class AgentGatewayRequestError(RuntimeError):
    def __init__(self, message: str, *, code: str, http_status: int = 400):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


class AgentGatewayExecutionError(AgentGatewayRequestError):
    pass


def execute_run_tool_call(
    *,
    run_id: int,
    tool_name: str,
    arguments,
    tool_executor=execute_agent_tool,
) -> dict:
    """Claim and execute the next exact tool in a deterministic run plan."""

    with transaction.atomic():
        run = (
            AgentRun.objects.select_for_update()
            .select_related("requested_by", "runtime")
            .get(pk=run_id)
        )
        if run.status != AgentRun.Status.RUNNING:
            raise AgentGatewayRequestError(
                "The agent run is not accepting tool calls.",
                code="RUN_NOT_RUNNING",
                http_status=409,
            )
        if tool_name not in TOOL_MANIFEST or not run.steps.filter(
            tool_name=tool_name
        ).exists():
            raise AgentGatewayRequestError(
                "The requested tool is not allowed for this objective.",
                code="TOOL_NOT_ALLOWED",
            )
        steps = list(run.steps.select_for_update().order_by("sequence_number"))
        expected_step = next(
            (
                step
                for step in steps
                if step.status
                not in {
                    AgentRunStep.Status.SUCCEEDED,
                    AgentRunStep.Status.SKIPPED,
                }
            ),
            None,
        )
        if expected_step is None:
            raise AgentGatewayRequestError(
                "The deterministic tool sequence is already complete.",
                code="TOOL_SEQUENCE_COMPLETE",
            )
        if tool_name != expected_step.tool_name:
            raise AgentGatewayRequestError(
                "The requested tool is out of sequence for this objective.",
                code="TOOL_OUT_OF_SEQUENCE",
            )
        completed_outputs = {
            step.tool_name: step.output_summary
            for step in steps
            if step.status == AgentRunStep.Status.SUCCEEDED
        }
        expected_arguments = resolve_runtime_arguments(
            expected_step.input_summary,
            completed_outputs,
        )
        if arguments != expected_arguments:
            raise AgentGatewayRequestError(
                "The requested tool arguments do not match the objective contract.",
                code="INVALID_TOOL_ARGUMENTS",
            )
        if expected_step.status != AgentRunStep.Status.PENDING:
            raise AgentGatewayRequestError(
                "The next tool step is already in progress or failed.",
                code="TOOL_STEP_UNAVAILABLE",
                http_status=409,
            )
        expected_step.status = AgentRunStep.Status.RUNNING
        expected_step.input_summary = expected_arguments
        expected_step.started_at = timezone.now()
        expected_step.save(update_fields=["input_summary", "status", "started_at"])
        step_id = expected_step.pk

    try:
        output = tool_executor(
            tool_name,
            expected_arguments,
            requested_by=run.requested_by,
        )
    except AgentToolError as exc:
        _record_tool_failure(run_id=run_id, step_id=step_id, error=exc)
        http_status = 504 if exc.failure_category == AgentRun.FailureCategory.TIMEOUT else 502
        raise AgentGatewayExecutionError(
            str(exc),
            code=exc.code,
            http_status=http_status,
        ) from None
    except Exception as exc:  # pragma: no cover - defensive host boundary
        logger.error(
            "agent_gateway_unexpected_failure run_id=%s step_id=%s error_type=%s",
            run_id,
            step_id,
            type(exc).__name__,
        )
        safe_error = AgentToolError(
            "The allowlisted agent tool failed unexpectedly.",
            code="INTERNAL_TOOL_ERROR",
            failure_category=AgentRun.FailureCategory.INTERNAL_ERROR,
        )
        _record_tool_failure(run_id=run_id, step_id=step_id, error=safe_error)
        raise AgentGatewayExecutionError(
            "The allowlisted agent tool failed unexpectedly.",
            code="INTERNAL_TOOL_ERROR",
            http_status=500,
        ) from None

    with transaction.atomic():
        run = (
            AgentRun.objects.select_for_update()
            .select_related("runtime")
            .get(pk=run_id)
        )
        step = AgentRunStep.objects.select_for_update().get(pk=step_id, run=run)
        if run.status != AgentRun.Status.RUNNING or step.status != AgentRunStep.Status.RUNNING:
            raise AgentGatewayRequestError(
                "The agent run changed state before the tool completed.",
                code="RUN_STATE_CHANGED",
                http_status=409,
            )
        step.status = AgentRunStep.Status.SUCCEEDED
        step.output_summary = output
        step.finished_at = timezone.now()
        step.save(
            update_fields=[
                "status",
                "output_summary",
                "finished_at",
                "duration_seconds",
            ]
        )
        AgentController._record_tool_artifact(run, step, output)
        if tool_name == "get_device_status" and output.get("serial"):
            run.device = DynamicDevice.objects.filter(serial=output["serial"]).first()
            run.save(update_fields=["device", "updated_at"])
        completed = not run.steps.exclude(
            status__in=[AgentRunStep.Status.SUCCEEDED, AgentRunStep.Status.SKIPPED]
        ).exists()
        if completed:
            outputs = AgentController._completed_outputs(run)
            run.finished_at = timezone.now()
            run.result_summary = AgentController._result_summary(
                outputs,
                succeeded=True,
                runtime=run.runtime,
                run=run,
            )
            proof_failed = bool(
                run.objective
                == AgentRun.Objective.FRIDA_RUNTIME_UI_MODIFICATION_PROOF
                and not run.result_summary.get("evidence_confirmed")
            )
            run.status = (
                AgentRun.Status.FAILED if proof_failed else AgentRun.Status.SUCCEEDED
            )
            if proof_failed:
                run.failure_category = AgentRun.FailureCategory.TOOL_EXECUTION_FAILED
                run.failure_message = (
                    "Frida executed, but the required before/after visible modification "
                    "evidence was not confirmed."
                )
            AgentController._record_instrumentation_evidence(run, outputs)
            AgentController._redact_persisted_text(run)
            run.save(
                update_fields=[
                    "status",
                    "finished_at",
                    "duration_seconds",
                    "result_summary",
                    "failure_category",
                    "failure_message",
                    "objective_input",
                    "updated_at",
                ]
            )
            if run.runtime is not None:
                run.runtime.last_seen_at = run.finished_at
                run.runtime.save(update_fields=["last_seen_at", "updated_at"])
        security_logger.info(
            "agent_gateway_tool_completed run_id=%s step_id=%s tool=%s run_status=%s",
            run.id,
            step.id,
            tool_name,
            run.status,
        )
        return {
            "run_id": run.id,
            "objective": run.objective,
            "sequence_number": step.sequence_number,
            "tool_name": step.tool_name,
            "step_status": step.status,
            "run_status": run.status,
            "output": output,
        }


def _record_tool_failure(*, run_id: int, step_id: int, error: AgentToolError) -> None:
    with transaction.atomic():
        run = (
            AgentRun.objects.select_for_update()
            .select_related("runtime")
            .get(pk=run_id)
        )
        step = AgentRunStep.objects.select_for_update().get(pk=step_id, run=run)
        if run.status != AgentRun.Status.RUNNING:
            return
        step.status = (
            AgentRunStep.Status.TIMEOUT
            if error.failure_category == AgentRun.FailureCategory.TIMEOUT
            else AgentRunStep.Status.FAILED
        )
        step.failure_message = str(error)
        step.finished_at = timezone.now()
        step.save(
            update_fields=[
                "status",
                "failure_message",
                "finished_at",
                "duration_seconds",
            ]
        )
        controller = AgentController()
        pending_steps = list(
            run.steps.filter(status=AgentRunStep.Status.PENDING).order_by(
                "sequence_number"
            )
        )
        controller._skip_pending_steps(pending_steps)
        controller._finish_failed_run(
            run,
            controller._completed_outputs(run),
            category=error.failure_category,
            message=str(error),
        )

from __future__ import annotations

import logging
from hashlib import sha256
import json
import re
from time import monotonic

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.api.roles import user_role
from apps.apk_files.models import APKFile
from apps.dynamic_analysis.models import (
    AgentRun,
    AgentRunStep,
    AssessmentPlan,
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
from apps.dynamic_analysis.services.assessment_execution_contract import (
    AssessmentExecutionContractError,
    approved_tool_call_for_run_step,
    validate_approved_execution_contract,
)


logger = logging.getLogger(__name__)
security_logger = logging.getLogger("msap.security")
TRANSIENT_TOOL_CODES = {
    "HOST_AGENT_UNREACHABLE",
    "HOST_AGENT_HTTP_ERROR",
    "HOST_AGENT_SCREENSHOT_FAILED",
}
SECRET_KEY_FRAGMENTS = (
    "api_key", "apikey", "authorization", "credential", "password",
    "private_key", "secret", "session", "token",
)
SECRET_VALUE_PATTERNS = (
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(
        r"\b(?:api[_-]?key|password|secret|token|credential)\s*[:=]\s*[^\s,;]+",
        re.IGNORECASE,
    ),
)


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
            .select_related("requested_by", "runtime", "assessment_plan")
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
        terminal_step_statuses = {
            AgentRunStep.Status.SUCCEEDED,
            AgentRunStep.Status.SKIPPED,
        }
        if run.assessment_plan_id:
            terminal_step_statuses.update({
                AgentRunStep.Status.FAILED,
                AgentRunStep.Status.TIMEOUT,
                AgentRunStep.Status.CANCELLED,
            })
        expected_step = next(
            (
                step
                for step in steps
                if step.status not in terminal_step_statuses
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
        if run.assessment_plan_id:
            try:
                contract = validate_approved_execution_contract(run.execution_contract)
                approved_call = approved_tool_call_for_run_step(run, expected_step)
            except AssessmentExecutionContractError:
                raise AgentGatewayRequestError(
                    "The approved execution contract failed its integrity check.",
                    code="APPROVED_PLAN_INTEGRITY_FAILED",
                    http_status=409,
                ) from None
            plan = run.assessment_plan
            if (
                plan is None
                or plan.status != AssessmentPlan.Status.EXECUTING
                or contract["plan_hash"] != plan.plan_hash
                or contract["approved_plan"] != plan.normalized_plan
                or run.approved_plan_hash != plan.plan_hash
                or run.audit_id != plan.audit_id
                or run.target_package != plan.target_package
                or user_role(run.requested_by) not in {"ADMIN", "ANALYST"}
                or not APKFile.objects.filter(
                    audit_id=run.audit_id,
                    package_name=run.target_package,
                ).exists()
            ):
                raise AgentGatewayRequestError(
                    "The approved plan is no longer authorized for execution.",
                    code="APPROVED_PLAN_AUTHORIZATION_FAILED",
                    http_status=403,
                )
            if (
                approved_call["name"] != expected_step.tool_name
                or approved_call["arguments"] != expected_step.input_summary
            ):
                raise AgentGatewayRequestError(
                    "The materialized tool call does not match the approved plan.",
                    code="APPROVED_TOOL_CALL_MISMATCH",
                )
            expected_arguments = approved_call["arguments"]
        else:
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

    attempt = 0
    started = monotonic()
    while True:
        _claim_tool_attempt(run_id, step_id)
        try:
            output = tool_executor(
                tool_name,
                expected_arguments,
                requested_by=run.requested_by,
            )
            break
        except AgentToolError as exc:
            step_state = AgentRunStep.objects.get(pk=step_id)
            retryable = (
                run.assessment_plan_id
                and exc.code in TRANSIENT_TOOL_CODES
                and attempt < step_state.max_retries
                and monotonic() - started < step_state.timeout_seconds
            )
            if retryable:
                attempt += 1
                AgentRunStep.objects.filter(pk=step_id).update(retry_count=attempt)
                security_logger.warning(
                    "agent_gateway_tool_retry run_id=%s step_id=%s tool=%s retry=%s code=%s",
                    run_id, step_id, tool_name, attempt, exc.code,
                )
                continue
            safe_error = AgentToolError(
                _safe_gateway_error(str(exc)),
                code=exc.code,
                failure_category=exc.failure_category,
            )
            _record_tool_failure(run_id=run_id, step_id=step_id, error=safe_error)
            http_status = 504 if exc.failure_category == AgentRun.FailureCategory.TIMEOUT else 502
            raise AgentGatewayExecutionError(
                str(safe_error),
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

    if run.assessment_plan_id:
        if monotonic() - started > expected_step.timeout_seconds:
            timeout_error = AgentToolError(
                "The approved tool call exceeded its step timeout.",
                code="AGENT_TOOL_TIMEOUT",
                failure_category=AgentRun.FailureCategory.TIMEOUT,
            )
            _record_tool_failure(run_id=run_id, step_id=step_id, error=timeout_error)
            raise AgentGatewayExecutionError(
                str(timeout_error), code=timeout_error.code, http_status=504
            )
        output = _bounded_tool_output(output)

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
        completed = not run.assessment_plan_id and not run.steps.exclude(
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
        if run.assessment_plan_id:
            security_logger.warning(
                "agent_gateway_tool_failed run_id=%s step_id=%s code=%s",
                run.id, step.id, error.code,
            )
            return
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


def _claim_tool_attempt(run_id: int, step_id: int) -> None:
    with transaction.atomic():
        run = AgentRun.objects.select_for_update().get(pk=run_id)
        step = AgentRunStep.objects.select_for_update().get(pk=step_id, run=run)
        limit = settings.MSAP_ASSESSMENT_EXECUTION_MAX_TOOL_CALLS
        if run.assessment_plan_id and run.tool_call_count >= limit:
            error = AgentToolError(
                "The approved assessment exceeded its tool-call limit.",
                code="TOOL_CALL_LIMIT_EXCEEDED",
                failure_category=AgentRun.FailureCategory.TOOL_EXECUTION_FAILED,
            )
            step.status = AgentRunStep.Status.FAILED
            step.failure_message = str(error)
            step.finished_at = timezone.now()
            step.save(update_fields=["status", "failure_message", "finished_at", "duration_seconds"])
            raise AgentGatewayExecutionError(str(error), code=error.code, http_status=409)
        run.tool_call_count += 1
        run.save(update_fields=["tool_call_count", "updated_at"])


def _bounded_tool_output(output) -> dict:
    if not isinstance(output, dict):
        raise AgentGatewayExecutionError(
            "The allowlisted tool returned an invalid structured result.",
            code="INVALID_TOOL_OUTPUT",
            http_status=502,
        )

    redacted = _redact_output(output)
    encoded = json.dumps(
        redacted, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    limit = settings.MSAP_ASSESSMENT_EXECUTION_MAX_OBSERVATION_BYTES
    if len(encoded) <= limit:
        return redacted
    return {
        "truncated": True,
        "original_sha256": sha256(encoded).hexdigest(),
        "preview": encoded[: min(8000, limit // 2)].decode("utf-8", errors="replace"),
    }


def _redact_output(value):
    if isinstance(value, dict):
        bounded = {}
        for key, child in list(value.items())[:500]:
            normalized = str(key).lower()
            bounded[str(key)] = (
                "[redacted]"
                if any(fragment in normalized for fragment in SECRET_KEY_FRAGMENTS)
                else _redact_output(child)
            )
        return bounded
    if isinstance(value, list):
        return [_redact_output(item) for item in value[:500]]
    if isinstance(value, str):
        cleaned = value
        for pattern in SECRET_VALUE_PATTERNS:
            cleaned = pattern.sub("[redacted]", cleaned)
        return cleaned[:65536]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return "[unsupported value redacted]"


def _safe_gateway_error(value: str) -> str:
    cleaned = value.replace("\x00", "")
    for pattern in SECRET_VALUE_PATTERNS:
        cleaned = pattern.sub("[redacted]", cleaned)
    return cleaned[:500]

from __future__ import annotations

import logging
from types import MappingProxyType

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from apps.api.roles import user_role
from apps.dynamic_analysis.models import (
    AgentRun,
    AgentRunArtifact,
    AgentRuntime,
    AgentRunStep,
    DynamicDevice,
)
from apps.dynamic_analysis.services.agent_tools import (
    AgentToolError,
    execute_agent_tool,
)
from apps.dynamic_analysis.services.agent_run_tokens import issue_agent_run_token
from apps.dynamic_analysis.services.container_runtime import (
    ContainerRuntimeError,
    ContainerRuntimeTimeout,
    run_container_sandbox,
)


logger = logging.getLogger(__name__)
security_logger = logging.getLogger("msap.security")

OBJECTIVE_PLANS = MappingProxyType(
    {
        AgentRun.Objective.DEVICE_READINESS_CHECK: (
            ("get_device_status", {}),
            ("take_screenshot", {"capture_reason": "device_readiness"}),
        ),
    }
)


class AgentControllerError(RuntimeError):
    pass


class AgentControllerPermissionError(AgentControllerError):
    pass


class AgentController:
    """Deterministic runtime controller with two bounded execution modes.

    The interface intentionally accepts an objective rather than a prompt or a
    caller-provided tool sequence. Both implementations execute the same fixed
    objective plan and persist the same normalized evidence contract.
    """

    def __init__(
        self,
        *,
        tool_executor=execute_agent_tool,
        container_executor=run_container_sandbox,
    ):
        self.tool_executor = tool_executor
        self.container_executor = container_executor

    def run(
        self,
        *,
        objective: str,
        requested_by,
        audit=None,
        runtime_type: str = AgentRuntime.RuntimeType.INTERNAL_CONTROLLER,
    ) -> AgentRun:
        self._validate_request(
            objective=objective,
            requested_by=requested_by,
            runtime_type=runtime_type,
        )
        runtime = self._select_runtime(runtime_type)
        with transaction.atomic():
            run = AgentRun.objects.create(
                audit=audit,
                runtime=runtime,
                objective=objective,
                requested_by=requested_by,
            )
            steps = [
                AgentRunStep.objects.create(
                    run=run,
                    sequence_number=sequence,
                    tool_name=tool_name,
                    input_summary=arguments,
                )
                for sequence, (tool_name, arguments) in enumerate(
                    OBJECTIVE_PLANS[objective],
                    start=1,
                )
            ]
        security_logger.info(
            "agent_run_requested run_id=%s objective=%s user_id=%s runtime_id=%s",
            run.id,
            objective,
            requested_by.pk,
            runtime.id if runtime else None,
        )
        if runtime is None:
            runtime_label = (
                "container sandbox"
                if runtime_type == AgentRuntime.RuntimeType.CONTAINER_SANDBOX
                else "internal agent"
            )
            return self._fail_before_execution(
                run,
                steps,
                category=AgentRun.FailureCategory.RUNTIME_UNAVAILABLE,
                message=f"No enabled {runtime_label} runtime is available.",
            )

        run.status = AgentRun.Status.RUNNING
        run.started_at = timezone.now()
        run.save(update_fields=["status", "started_at", "updated_at"])
        if runtime.runtime_type == AgentRuntime.RuntimeType.CONTAINER_SANDBOX:
            return self._run_container(run=run, steps=steps)
        return self._run_internal(
            run=run,
            steps=steps,
            runtime=runtime,
            requested_by=requested_by,
        )

    def _run_internal(
        self,
        *,
        run: AgentRun,
        steps: list[AgentRunStep],
        runtime: AgentRuntime,
        requested_by,
    ) -> AgentRun:
        outputs: dict[str, dict] = {}

        for step in steps:
            step.status = AgentRunStep.Status.RUNNING
            step.started_at = timezone.now()
            step.save(update_fields=["status", "started_at"])
            try:
                output = self.tool_executor(
                    step.tool_name,
                    step.input_summary,
                    requested_by=requested_by,
                )
            except AgentToolError as exc:
                step.status = (
                    AgentRunStep.Status.TIMEOUT
                    if exc.failure_category == AgentRun.FailureCategory.TIMEOUT
                    else AgentRunStep.Status.FAILED
                )
                step.failure_message = str(exc)
                step.finished_at = timezone.now()
                step.save(
                    update_fields=[
                        "status",
                        "failure_message",
                        "finished_at",
                        "duration_seconds",
                    ]
                )
                self._skip_pending_steps(steps)
                return self._finish_failed_run(
                    run,
                    outputs,
                    category=exc.failure_category,
                    message=str(exc),
                )
            except Exception as exc:  # pragma: no cover - defensive boundary
                logger.error(
                    "agent_tool_unexpected_failure run_id=%s step_id=%s error_type=%s",
                    run.id,
                    step.id,
                    type(exc).__name__,
                )
                step.status = AgentRunStep.Status.FAILED
                step.failure_message = "The allowlisted agent tool failed unexpectedly."
                step.finished_at = timezone.now()
                step.save(
                    update_fields=[
                        "status",
                        "failure_message",
                        "finished_at",
                        "duration_seconds",
                    ]
                )
                self._skip_pending_steps(steps)
                return self._finish_failed_run(
                    run,
                    outputs,
                    category=AgentRun.FailureCategory.INTERNAL_ERROR,
                    message="The controlled agent run failed unexpectedly.",
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
            outputs[step.tool_name] = output
            self._record_tool_artifact(run, step, output)
            if step.tool_name == "get_device_status" and output.get("serial"):
                run.device = DynamicDevice.objects.filter(
                    serial=output["serial"]
                ).first()
                run.save(update_fields=["device", "updated_at"])
            security_logger.info(
                "agent_tool_completed run_id=%s step_id=%s tool=%s status=%s",
                run.id,
                step.id,
                step.tool_name,
                step.status,
            )

        run.status = AgentRun.Status.SUCCEEDED
        run.finished_at = timezone.now()
        run.result_summary = self._result_summary(
            outputs,
            succeeded=True,
            runtime=runtime,
        )
        runtime.last_seen_at = run.finished_at
        runtime.save(update_fields=["last_seen_at", "updated_at"])
        run.save(
            update_fields=[
                "status",
                "finished_at",
                "duration_seconds",
                "result_summary",
                "updated_at",
            ]
        )
        security_logger.info("agent_run_completed run_id=%s status=SUCCEEDED", run.id)
        return run

    def _run_container(
        self,
        *,
        run: AgentRun,
        steps: list[AgentRunStep],
    ) -> AgentRun:
        try:
            run_token = issue_agent_run_token(run)
            self.container_executor(run=run, run_token=run_token)
        except ContainerRuntimeTimeout as exc:
            run.refresh_from_db()
            if run.status in self._terminal_statuses():
                return run
            self._mark_container_steps_failed(
                steps,
                status=AgentRunStep.Status.TIMEOUT,
                message="The sandbox stopped before the tool sequence completed.",
            )
            return self._finish_failed_run(
                run,
                self._completed_outputs(run),
                category=AgentRun.FailureCategory.TIMEOUT,
                message=str(exc),
            )
        except ContainerRuntimeError as exc:
            run.refresh_from_db()
            if run.status in self._terminal_statuses():
                return run
            self._mark_container_steps_failed(
                steps,
                status=AgentRunStep.Status.FAILED,
                message="The sandbox stopped before the tool sequence completed.",
            )
            return self._finish_failed_run(
                run,
                self._completed_outputs(run),
                category=AgentRun.FailureCategory.RUNTIME_UNAVAILABLE,
                message=str(exc),
            )
        except Exception as exc:  # pragma: no cover - defensive process boundary
            logger.error(
                "agent_container_unexpected_failure run_id=%s error_type=%s",
                run.id,
                type(exc).__name__,
            )
            run.refresh_from_db()
            if run.status in self._terminal_statuses():
                return run
            self._mark_container_steps_failed(
                steps,
                status=AgentRunStep.Status.FAILED,
                message="The sandbox stopped before the tool sequence completed.",
            )
            return self._finish_failed_run(
                run,
                self._completed_outputs(run),
                category=AgentRun.FailureCategory.INTERNAL_ERROR,
                message="The container sandbox failed unexpectedly.",
            )

        run.refresh_from_db()
        if run.status in self._terminal_statuses():
            return run
        self._mark_container_steps_failed(
            steps,
            status=AgentRunStep.Status.FAILED,
            message="The sandbox exited without completing the tool sequence.",
        )
        return self._finish_failed_run(
            run,
            self._completed_outputs(run),
            category=AgentRun.FailureCategory.TOOL_EXECUTION_FAILED,
            message="The container sandbox did not complete its controlled run.",
        )

    @staticmethod
    def _validate_request(
        *,
        objective: str,
        requested_by,
        runtime_type: str,
    ) -> None:
        if user_role(requested_by) not in {"ADMIN", "ANALYST"}:
            raise AgentControllerPermissionError(
                "Only an Analyst or Admin can start an agent run."
            )
        if objective not in OBJECTIVE_PLANS:
            raise AgentControllerError("The requested objective is not supported.")
        if runtime_type not in AgentRuntime.RuntimeType.values:
            raise AgentControllerError("The requested runtime type is not supported.")

    @staticmethod
    def _select_runtime(runtime_type: str) -> AgentRuntime | None:
        if (
            runtime_type == AgentRuntime.RuntimeType.CONTAINER_SANDBOX
            and not settings.MSAP_AGENT_CONTAINER_ENABLED
        ):
            return None
        return (
            AgentRuntime.objects.filter(
                enabled=True,
                status=AgentRuntime.Status.AVAILABLE,
                runtime_type=runtime_type,
            )
            .order_by("id")
            .first()
        )

    def _fail_before_execution(
        self,
        run: AgentRun,
        steps: list[AgentRunStep],
        *,
        category: str,
        message: str,
    ) -> AgentRun:
        now = timezone.now()
        for step in steps:
            step.status = AgentRunStep.Status.SKIPPED
            step.failure_message = "Skipped because the agent runtime was unavailable."
            step.finished_at = now
            step.save(update_fields=["status", "failure_message", "finished_at"])
        run.started_at = now
        return self._finish_failed_run(
            run,
            {},
            category=category,
            message=message,
        )

    @staticmethod
    def _skip_pending_steps(steps: list[AgentRunStep]) -> None:
        now = timezone.now()
        for pending_step in steps:
            if pending_step.status != AgentRunStep.Status.PENDING:
                continue
            pending_step.status = AgentRunStep.Status.SKIPPED
            pending_step.failure_message = "Skipped after a previous tool failed."
            pending_step.finished_at = now
            pending_step.save(
                update_fields=["status", "failure_message", "finished_at"]
            )

    def _finish_failed_run(
        self,
        run: AgentRun,
        outputs: dict[str, dict],
        *,
        category: str,
        message: str,
    ) -> AgentRun:
        run.status = (
            AgentRun.Status.TIMEOUT
            if category == AgentRun.FailureCategory.TIMEOUT
            else AgentRun.Status.FAILED
        )
        run.finished_at = timezone.now()
        run.failure_category = category
        run.failure_message = message
        run.result_summary = self._result_summary(
            outputs,
            succeeded=False,
            runtime=run.runtime,
        )
        run.save(
            update_fields=[
                "status",
                "started_at",
                "finished_at",
                "duration_seconds",
                "failure_category",
                "failure_message",
                "result_summary",
                "updated_at",
            ]
        )
        security_logger.warning(
            "agent_run_completed run_id=%s status=%s category=%s",
            run.id,
            run.status,
            category,
        )
        return run

    @staticmethod
    def _record_tool_artifact(
        run: AgentRun,
        step: AgentRunStep,
        output: dict,
    ) -> None:
        if step.tool_name == "take_screenshot":
            AgentRunArtifact.objects.create(
                run=run,
                step=step,
                artifact_type=AgentRunArtifact.ArtifactType.SCREENSHOT,
                name="device-readiness-screenshot.png",
                content_type="image/png",
                metadata=output,
            )
        else:
            AgentRunArtifact.objects.create(
                run=run,
                step=step,
                artifact_type=AgentRunArtifact.ArtifactType.JSON_RESULT,
                name="device-status.json",
                content_type="application/json",
                metadata=output,
            )

    @staticmethod
    def _result_summary(
        outputs: dict[str, dict],
        *,
        succeeded: bool,
        runtime: AgentRuntime | None = None,
    ) -> dict:
        status_output = outputs.get("get_device_status", {})
        screenshot_output = outputs.get("take_screenshot", {})
        host_reachable = status_output.get("host_agent_status") == "REACHABLE"
        emulator_reachable = status_output.get("emulator_status") == "REACHABLE"
        screenshot_captured = bool(screenshot_output.get("sha256"))
        environment_ready = bool(
            succeeded
            and status_output.get("ready")
            and screenshot_captured
        )
        return {
            "objective": AgentRun.Objective.DEVICE_READINESS_CHECK,
            "runtime_type": runtime.runtime_type if runtime else "",
            "runtime_name": runtime.name if runtime else "",
            "isolation_level": runtime.isolation_level if runtime else "",
            "host_agent_reachable": host_reachable,
            "emulator_reachable": emulator_reachable,
            "device": {
                "serial": status_output.get("serial") or "",
                "android_version": status_output.get("android_version") or "",
                "api_level": status_output.get("api_level"),
                "abi": status_output.get("abi") or "",
                "root_uid": status_output.get("root_uid"),
                "selinux": status_output.get("selinux") or "",
                "proxy": status_output.get("proxy") or "",
                "focused_app": status_output.get("focused_app") or "",
            },
            "screenshot_captured": screenshot_captured,
            "screenshot": screenshot_output,
            "environment_ready": environment_ready,
            "summary": (
                "The controlled environment is ready for future agentic dynamic assessment."
                if environment_ready
                else "The controlled environment is not ready; review the failed or skipped step."
            ),
            "assessment_scope": "Device readiness only; no vulnerability or malware verdict was produced.",
        }

    @staticmethod
    def _completed_outputs(run: AgentRun) -> dict[str, dict]:
        return {
            step.tool_name: step.output_summary
            for step in run.steps.filter(status=AgentRunStep.Status.SUCCEEDED)
        }

    @staticmethod
    def _terminal_statuses() -> set[str]:
        return {
            AgentRun.Status.SUCCEEDED,
            AgentRun.Status.FAILED,
            AgentRun.Status.CANCELLED,
            AgentRun.Status.TIMEOUT,
        }

    @staticmethod
    def _mark_container_steps_failed(
        steps: list[AgentRunStep],
        *,
        status: str,
        message: str,
    ) -> None:
        now = timezone.now()
        marked_failure = False
        for step in steps:
            step.refresh_from_db()
            if step.status == AgentRunStep.Status.SUCCEEDED:
                continue
            if not marked_failure:
                step.status = status
                step.failure_message = message
                if step.started_at is None:
                    step.started_at = now
                marked_failure = True
            else:
                step.status = AgentRunStep.Status.SKIPPED
                step.failure_message = "Skipped after the sandbox stopped."
            step.finished_at = now
            step.save(
                update_fields=[
                    "status",
                    "failure_message",
                    "started_at",
                    "finished_at",
                    "duration_seconds",
                ]
            )

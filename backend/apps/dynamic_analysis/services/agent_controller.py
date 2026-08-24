from __future__ import annotations

import logging
import json
from hashlib import sha256
from dataclasses import dataclass
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
    BUILTIN_FRIDA_UI_PROOF,
    execute_agent_tool,
)
from apps.dynamic_analysis.services.agent_run_tokens import issue_agent_run_token
from apps.dynamic_analysis.services.container_runtime import (
    ContainerRuntimeError,
    ContainerRuntimeTimeout,
    run_container_sandbox,
)
from apps.dynamic_analysis.services.frida_scripts import (
    RUNTIME_UI_MODIFICATION_PROOF_NAME,
    RUNTIME_UI_MODIFICATION_VALUE,
)


logger = logging.getLogger(__name__)
security_logger = logging.getLogger("msap.security")

PACKAGE_FROM_INSTALL = "__MSAP_PACKAGE_FROM_INSTALL__"
COLLECTOR_FROM_START = "__MSAP_COLLECTOR_FROM_START__"
COLLECTOR_FROM_PREVIOUS_STEP = "collector_from_previous_step"
PROXY_CAPTURE_FROM_PREVIOUS_STEP = "proxy_capture_from_previous_step"

KNOWN_RUNTIME_PLACEHOLDERS = frozenset(
    {
        PACKAGE_FROM_INSTALL,
        COLLECTOR_FROM_START,
        COLLECTOR_FROM_PREVIOUS_STEP,
        PROXY_CAPTURE_FROM_PREVIOUS_STEP,
    }
)


class RuntimePlaceholderError(RuntimeError):
    """A plan references a run-scoped value that no earlier approved step produced."""

    def __init__(self, message: str, *, code: str = "RUNTIME_PLACEHOLDER_UNRESOLVED"):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ObjectivePlanStep:
    tool_name: str
    arguments: dict
    skip_reason: str = ""


OBJECTIVE_PLANS = MappingProxyType(
    {
        AgentRun.Objective.DEVICE_READINESS_CHECK: (
            ObjectivePlanStep("get_device_status", {}),
            ObjectivePlanStep(
                "take_screenshot", {"capture_reason": "device_readiness"}
            ),
        ),
        AgentRun.Objective.BASIC_APP_INTERACTION_CHECK: (
            "get_device_status",
            "install_verified_apk",
            "launch_package",
            "take_screenshot",
            "dump_ui",
            "start_logcat",
            "tap_coordinates",
            "type_text",
            "get_logcat_excerpt",
            "force_stop_package",
        ),
        AgentRun.Objective.FRIDA_RUNTIME_ACTION: (
            "frida_status", "frida_setup", "frida_ps", "frida_attach",
        ),
        AgentRun.Objective.FRIDA_RUNTIME_UI_MODIFICATION_PROOF: (
            "get_device_status", "launch_package", "take_screenshot", "dump_ui",
            "frida_status", "frida_attach", "frida_run_js", "take_screenshot",
            "dump_ui", "force_stop_package",
        ),
        AgentRun.Objective.FRIDA_CUSTOM_SCRIPT: (
            "get_device_status", "launch_package", "take_screenshot", "dump_ui",
            "frida_run_js", "take_screenshot", "dump_ui", "force_stop_package",
        ),
    }
)


def build_objective_plan(
    objective: str,
    objective_input: dict | None = None,
) -> tuple[ObjectivePlanStep, ...]:
    """Build one fixed, typed plan from already validated objective input."""

    if objective == AgentRun.Objective.DEVICE_READINESS_CHECK:
        return OBJECTIVE_PLANS[objective]
    if objective == AgentRun.Objective.FRIDA_RUNTIME_ACTION:
        values = objective_input or {}
        package_name = values.get("package_name")
        operation = values.get("operation")
        if operation == "status":
            return (
                ObjectivePlanStep("launch_package", {"package_name": package_name}),
                ObjectivePlanStep("frida_status", {"package_name": package_name}),
            )
        if operation == "setup":
            return (ObjectivePlanStep("frida_setup", {"package_name": package_name}),)
        if operation == "ps":
            return (ObjectivePlanStep("frida_ps", {}),)
        if operation == "attach":
            return (
                ObjectivePlanStep("launch_package", {"package_name": package_name}),
                ObjectivePlanStep(
                    "frida_attach",
                    {
                        "package_name": package_name,
                        "mode": values.get("mode", "attach"),
                        "timeout": values.get("timeout", 10),
                    },
                ),
            )
        raise AgentControllerError("The requested Frida runtime action is not supported.")
    if objective == AgentRun.Objective.FRIDA_RUNTIME_UI_MODIFICATION_PROOF:
        values = objective_input or {}
        package_name = values.get("package_name")
        return (
            ObjectivePlanStep("get_device_status", {}),
            ObjectivePlanStep("launch_package", {"package_name": package_name}),
            ObjectivePlanStep("take_screenshot", {"capture_reason": "instrumentation_before", "audit_id": values.get("audit_id")}),
            ObjectivePlanStep("dump_ui", {"package_name": package_name}),
            ObjectivePlanStep("frida_status", {"package_name": package_name}),
            ObjectivePlanStep(
                "frida_attach",
                {"package_name": package_name, "mode": "attach", "timeout": 10},
            ),
            ObjectivePlanStep(
                "frida_run_js",
                {
                    "package_name": package_name,
                    "mode": "attach",
                    "source": BUILTIN_FRIDA_UI_PROOF,
                    "timeout": 12,
                    "capture_logcat": True,
                    "capture_screenshot": False,
                },
            ),
            ObjectivePlanStep("take_screenshot", {"capture_reason": "instrumentation_after", "audit_id": values.get("audit_id")}),
            ObjectivePlanStep("dump_ui", {"package_name": package_name}),
            ObjectivePlanStep("force_stop_package", {"package_name": package_name}),
        )
    if objective == AgentRun.Objective.FRIDA_CUSTOM_SCRIPT:
        values = objective_input or {}
        package_name = values.get("package_name")
        return (
            ObjectivePlanStep("get_device_status", {}),
            ObjectivePlanStep("launch_package", {"package_name": package_name}),
            ObjectivePlanStep("take_screenshot", {"capture_reason": "instrumentation_before", "audit_id": values.get("audit_id")}),
            ObjectivePlanStep("dump_ui", {"package_name": package_name}),
            ObjectivePlanStep(
                "frida_run_js",
                {
                    "package_name": package_name,
                    "mode": values.get("mode", "attach"),
                    "source": values.get("source"),
                    "timeout": values.get("timeout", 12),
                    "capture_logcat": bool(values.get("capture_logcat", True)),
                    "capture_screenshot": False,
                },
            ),
            ObjectivePlanStep("take_screenshot", {"capture_reason": "instrumentation_after", "audit_id": values.get("audit_id")}),
            ObjectivePlanStep("dump_ui", {"package_name": package_name}),
            ObjectivePlanStep("force_stop_package", {"package_name": package_name}),
        )
    if objective != AgentRun.Objective.BASIC_APP_INTERACTION_CHECK:
        raise AgentControllerError("The requested objective is not supported.")
    values = objective_input or {}
    apk_file_id = values.get("apk_file_id")
    explicit_package = values.get("package_name")
    package_name = explicit_package or PACKAGE_FROM_INSTALL
    tap = values.get("tap")
    text = values.get("text")
    return (
        ObjectivePlanStep("get_device_status", {}),
        ObjectivePlanStep(
            "install_verified_apk",
            {
                "audit_id": values.get("audit_id"),
                "apk_file_id": apk_file_id,
            },
            "Skipped because the objective targets an already installed package."
            if apk_file_id is None
            else "",
        ),
        ObjectivePlanStep("launch_package", {"package_name": package_name}),
        ObjectivePlanStep("take_screenshot", {"capture_reason": "manual_check"}),
        ObjectivePlanStep("dump_ui", {"package_name": package_name}),
        ObjectivePlanStep(
            "start_logcat",
            {
                "package_name": package_name,
                "reason": "agent_step",
                "max_seconds": 60,
            },
        ),
        ObjectivePlanStep(
            "tap_coordinates",
            {
                "x": tap.get("x") if isinstance(tap, dict) else None,
                "y": tap.get("y") if isinstance(tap, dict) else None,
                "reason": "agent_navigation",
            },
            "Skipped because no tap coordinates were provided."
            if tap is None
            else "",
        ),
        ObjectivePlanStep(
            "type_text",
            {"text": text, "reason": "agent_navigation"},
            "Skipped because no text was provided." if text is None else "",
        ),
        ObjectivePlanStep(
            "get_logcat_excerpt",
            {"collector_id": COLLECTOR_FROM_START, "max_lines": 100},
        ),
        ObjectivePlanStep("force_stop_package", {"package_name": package_name}),
    )


def resolve_runtime_arguments(arguments: dict, outputs: dict[str, dict]) -> dict:
    resolved = dict(arguments)
    for key, value in tuple(resolved.items()):
        if value == PACKAGE_FROM_INSTALL:
            value = outputs.get("install_verified_apk", {}).get("package_name")
        elif value in {COLLECTOR_FROM_START, COLLECTOR_FROM_PREVIOUS_STEP}:
            value = outputs.get("start_logcat", {}).get("collector_id")
        resolved[key] = value
    return resolved


def resolve_approved_plan_arguments(
    arguments: dict,
    completed_outputs: dict[str, dict],
) -> dict:
    """Resolve only the closed set of run-scoped placeholders in plan arguments.

    No arbitrary variable interpolation is performed: a value must exactly equal
    a known placeholder constant, and the replacement value is read only from a
    bounded completed tool output of the same AgentRun. Any other value is
    preserved verbatim. An unresolved placeholder fails with a deterministic
    ``RuntimePlaceholderError`` so no model- or plan-supplied value can ever be
    interpreted as a dynamic reference into unrelated data.
    """
    resolved = dict(arguments)
    for key, value in tuple(resolved.items()):
        if value not in KNOWN_RUNTIME_PLACEHOLDERS:
            continue
        if value == PACKAGE_FROM_INSTALL:
            package_name = (completed_outputs.get("install_verified_apk") or {}).get(
                "package_name"
            )
            if not isinstance(package_name, str) or not package_name:
                raise RuntimePlaceholderError(
                    "The approved plan references the installed package, but no "
                    "earlier approved step produced one (argument '%s')." % key
                )
            resolved[key] = package_name
            continue
        if value == PROXY_CAPTURE_FROM_PREVIOUS_STEP:
            capture_id = (completed_outputs.get("start_proxy_capture") or {}).get(
                "capture_id"
            )
            if not isinstance(capture_id, str) or not capture_id:
                raise RuntimePlaceholderError(
                    "The approved plan references a proxy capture, but no earlier "
                    "approved step produced one (argument '%s')." % key
                )
            resolved[key] = capture_id
            continue
        collector_id = (completed_outputs.get("start_logcat") or {}).get(
            "collector_id"
        )
        if not isinstance(collector_id, str) or not collector_id:
            raise RuntimePlaceholderError(
                "The approved plan references a logcat collector, but no earlier "
                "approved step produced one (argument '%s')." % key
            )
        resolved[key] = collector_id
    return resolved


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
        objective_input: dict | None = None,
        runtime_type: str = AgentRuntime.RuntimeType.INTERNAL_CONTROLLER,
    ) -> AgentRun:
        self._validate_request(
            objective=objective,
            objective_input=objective_input,
            requested_by=requested_by,
            runtime_type=runtime_type,
        )
        runtime = self._select_runtime(runtime_type)
        plan = build_objective_plan(objective, objective_input)
        with transaction.atomic():
            run = AgentRun.objects.create(
                audit=audit,
                runtime=runtime,
                objective=objective,
                objective_input=objective_input or {},
                requested_by=requested_by,
            )
            steps = [
                AgentRunStep.objects.create(
                    run=run,
                    sequence_number=sequence,
                    tool_name=plan_step.tool_name,
                    input_summary=plan_step.arguments,
                    status=(
                        AgentRunStep.Status.SKIPPED
                        if plan_step.skip_reason
                        else AgentRunStep.Status.PENDING
                    ),
                    failure_message=plan_step.skip_reason,
                    finished_at=(timezone.now() if plan_step.skip_reason else None),
                )
                for sequence, plan_step in enumerate(plan, start=1)
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
            if step.status == AgentRunStep.Status.SKIPPED:
                continue
            resolved_arguments = resolve_runtime_arguments(step.input_summary, outputs)
            step.input_summary = resolved_arguments
            step.status = AgentRunStep.Status.RUNNING
            step.started_at = timezone.now()
            step.save(update_fields=["input_summary", "status", "started_at"])
            try:
                output = self.tool_executor(
                    step.tool_name,
                    resolved_arguments,
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
            outputs[self._output_key(run, step, outputs)] = output
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

        run.finished_at = timezone.now()
        run.result_summary = self._result_summary(
            outputs,
            succeeded=True,
            runtime=runtime,
            run=run,
        )
        proof_failed = bool(
            run.objective == AgentRun.Objective.FRIDA_RUNTIME_UI_MODIFICATION_PROOF
            and not run.result_summary.get("evidence_confirmed")
        )
        run.status = AgentRun.Status.FAILED if proof_failed else AgentRun.Status.SUCCEEDED
        if proof_failed:
            run.failure_category = AgentRun.FailureCategory.TOOL_EXECUTION_FAILED
            run.failure_message = (
                "Frida executed, but the required before/after visible modification "
                "evidence was not confirmed."
            )
        self._record_instrumentation_evidence(run, outputs)
        self._redact_persisted_text(run)
        runtime.last_seen_at = run.finished_at
        runtime.save(update_fields=["last_seen_at", "updated_at"])
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
        security_logger.info("agent_run_completed run_id=%s status=%s", run.id, run.status)
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
        objective_input: dict | None,
        requested_by,
        runtime_type: str,
    ) -> None:
        if user_role(requested_by) not in {"ADMIN", "ANALYST"}:
            raise AgentControllerPermissionError(
                "Only an Analyst or Admin can start an agent run."
            )
        if objective not in OBJECTIVE_PLANS:
            raise AgentControllerError("The requested objective is not supported.")
        if objective == AgentRun.Objective.DEVICE_READINESS_CHECK and objective_input:
            raise AgentControllerError("Device readiness does not accept objective input.")
        if objective == AgentRun.Objective.BASIC_APP_INTERACTION_CHECK:
            if not isinstance(objective_input, dict) or not objective_input:
                raise AgentControllerError(
                    "Basic app interaction requires validated objective input."
                )
        if objective in {
            AgentRun.Objective.FRIDA_RUNTIME_ACTION,
            AgentRun.Objective.FRIDA_RUNTIME_UI_MODIFICATION_PROOF,
            AgentRun.Objective.FRIDA_CUSTOM_SCRIPT,
        } and (not isinstance(objective_input, dict) or not objective_input):
            raise AgentControllerError(
                "Runtime instrumentation requires validated objective input."
            )
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
            run=run,
        )
        self._record_instrumentation_evidence(run, outputs)
        self._redact_persisted_text(run)
        run.save(
            update_fields=[
                "status",
                "started_at",
                "finished_at",
                "duration_seconds",
                "failure_category",
                "failure_message",
                "result_summary",
                "objective_input",
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
        encoded = json.dumps(
            output,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        metadata_sha256 = sha256(encoded).hexdigest()
        if step.tool_name == "take_screenshot":
            capture_reason = str((step.input_summary or {}).get("capture_reason") or "")
            screenshot_name = {
                "device_readiness": "device-readiness-screenshot.png",
                "manual_check": "basic-app-interaction-screenshot.png",
                "instrumentation_before": "frida-before-screenshot.png",
                "instrumentation_after": "frida-after-screenshot.png",
            }.get(capture_reason, "agent-screenshot.png")
            AgentRunArtifact.objects.create(
                run=run,
                step=step,
                artifact_type=AgentRunArtifact.ArtifactType.SCREENSHOT,
                name=screenshot_name,
                content_type="image/png",
                object_reference_id=output.get("object_reference_id"),
                metadata=output,
                size_bytes=output.get("size_bytes"),
                sha256=output.get("sha256") or metadata_sha256,
            )
        else:
            artifact_type = (
                AgentRunArtifact.ArtifactType.LOG
                if step.tool_name == "get_logcat_excerpt"
                else AgentRunArtifact.ArtifactType.JSON_RESULT
            )
            AgentRunArtifact.objects.create(
                run=run,
                step=step,
                artifact_type=artifact_type,
                name=f"{step.tool_name.replace('_', '-')}.json",
                content_type="application/json",
                metadata=output,
                size_bytes=len(encoded),
                sha256=metadata_sha256,
            )

    @staticmethod
    def _record_instrumentation_evidence(run: AgentRun, outputs: dict[str, dict]) -> None:
        if run.objective not in {
            AgentRun.Objective.FRIDA_RUNTIME_UI_MODIFICATION_PROOF,
            AgentRun.Objective.FRIDA_CUSTOM_SCRIPT,
        }:
            return
        summary = run.result_summary or {}
        frida_output = outputs.get("frida_run_js", {})
        status_output = outputs.get("frida_status", {})
        before_screenshot = outputs.get("before_screenshot", {})
        after_screenshot = outputs.get("after_screenshot", {})
        before_ui = outputs.get("before_ui", {})
        after_ui = outputs.get("after_ui", {})
        logcat = frida_output.get("logcat", {})
        metadata = {
            "run_id": run.id,
            "package": summary.get("package_name", ""),
            "pid": summary.get("pid"),
            "serial": status_output.get("emulator_serial") or (
                run.device.serial if run.device_id else ""
            ),
            "frida_client_version": summary.get("frida_client_version", ""),
            "frida_server_version": summary.get("frida_server_version", ""),
            "script_sha256": frida_output.get("script_sha256", ""),
            "script_name": summary.get("script_name", ""),
            "execution_start": frida_output.get("started_at", ""),
            "execution_end": frida_output.get("finished_at", ""),
            "duration_seconds": frida_output.get("duration_seconds"),
            "attach_result": summary.get("attach_succeeded", False),
            "event_count": frida_output.get("event_count", 0),
            "error_count": frida_output.get("error_count", 0),
            "before_screenshot_digest": before_screenshot.get("sha256", ""),
            "after_screenshot_digest": after_screenshot.get("sha256", ""),
            "before_ui_digest": before_ui.get("xml_sha256", ""),
            "after_ui_digest": after_ui.get("xml_sha256", ""),
            "logcat_digest": logcat.get("sha256", ""),
            "logcat_summary": {
                "t0": logcat.get("t0", ""),
                "t1": logcat.get("t1", ""),
                "t2": logcat.get("t2", ""),
                "line_count": logcat.get("line_count", 0),
                "redaction_applied": bool(logcat.get("redaction_applied")),
            },
            "interpretation": summary.get("interpretation", ""),
            "limitations": summary.get("limitations", ""),
        }
        AgentRunArtifact.objects.update_or_create(
            run=run,
            name="frida-instrumentation-evidence.json",
            defaults={
                "artifact_type": AgentRunArtifact.ArtifactType.JSON_RESULT,
                "content_type": "application/json",
                "metadata": metadata,
            },
        )
    @staticmethod
    def _result_summary(
        outputs: dict[str, dict],
        *,
        succeeded: bool,
        runtime: AgentRuntime | None = None,
        run: AgentRun | None = None,
    ) -> dict:
        if run is not None and run.objective == AgentRun.Objective.FRIDA_RUNTIME_ACTION:
            operation = (run.objective_input or {}).get("operation", "")
            action_output = outputs.get(
                {
                    "status": "frida_status",
                    "setup": "frida_setup",
                    "ps": "frida_ps",
                    "attach": "frida_attach",
                }.get(operation, ""),
                {},
            )
            return {
                "objective": run.objective,
                "runtime_type": runtime.runtime_type if runtime else "",
                "runtime_name": runtime.name if runtime else "",
                "package_name": (run.objective_input or {}).get("package_name", ""),
                "operation": operation,
                "completed": bool(succeeded),
                "result": action_output,
                "assessment_scope": "Runtime instrumentation environment evidence only; no vulnerability verdict was produced.",
            }
        if run is not None and run.objective in {
            AgentRun.Objective.FRIDA_RUNTIME_UI_MODIFICATION_PROOF,
            AgentRun.Objective.FRIDA_CUSTOM_SCRIPT,
        }:
            before_screenshot = outputs.get("before_screenshot", {})
            after_screenshot = outputs.get("after_screenshot", {})
            before_ui = outputs.get("before_ui", {})
            after_ui = outputs.get("after_ui", {})
            frida_output = outputs.get("frida_run_js", {})
            status_output = outputs.get("frida_status", {})
            attach_output = outputs.get("frida_attach", {})
            events = frida_output.get("events", [])
            modification_event = next(
                (
                    event for event in events
                    if isinstance(event, dict)
                    and event.get("type") == "ui_modification"
                ),
                {},
            )
            screenshot_changed = bool(
                before_screenshot.get("sha256")
                and after_screenshot.get("sha256")
                and before_screenshot.get("sha256") != after_screenshot.get("sha256")
            )
            ui_changed = bool(
                before_ui.get("xml_sha256")
                and after_ui.get("xml_sha256")
                and before_ui.get("xml_sha256") != after_ui.get("xml_sha256")
            )
            modification_confirmed = bool(
                modification_event.get("success") is True
                and modification_event.get("new_value") == RUNTIME_UI_MODIFICATION_VALUE
            )
            proof_objective = (
                run.objective
                == AgentRun.Objective.FRIDA_RUNTIME_UI_MODIFICATION_PROOF
            )
            evidence_confirmed = bool(
                succeeded
                and (modification_confirmed and screenshot_changed if proof_objective else True)
            )
            return {
                "objective": run.objective,
                "runtime_type": runtime.runtime_type if runtime else "",
                "runtime_name": runtime.name if runtime else "",
                "package_name": (run.objective_input or {}).get("package_name", ""),
                "script_name": (
                    RUNTIME_UI_MODIFICATION_PROOF_NAME
                    if proof_objective
                    else "Analyst custom Frida script"
                ),
                "execution_succeeded": bool(succeeded),
                "evidence_confirmed": evidence_confirmed,
                "pid": frida_output.get("pid") or attach_output.get("pid"),
                "frida_client_version": status_output.get("frida_client_version") or frida_output.get("frida_version", ""),
                "frida_server_version": status_output.get("frida_server_version", ""),
                "attach_succeeded": bool(attach_output.get("attach_event_received") or frida_output.get("pid")),
                "frida_event": modification_event,
                "frida_event_received": modification_confirmed,
                "before_screenshot": before_screenshot,
                "after_screenshot": after_screenshot,
                "before_ui": before_ui,
                "after_ui": after_ui,
                "before_ui_node_count": before_ui.get("node_count"),
                "after_ui_node_count": after_ui.get("node_count"),
                "screenshot_changed": screenshot_changed,
                "ui_changed": ui_changed,
                "visual_state_changed": screenshot_changed,
                "logcat": frida_output.get("logcat", {}),
                "event_count": frida_output.get("event_count", 0),
                "error_count": frida_output.get("error_count", 0),
                "cleanup_state": frida_output.get("cleanup_state", ""),
                "interpretation": (
                    "Runtime instrumentation successfully modified the target application. The evidence confirms code execution inside the target process."
                    if evidence_confirmed and proof_objective
                    else "Runtime instrumentation evidence was captured without making a vulnerability determination."
                ),
                "limitations": "Visible UI modification is an instrumentation proof, not a vulnerability or malware verdict.",
                "assessment_scope": "Runtime instrumentation evidence only; no vulnerability or malware verdict was produced.",
            }
        if run is not None and run.objective == AgentRun.Objective.BASIC_APP_INTERACTION_CHECK:
            screenshot_output = outputs.get("take_screenshot", {})
            install_output = outputs.get("install_verified_apk", {})
            launch_output = outputs.get("launch_package", {})
            ui_output = outputs.get("dump_ui", {})
            logcat_output = outputs.get("get_logcat_excerpt", {})
            capture_output = outputs.get("start_logcat", {})
            force_stop_output = outputs.get("force_stop_package", {})
            used_apk = bool((run.objective_input or {}).get("apk_file_id"))
            return {
                "objective": AgentRun.Objective.BASIC_APP_INTERACTION_CHECK,
                "runtime_type": runtime.runtime_type if runtime else "",
                "runtime_name": runtime.name if runtime else "",
                "isolation_level": runtime.isolation_level if runtime else "",
                "app_installed": bool(used_apk and install_output.get("install_status") == "PASS"),
                "app_already_present": not used_apk,
                "package_name": (
                    install_output.get("package_name")
                    or (run.objective_input or {}).get("package_name")
                    or ""
                ),
                "app_launched": bool(launch_output.get("launched")),
                "screenshot_captured": bool(screenshot_output.get("sha256")),
                "screenshot": screenshot_output,
                "ui_dumped": bool(
                    ui_output.get("capture_status") == "CAPTURED"
                    and (ui_output.get("node_count") or 0) > 0
                    and ui_output.get("xml_sha256")
                ),
                "ui_dump": ui_output,
                "logcat_captured": bool(capture_output.get("collector_id")),
                "logcat_excerpt": logcat_output,
                "tap_executed": bool(outputs.get("tap_coordinates", {}).get("tapped")),
                "tap_skipped": "tap" not in (run.objective_input or {}),
                "type_executed": bool(outputs.get("type_text", {}).get("typed")),
                "type_skipped": "text" not in (run.objective_input or {}),
                "force_stop_completed": bool(force_stop_output.get("stopped")),
                "interaction_completed": bool(succeeded),
                "summary": (
                    "The bounded basic app interaction sequence completed."
                    if succeeded
                    else "The bounded basic app interaction sequence ended with a controlled failure."
                ),
                "assessment_scope": (
                    "Interaction evidence only; no vulnerability or malware verdict was produced."
                ),
            }
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
        outputs: dict[str, dict] = {}
        for step in run.steps.filter(status=AgentRunStep.Status.SUCCEEDED).order_by(
            "sequence_number"
        ):
            outputs[AgentController._output_key(run, step, outputs)] = step.output_summary
        return outputs

    @staticmethod
    def _output_key(run: AgentRun, step: AgentRunStep, outputs: dict[str, dict]) -> str:
        if run.objective in {
            AgentRun.Objective.FRIDA_RUNTIME_UI_MODIFICATION_PROOF,
            AgentRun.Objective.FRIDA_CUSTOM_SCRIPT,
        }:
            if step.tool_name == "take_screenshot":
                return (
                    "before_screenshot"
                    if "before_screenshot" not in outputs
                    else "after_screenshot"
                )
            if step.tool_name == "dump_ui":
                return "before_ui" if "before_ui" not in outputs else "after_ui"
        return step.tool_name

    @staticmethod
    def _redact_persisted_text(run: AgentRun) -> None:
        objective_input = dict(run.objective_input or {})
        text = objective_input.get("text")
        if isinstance(text, str) and text != "[redacted]":
            objective_input["text"] = "[redacted]"
            objective_input["text_length"] = len(text)
            run.objective_input = objective_input
        source = objective_input.get("source")
        if isinstance(source, str) and source != "[redacted]":
            from hashlib import sha256

            objective_input["source"] = "[redacted]"
            objective_input["script_size_bytes"] = len(source.encode("utf-8"))
            objective_input["script_sha256"] = sha256(source.encode("utf-8")).hexdigest()
            run.objective_input = objective_input
        for step in run.steps.filter(tool_name="type_text"):
            input_summary = dict(step.input_summary or {})
            step_text = input_summary.get("text")
            if isinstance(step_text, str) and step_text != "[redacted]":
                input_summary["text"] = "[redacted]"
                input_summary["text_length"] = len(step_text)
                step.input_summary = input_summary
                step.save(update_fields=["input_summary"])
        for step in run.steps.filter(tool_name="frida_run_js"):
            input_summary = dict(step.input_summary or {})
            step_source = input_summary.get("source")
            if isinstance(step_source, str) and step_source != "[redacted]":
                from hashlib import sha256

                input_summary["source"] = "[redacted]"
                input_summary["script_size_bytes"] = len(step_source.encode("utf-8"))
                input_summary["script_sha256"] = sha256(step_source.encode("utf-8")).hexdigest()
                step.input_summary = input_summary
                step.save(update_fields=["input_summary"])

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
            if step.status in {
                AgentRunStep.Status.SUCCEEDED,
                AgentRunStep.Status.SKIPPED,
            }:
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

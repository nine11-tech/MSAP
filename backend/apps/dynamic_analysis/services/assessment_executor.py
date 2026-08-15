from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import logging
import re
from time import monotonic
from typing import Any, Callable

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.api.roles import user_role
from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.dynamic_analysis.models import (
    AgentRun,
    AgentRunArtifact,
    AgentRuntime,
    AgentRunStep,
    AssessmentPlan,
    AssessmentPlanStep,
)
from apps.dynamic_analysis.services.agent_gateway import (
    AgentGatewayExecutionError,
    AgentGatewayRequestError,
    execute_run_tool_call,
)
from apps.dynamic_analysis.services.agent_tools import TOOL_MANIFEST
from apps.dynamic_analysis.services.assessment_execution_contract import (
    AssessmentExecutionContractError,
    build_approved_execution_contract,
    validate_approved_execution_contract,
)
from apps.dynamic_analysis.services.assessment_plan_contract import MAX_PLAN_STEPS
from apps.evidence.models import Evidence


logger = logging.getLogger(__name__)
security_logger = logging.getLogger("msap.security")

OBSERVATION_CONTRACT_VERSION = "msap.agent-observation/v1"
CONTROL_STEP_NAME = "assessment_plan_observation"
MAX_EVIDENCE_SNIPPET_CHARS = 4000
MAX_SAFE_ERROR_CHARS = 500
SECRET_KEY_RE = re.compile(
    r"(?:api[_-]?key|authorization|bearer|cookie|credential|password|private[_-]?key|secret|session|token)",
    re.IGNORECASE,
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


class AssessmentExecutionError(RuntimeError):
    def __init__(self, message: str, *, code: str, http_status: int = 409):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


class AssessmentExecutionPermissionError(AssessmentExecutionError):
    def __init__(self):
        super().__init__(
            "Only an Analyst or Admin can execute an approved assessment plan.",
            code="ASSESSMENT_EXECUTION_FORBIDDEN",
            http_status=403,
        )


class AssessmentExecutor:
    """Sequential executor for one immutable ApprovedAssessmentPlan v1 snapshot."""

    def __init__(
        self,
        *,
        gateway_executor: Callable[..., dict[str, Any]] = execute_run_tool_call,
        clock: Callable[[], float] = monotonic,
    ):
        self.gateway_executor = gateway_executor
        self.clock = clock

    def create_run(
        self,
        *,
        plan: AssessmentPlan,
        requested_by,
        runtime_type: str = AgentRuntime.RuntimeType.INTERNAL_CONTROLLER,
    ) -> AgentRun:
        if user_role(requested_by) not in {"ADMIN", "ANALYST"}:
            raise AssessmentExecutionPermissionError()
        if runtime_type not in AgentRuntime.RuntimeType.values:
            raise AssessmentExecutionError(
                "The requested execution runtime is unsupported.",
                code="ASSESSMENT_RUNTIME_INVALID",
            )
        if runtime_type != AgentRuntime.RuntimeType.INTERNAL_CONTROLLER:
            raise AssessmentExecutionError(
                "Approved-plan execution currently uses the backend execution worker.",
                code="ASSESSMENT_RUNTIME_UNSUPPORTED",
            )

        try:
            with transaction.atomic():
                persisted = (
                    AssessmentPlan.objects.select_for_update()
                    .get(pk=plan.pk)
                )
                contract = build_approved_execution_contract(persisted)
                canonical = contract["approved_plan"]
                self._validate_live_authorization(persisted, canonical)
                runtime = self._select_runtime(runtime_type)
                if runtime is None:
                    raise AssessmentExecutionError(
                        "No enabled execution runtime is available.",
                        code="ASSESSMENT_RUNTIME_UNAVAILABLE",
                        http_status=503,
                    )
                required_tools = {
                    tool["name"]
                    for step in canonical["steps"]
                    for tool in step["tools"]
                }
                runtime_capabilities = (
                    runtime.capabilities if isinstance(runtime.capabilities, dict) else {}
                )
                runtime_tools = set(runtime_capabilities.get("tools", []))
                if not required_tools <= runtime_tools:
                    raise AssessmentExecutionError(
                        "The selected runtime no longer exposes every approved capability.",
                        code="ASSESSMENT_RUNTIME_CAPABILITY_MISMATCH",
                        http_status=503,
                    )
                if AgentRun.objects.filter(assessment_plan=persisted).exists():
                    raise AssessmentExecutionError(
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
                    objective=AgentRun.Objective.ASSESSMENT_PLAN_EXECUTION,
                    objective_input={
                        "assessment_plan_id": persisted.id,
                        "approved_plan_hash": persisted.plan_hash,
                    },
                    requested_by=requested_by,
                )
                self._materialize_steps(run, canonical)
                persisted.status = AssessmentPlan.Status.EXECUTING
                persisted.save(update_fields=["status", "updated_at"])
        except AssessmentPlan.DoesNotExist:
            raise AssessmentExecutionError(
                "The approved assessment plan no longer exists.",
                code="ASSESSMENT_PLAN_NOT_FOUND",
                http_status=404,
            ) from None
        except AssessmentExecutionContractError as exc:
            raise AssessmentExecutionError(
                str(exc),
                code="ASSESSMENT_PLAN_NOT_EXECUTABLE",
            ) from None
        except IntegrityError:
            raise AssessmentExecutionError(
                "This approved assessment plan already has an execution run.",
                code="ASSESSMENT_PLAN_ALREADY_EXECUTED",
            ) from None

        security_logger.info(
            "assessment_execution_created run_id=%s plan_id=%s plan_hash=%s user_id=%s",
            run.id,
            persisted.id,
            persisted.plan_hash,
            requested_by.pk,
        )
        return run

    def execute(self, run_id: int) -> AgentRun:
        run = self._start_run(run_id)
        deadline = self.clock() + settings.MSAP_ASSESSMENT_EXECUTION_TOTAL_TIMEOUT_SECONDS
        any_failure = False

        for step_id in run.steps.order_by("sequence_number").values_list("id", flat=True):
            run.refresh_from_db()
            if run.cancellation_requested_at is not None:
                return self._finish_cancelled(run)
            if self.clock() >= deadline:
                return self._finish_timeout(run, "The approved assessment exceeded its total execution limit.")

            step = AgentRunStep.objects.get(pk=step_id, run=run)
            dependency_failure = self._dependency_failure(run, step)
            if dependency_failure:
                self._skip_step(step, dependency_failure)
                any_failure = True
                continue
            if step.is_control_step:
                self._complete_control_step(step)
                continue

            started = self.clock()
            try:
                result = self.gateway_executor(
                    run_id=run.id,
                    tool_name=step.tool_name,
                    arguments=deepcopy(step.input_summary),
                )
            except AgentGatewayExecutionError:
                step.refresh_from_db()
                any_failure = True
                self._record_failed_observation(run, step)
                continue
            except AgentGatewayRequestError as exc:
                step.refresh_from_db()
                if step.status == AgentRunStep.Status.PENDING:
                    self._fail_step(step, str(exc))
                any_failure = True
                self._record_failed_observation(run, step)
                continue

            elapsed = self.clock() - started
            step.refresh_from_db()
            if elapsed > step.timeout_seconds:
                self._mark_step_timeout(step, "The approved tool call exceeded its step timeout.")
                any_failure = True
                continue
            try:
                self._record_successful_observation(run, step, result.get("output", {}))
            except AssessmentExecutionError as exc:
                self._fail_step(step, str(exc))
                any_failure = True

        run.refresh_from_db()
        if run.cancellation_requested_at is not None:
            return self._finish_cancelled(run)
        return self._finish(run, failed=any_failure or run.steps.filter(
            status__in=[AgentRunStep.Status.FAILED, AgentRunStep.Status.TIMEOUT]
        ).exists())

    @staticmethod
    def request_cancellation(run: AgentRun, *, requested_by) -> AgentRun:
        if user_role(requested_by) not in {"ADMIN", "ANALYST"}:
            raise AssessmentExecutionPermissionError()
        with transaction.atomic():
            run = AgentRun.objects.select_for_update().get(pk=run.pk)
            if run.objective != AgentRun.Objective.ASSESSMENT_PLAN_EXECUTION:
                raise AssessmentExecutionError(
                    "Only approved-plan execution runs use this cancellation endpoint.",
                    code="ASSESSMENT_CANCELLATION_UNSUPPORTED",
                )
            if run.status in {
                AgentRun.Status.SUCCEEDED,
                AgentRun.Status.FAILED,
                AgentRun.Status.CANCELLED,
                AgentRun.Status.TIMEOUT,
            }:
                return run
            now = timezone.now()
            run.cancellation_requested_at = now
            run.cancelled_by = requested_by
            if run.status == AgentRun.Status.QUEUED:
                run.status = AgentRun.Status.CANCELLED
                run.started_at = now
                run.finished_at = now
                run.failure_message = "Assessment execution cancelled before worker execution."
                run.steps.filter(status=AgentRunStep.Status.PENDING).update(
                    status=AgentRunStep.Status.CANCELLED,
                    failure_message="Cancelled before execution.",
                    finished_at=now,
                )
                if run.assessment_plan_id:
                    AssessmentPlan.objects.filter(pk=run.assessment_plan_id).update(
                        status=AssessmentPlan.Status.CANCELLED,
                        updated_at=now,
                    )
                    AssessmentPlanStep.objects.filter(plan_id=run.assessment_plan_id).update(
                        status=AssessmentPlanStep.Status.CANCELLED,
                        updated_at=now,
                    )
            run.save(update_fields=[
                "cancellation_requested_at", "cancelled_by", "status", "started_at",
                "finished_at", "duration_seconds", "failure_message", "updated_at",
            ])
        return run

    @staticmethod
    def mark_enqueue_failed(run: AgentRun) -> AgentRun:
        with transaction.atomic():
            run = AgentRun.objects.select_for_update().get(pk=run.pk)
            if run.status != AgentRun.Status.QUEUED:
                return run
            now = timezone.now()
            run.status = AgentRun.Status.FAILED
            run.started_at = now
            run.finished_at = now
            run.failure_category = AgentRun.FailureCategory.RUNTIME_UNAVAILABLE
            run.failure_message = "Assessment execution could not be queued."
            run.steps.update(
                status=AgentRunStep.Status.SKIPPED,
                failure_message="Skipped because worker dispatch failed.",
                finished_at=now,
            )
            run.save(update_fields=[
                "status", "started_at", "finished_at", "duration_seconds",
                "failure_category", "failure_message", "updated_at",
            ])
            if run.assessment_plan_id:
                AssessmentPlan.objects.filter(pk=run.assessment_plan_id).update(
                    status=AssessmentPlan.Status.FAILED,
                    updated_at=now,
                )
                AssessmentPlanStep.objects.filter(plan_id=run.assessment_plan_id).update(
                    status=AssessmentPlanStep.Status.SKIPPED,
                    updated_at=now,
                )
        return run

    @staticmethod
    def mark_execution_failed(run_id: int, *, message: str) -> AgentRun:
        with transaction.atomic():
            run = AgentRun.objects.select_for_update().get(pk=run_id)
            if run.status in {
                AgentRun.Status.SUCCEEDED,
                AgentRun.Status.FAILED,
                AgentRun.Status.CANCELLED,
                AgentRun.Status.TIMEOUT,
            }:
                return run
            now = timezone.now()
            run.status = AgentRun.Status.FAILED
            run.started_at = run.started_at or now
            run.finished_at = now
            run.failure_category = AgentRun.FailureCategory.INTERNAL_ERROR
            run.failure_message = _safe_text(message, MAX_SAFE_ERROR_CHARS)
            run.steps.filter(status=AgentRunStep.Status.RUNNING).update(
                status=AgentRunStep.Status.FAILED,
                failure_message="The bounded execution worker stopped unexpectedly.",
                finished_at=now,
            )
            run.steps.filter(status=AgentRunStep.Status.PENDING).update(
                status=AgentRunStep.Status.SKIPPED,
                failure_message="Skipped after the execution worker stopped.",
                finished_at=now,
            )
            run.save(update_fields=[
                "status", "started_at", "finished_at", "duration_seconds",
                "failure_category", "failure_message", "updated_at",
            ])
            if run.assessment_plan_id:
                AssessmentPlan.objects.filter(pk=run.assessment_plan_id).update(
                    status=AssessmentPlan.Status.FAILED, updated_at=now
                )
                AssessmentPlanStep.objects.filter(plan_id=run.assessment_plan_id).update(
                    status=AssessmentPlanStep.Status.FAILED, updated_at=now
                )
        return run

    def _start_run(self, run_id: int) -> AgentRun:
        with transaction.atomic():
            run = (
                AgentRun.objects.select_for_update()
                .get(pk=run_id)
            )
            if run.objective != AgentRun.Objective.ASSESSMENT_PLAN_EXECUTION:
                raise AssessmentExecutionError(
                    "The run is not an approved assessment execution.",
                    code="ASSESSMENT_RUN_INVALID",
                )
            if run.status == AgentRun.Status.CANCELLED:
                return run
            if run.status != AgentRun.Status.QUEUED:
                raise AssessmentExecutionError(
                    "The assessment run is not queued for execution.",
                    code="ASSESSMENT_RUN_STATE_INVALID",
                )
            if user_role(run.requested_by) not in {"ADMIN", "ANALYST"}:
                raise AssessmentExecutionPermissionError()
            validate_approved_execution_contract(run.execution_contract)
            self._validate_run_snapshot(run)
            run.status = AgentRun.Status.RUNNING
            run.started_at = timezone.now()
            run.save(update_fields=["status", "started_at", "updated_at"])
            AssessmentPlanStep.objects.filter(plan_id=run.assessment_plan_id).update(
                status=AssessmentPlanStep.Status.EXECUTING,
                updated_at=timezone.now(),
            )
        security_logger.info(
            "assessment_execution_started run_id=%s plan_id=%s", run.id, run.assessment_plan_id
        )
        return run

    @staticmethod
    def _validate_live_authorization(plan: AssessmentPlan, canonical: dict[str, Any]) -> None:
        if not Audit.objects.filter(pk=plan.audit_id).exists():
            raise AssessmentExecutionError(
                "The approved audit no longer exists.", code="ASSESSMENT_AUDIT_INVALID"
            )
        if canonical["audit_id"] != plan.audit_id or canonical["target_package"] != plan.target_package:
            raise AssessmentExecutionError(
                "The approved target scope no longer matches the plan.",
                code="ASSESSMENT_TARGET_MISMATCH",
            )
        if not APKFile.objects.filter(
            audit_id=plan.audit_id, package_name=plan.target_package
        ).exists():
            raise AssessmentExecutionError(
                "The target package is no longer authorized by the audit.",
                code="ASSESSMENT_TARGET_UNAUTHORIZED",
            )
        tools = [tool for step in canonical["steps"] for tool in step["tools"]]
        if len(canonical["steps"]) > MAX_PLAN_STEPS or any(
            tool["name"] not in TOOL_MANIFEST for tool in tools
        ):
            raise AssessmentExecutionError(
                "The approved plan references an unavailable capability.",
                code="ASSESSMENT_CAPABILITY_UNAVAILABLE",
            )
        if len(tools) > settings.MSAP_ASSESSMENT_EXECUTION_MAX_TOOL_CALLS:
            raise AssessmentExecutionError(
                "The approved plan exceeds the execution tool-call bound.",
                code="ASSESSMENT_TOOL_CALL_LIMIT",
            )
        total_timeout = sum(TOOL_MANIFEST[tool["name"]].timeout_seconds for tool in tools)
        if total_timeout > settings.MSAP_ASSESSMENT_EXECUTION_TOTAL_TIMEOUT_SECONDS:
            raise AssessmentExecutionError(
                "The approved plan exceeds the total execution timeout.",
                code="ASSESSMENT_TIMEOUT_LIMIT",
            )

    @classmethod
    def _validate_run_snapshot(cls, run: AgentRun) -> None:
        plan = run.assessment_plan
        if plan is None or plan.status != AssessmentPlan.Status.EXECUTING:
            raise AssessmentExecutionError(
                "The linked approved plan is not in the execution lifecycle.",
                code="ASSESSMENT_PLAN_STATE_INVALID",
            )
        contract = validate_approved_execution_contract(run.execution_contract)
        if (
            contract["plan_id"] != plan.id
            or contract["plan_hash"] != plan.plan_hash
            or contract["plan_hash"] != run.approved_plan_hash
            or contract["approved_plan"] != plan.normalized_plan
            or run.audit_id != plan.audit_id
            or run.target_package != plan.target_package
        ):
            raise AssessmentExecutionError(
                "The approved plan or execution snapshot failed its integrity check.",
                code="ASSESSMENT_PLAN_INTEGRITY_FAILED",
            )
        cls._validate_materialized_steps(run, contract["approved_plan"])
        cls._validate_live_authorization(plan, contract["approved_plan"])

    @staticmethod
    def _validate_materialized_steps(run: AgentRun, canonical: dict[str, Any]) -> None:
        expected: list[dict[str, Any]] = []
        sequence = 1
        for plan_step in canonical["steps"]:
            tools = plan_step["tools"]
            if not tools:
                expected.append({
                    "sequence_number": sequence,
                    "tool_name": CONTROL_STEP_NAME,
                    "plan_step_identifier": plan_step["step_id"],
                    "plan_step_sequence": plan_step["sequence"],
                    "tool_call_index": 0,
                    "is_control_step": True,
                    "dependencies": plan_step["dependencies"],
                    "evidence_requirements": plan_step["evidence_requirements"],
                    "input_summary": {},
                    "timeout_seconds": 0,
                    "max_retries": 0,
                    "status": AgentRunStep.Status.PENDING,
                })
                sequence += 1
                continue
            for index, tool in enumerate(tools, start=1):
                expected.append({
                    "sequence_number": sequence,
                    "tool_name": tool["name"],
                    "plan_step_identifier": plan_step["step_id"],
                    "plan_step_sequence": plan_step["sequence"],
                    "tool_call_index": index,
                    "is_control_step": False,
                    "dependencies": plan_step["dependencies"],
                    "evidence_requirements": plan_step["evidence_requirements"],
                    "input_summary": tool["arguments"],
                    "timeout_seconds": TOOL_MANIFEST[tool["name"]].timeout_seconds,
                    "max_retries": settings.MSAP_ASSESSMENT_EXECUTION_MAX_RETRIES,
                    "status": AgentRunStep.Status.PENDING,
                })
                sequence += 1
        actual = list(run.steps.order_by("sequence_number").values(*expected[0].keys()))
        if actual != expected:
            raise AssessmentExecutionError(
                "The materialized run steps do not exactly match the approved plan.",
                code="ASSESSMENT_RUN_STEP_INTEGRITY_FAILED",
            )

    @staticmethod
    def _select_runtime(runtime_type: str) -> AgentRuntime | None:
        if runtime_type == AgentRuntime.RuntimeType.CONTAINER_SANDBOX and not settings.MSAP_AGENT_CONTAINER_ENABLED:
            return None
        return AgentRuntime.objects.filter(
            runtime_type=runtime_type,
            enabled=True,
            status=AgentRuntime.Status.AVAILABLE,
        ).order_by("id").first()

    @staticmethod
    def _materialize_steps(run: AgentRun, canonical: dict[str, Any]) -> None:
        sequence = 1
        rows: list[AgentRunStep] = []
        for plan_step in canonical["steps"]:
            tools = plan_step["tools"]
            if not tools:
                rows.append(AgentRunStep(
                    run=run,
                    sequence_number=sequence,
                    tool_name=CONTROL_STEP_NAME,
                    plan_step_identifier=plan_step["step_id"],
                    plan_step_sequence=plan_step["sequence"],
                    tool_call_index=0,
                    is_control_step=True,
                    dependencies=plan_step["dependencies"],
                    evidence_requirements=plan_step["evidence_requirements"],
                    input_summary={},
                    timeout_seconds=0,
                ))
                sequence += 1
                continue
            for call_index, tool in enumerate(tools, start=1):
                spec = TOOL_MANIFEST[tool["name"]]
                rows.append(AgentRunStep(
                    run=run,
                    sequence_number=sequence,
                    tool_name=tool["name"],
                    plan_step_identifier=plan_step["step_id"],
                    plan_step_sequence=plan_step["sequence"],
                    tool_call_index=call_index,
                    dependencies=plan_step["dependencies"],
                    evidence_requirements=plan_step["evidence_requirements"],
                    input_summary=deepcopy(tool["arguments"]),
                    max_retries=settings.MSAP_ASSESSMENT_EXECUTION_MAX_RETRIES,
                    timeout_seconds=spec.timeout_seconds,
                ))
                sequence += 1
        AgentRunStep.objects.bulk_create(rows)

    @staticmethod
    def _dependency_failure(run: AgentRun, step: AgentRunStep) -> str:
        earlier_same_step = run.steps.filter(
            plan_step_identifier=step.plan_step_identifier,
            sequence_number__lt=step.sequence_number,
        ).exclude(status=AgentRunStep.Status.SUCCEEDED)
        if earlier_same_step.exists():
            return "Skipped because an earlier tool in the approved plan step did not succeed."
        dependencies = set(step.dependencies or [])
        if not dependencies:
            return ""
        statuses = set(run.steps.filter(
            plan_step_identifier__in=dependencies
        ).values_list("status", flat=True))
        if statuses - {AgentRunStep.Status.SUCCEEDED}:
            return "Skipped because an approved plan dependency did not succeed."
        return ""

    def _complete_control_step(self, step: AgentRunStep) -> None:
        now = timezone.now()
        data = {
            "step_id": step.plan_step_identifier,
            "result": "Approved reasoning-only plan intent preserved; no model or tool was executed.",
        }
        observation = normalize_observation(CONTROL_STEP_NAME, data)
        step.status = AgentRunStep.Status.SUCCEEDED
        step.started_at = now
        step.finished_at = now
        step.output_summary = data
        step.observation = observation
        step.save(update_fields=[
            "status", "started_at", "finished_at", "duration_seconds",
            "output_summary", "observation",
        ])
        self._create_evidence(step.run, step, None, observation)

    def _record_successful_observation(self, run: AgentRun, step: AgentRunStep, output: Any) -> None:
        observation = normalize_observation(step.tool_name, output)
        step.observation = observation
        step.save(update_fields=["observation"])
        artifact = step.artifacts.order_by("id").first()
        self._validate_artifact_bounds(run, artifact)
        self._create_evidence(run, step, artifact, observation)

    def _record_failed_observation(self, run: AgentRun, step: AgentRunStep) -> None:
        observation = normalize_observation(step.tool_name, {
            "status": step.status,
            "error": _safe_text(step.failure_message, MAX_SAFE_ERROR_CHARS),
        })
        step.observation = observation
        step.save(update_fields=["observation"])
        self._create_evidence(run, step, None, observation)

    @staticmethod
    def _validate_artifact_bounds(run: AgentRun, artifact: AgentRunArtifact | None) -> None:
        if artifact is None:
            return
        if run.artifacts.count() > settings.MSAP_ASSESSMENT_EXECUTION_MAX_ARTIFACTS:
            raise AssessmentExecutionError(
                "The assessment execution exceeded its artifact-count limit.",
                code="ASSESSMENT_ARTIFACT_LIMIT",
            )
        size = artifact.size_bytes
        if size is None and artifact.object_reference_id:
            size = artifact.object_reference.size_bytes
        if size is not None and size > settings.MSAP_ASSESSMENT_EXECUTION_MAX_ARTIFACT_BYTES:
            raise AssessmentExecutionError(
                "An assessment artifact exceeded its size limit.",
                code="ASSESSMENT_ARTIFACT_TOO_LARGE",
            )

    @staticmethod
    def _create_evidence(
        run: AgentRun,
        step: AgentRunStep,
        artifact: AgentRunArtifact | None,
        observation: dict[str, Any],
    ) -> Evidence:
        encoded = _canonical_json(observation)
        evidence_type = _evidence_type(step.tool_name)
        return Evidence.objects.create(
            audit_id=run.audit_id,
            storage_reference=(artifact.object_reference if artifact else None),
            agent_run=run,
            agent_run_step=step,
            agent_run_artifact=artifact,
            evidence_type=evidence_type,
            source=f"agent_run:{run.id}:step:{step.sequence_number}:{step.tool_name}",
            snippet=encoded[:MAX_EVIDENCE_SNIPPET_CHARS],
            redacted=bool(observation.get("redaction_applied")),
            sha256=sha256(encoded.encode("utf-8")).hexdigest(),
            provenance={
                "contract_version": OBSERVATION_CONTRACT_VERSION,
                "assessment_plan_id": run.assessment_plan_id,
                "plan_hash": run.approved_plan_hash,
                "run_id": run.id,
                "run_step_id": step.id,
                "plan_step_id": step.plan_step_identifier,
                "tool": step.tool_name,
                "finding_verdict": False,
            },
        )

    @staticmethod
    def _skip_step(step: AgentRunStep, reason: str) -> None:
        step.status = AgentRunStep.Status.SKIPPED
        step.failure_message = reason
        step.finished_at = timezone.now()
        step.save(update_fields=["status", "failure_message", "finished_at"])

    @staticmethod
    def _fail_step(step: AgentRunStep, reason: str) -> None:
        now = timezone.now()
        step.status = AgentRunStep.Status.FAILED
        step.started_at = step.started_at or now
        step.finished_at = now
        step.failure_message = _safe_text(reason, MAX_SAFE_ERROR_CHARS)
        step.save(update_fields=[
            "status", "started_at", "finished_at", "duration_seconds", "failure_message",
        ])

    @staticmethod
    def _mark_step_timeout(step: AgentRunStep, reason: str) -> None:
        step.status = AgentRunStep.Status.TIMEOUT
        step.failure_message = reason
        step.finished_at = timezone.now()
        step.save(update_fields=["status", "failure_message", "finished_at", "duration_seconds"])

    def _finish_timeout(self, run: AgentRun, reason: str) -> AgentRun:
        now = timezone.now()
        for step in run.steps.filter(status=AgentRunStep.Status.PENDING):
            self._skip_step(step, "Skipped after the total execution timeout.")
        return self._finish(run, failed=True, timeout=True, message=reason)

    def _finish_cancelled(self, run: AgentRun) -> AgentRun:
        now = timezone.now()
        run.steps.filter(status=AgentRunStep.Status.PENDING).update(
            status=AgentRunStep.Status.CANCELLED,
            failure_message="Cancelled before execution.",
            finished_at=now,
        )
        self._sync_plan_step_statuses(run, cancelled=True)
        run.status = AgentRun.Status.CANCELLED
        run.finished_at = now
        run.failure_message = "Assessment execution cancelled by an authorized operator."
        run.result_summary = self._result_summary(run)
        run.save(update_fields=[
            "status", "finished_at", "duration_seconds", "failure_message",
            "result_summary", "updated_at",
        ])
        AssessmentPlan.objects.filter(pk=run.assessment_plan_id).update(
            status=AssessmentPlan.Status.CANCELLED, updated_at=now
        )
        return run

    def _finish(
        self,
        run: AgentRun,
        *,
        failed: bool,
        timeout: bool = False,
        message: str = "",
    ) -> AgentRun:
        now = timezone.now()
        self._sync_plan_step_statuses(run)
        run.status = (
            AgentRun.Status.TIMEOUT if timeout else
            AgentRun.Status.FAILED if failed else
            AgentRun.Status.SUCCEEDED
        )
        run.finished_at = now
        if failed:
            run.failure_category = (
                AgentRun.FailureCategory.TIMEOUT if timeout else
                AgentRun.FailureCategory.TOOL_EXECUTION_FAILED
            )
            run.failure_message = message or "One or more approved assessment steps failed."
        run.result_summary = self._result_summary(run)
        run.save(update_fields=[
            "status", "finished_at", "duration_seconds", "failure_category",
            "failure_message", "result_summary", "updated_at",
        ])
        plan_status = AssessmentPlan.Status.FAILED if failed else AssessmentPlan.Status.COMPLETED
        AssessmentPlan.objects.filter(pk=run.assessment_plan_id).update(
            status=plan_status, updated_at=now
        )
        self._resolve_post_processing(run)
        if run.runtime_id:
            AgentRuntime.objects.filter(pk=run.runtime_id).update(last_seen_at=now, updated_at=now)
        security_logger.info(
            "assessment_execution_completed run_id=%s plan_id=%s status=%s "
            "tool_calls=%s artifacts=%s evidence=%s",
            run.id, run.assessment_plan_id, run.status, run.tool_call_count,
            run.artifacts.count(), run.evidence_records.count(),
        )
        return run

    @staticmethod
    def _resolve_post_processing(run: AgentRun) -> None:
        try:
            from apps.dynamic_analysis.services.assessment_results import (
                resolve_completed_assessment,
            )

            result = resolve_completed_assessment(run)
        except Exception as exc:  # deterministic reporting must not corrupt run state
            logger.error(
                "assessment_post_processing_failed run_id=%s error_type=%s",
                run.id,
                type(exc).__name__,
            )
            result = {
                "status": "FAILED",
                "reason": "Deterministic post-processing failed safely.",
            }
        run.refresh_from_db()
        summary = AssessmentExecutor._result_summary(run)
        summary["post_processing"] = result
        deterministic = result.get("deterministic_rules", {})
        assessment = result.get("assessment_summary", {})
        summary["finding_count_created"] = deterministic.get(
            "findings_created", 0
        )
        summary["finding_count_total"] = assessment.get("audit_finding_count", 0)
        summary["risk"] = assessment.get("risk", {})
        summary["compliance"] = assessment.get("compliance", {})
        summary["report"] = result.get("report", {"status": "NOT_GENERATED"})
        run.result_summary = summary
        run.save(update_fields=["result_summary", "updated_at"])

    @staticmethod
    def _sync_plan_step_statuses(run: AgentRun, *, cancelled: bool = False) -> None:
        del cancelled
        for plan_step in AssessmentPlanStep.objects.filter(plan_id=run.assessment_plan_id):
            statuses = set(run.steps.filter(
                plan_step_identifier=plan_step.step_identifier
            ).values_list("status", flat=True))
            if AgentRunStep.Status.CANCELLED in statuses:
                status = AssessmentPlanStep.Status.CANCELLED
            elif statuses and statuses <= {AgentRunStep.Status.SUCCEEDED}:
                status = AssessmentPlanStep.Status.COMPLETED
            elif statuses & {AgentRunStep.Status.FAILED, AgentRunStep.Status.TIMEOUT}:
                status = AssessmentPlanStep.Status.FAILED
            else:
                status = AssessmentPlanStep.Status.SKIPPED
            plan_step.status = status
            plan_step.save(update_fields=["status", "updated_at"])

    @staticmethod
    def _result_summary(run: AgentRun) -> dict[str, Any]:
        statuses = {
            status: run.steps.filter(status=status).count()
            for status in AgentRunStep.Status.values
        }
        return {
            "objective": AgentRun.Objective.ASSESSMENT_PLAN_EXECUTION,
            "assessment_plan_id": run.assessment_plan_id,
            "approved_plan_hash": run.approved_plan_hash,
            "target_package": run.target_package,
            "execution_mode": "SEQUENTIAL_APPROVED_PLAN",
            "execution_channel": "RUN_SCOPED_TOOL_GATEWAY",
            "step_status_counts": statuses,
            "tool_call_count": run.tool_call_count,
            "artifact_count": run.artifacts.count(),
            "evidence_count": run.evidence_records.count(),
            "observations_are_untrusted_data": True,
            "finding_count_created": 0,
            "assessment_scope": "Runtime evidence collection only; no vulnerability or malware verdict was produced.",
        }


def normalize_observation(tool_name: str, output: Any) -> dict[str, Any]:
    redaction = {"applied": False}
    sanitized = _sanitize_value(output, redaction=redaction)
    encoded = _canonical_json(sanitized)
    max_bytes = settings.MSAP_ASSESSMENT_EXECUTION_MAX_OBSERVATION_BYTES
    if len(encoded.encode("utf-8")) > max_bytes:
        digest = sha256(encoded.encode("utf-8")).hexdigest()
        sanitized = {
            "truncated": True,
            "original_sha256": digest,
            "preview": _safe_text(encoded, min(8000, max_bytes // 2)),
        }
    observation = {
        "contract_version": OBSERVATION_CONTRACT_VERSION,
        "classification": "UNTRUSTED_APPLICATION_OBSERVATION",
        "tool_name": tool_name,
        "captured_at": timezone.now().isoformat(),
        "redaction_applied": redaction["applied"],
        "data": sanitized,
    }
    encoded_observation = _canonical_json(observation)
    if len(encoded_observation.encode("utf-8")) > max_bytes:
        raise AssessmentExecutionError(
            "The normalized observation exceeded its storage bound.",
            code="ASSESSMENT_OBSERVATION_TOO_LARGE",
        )
    return observation


def _sanitize_value(value: Any, *, redaction: dict[str, bool]) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, child in list(value.items())[:500]:
            if SECRET_KEY_RE.search(str(key)):
                result[str(key)] = "[redacted]"
                redaction["applied"] = True
            else:
                result[str(key)] = _sanitize_value(child, redaction=redaction)
        return result
    if isinstance(value, list):
        return [_sanitize_value(item, redaction=redaction) for item in value[:500]]
    if isinstance(value, str):
        cleaned = value
        for pattern in SECRET_VALUE_PATTERNS:
            updated = pattern.sub("[redacted]", cleaned)
            if updated != cleaned:
                redaction["applied"] = True
            cleaned = updated
        return cleaned[:65536]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    redaction["applied"] = True
    return "[unsupported value redacted]"


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _safe_text(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    text = value.replace("\x00", "")
    for pattern in SECRET_VALUE_PATTERNS:
        text = pattern.sub("[redacted]", text)
    return text[:limit]


def _evidence_type(tool_name: str) -> str:
    return {
        "take_screenshot": "dynamic_screenshot",
        "dump_ui": "dynamic_ui_hierarchy",
        "start_logcat": "dynamic_logcat_capture",
        "get_logcat_excerpt": "dynamic_logcat_excerpt",
        "frida_status": "dynamic_frida_status",
        "frida_ps": "dynamic_frida_processes",
        "frida_attach": "dynamic_frida_attach",
        "frida_run_js": "dynamic_frida_events",
        CONTROL_STEP_NAME: "assessment_plan_control_observation",
    }.get(tool_name, "dynamic_tool_observation")

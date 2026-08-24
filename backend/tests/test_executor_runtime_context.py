"""Runtime context passing for approved assessment plan execution.

Covers the run-scoped placeholder contract (``collector_from_previous_step``
and the closed placeholder set) across the sequential executor and the
approved-plan Tool Gateway path.
"""

from copy import deepcopy
from unittest.mock import Mock

import pytest
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.utils import timezone

from apps.api.roles import ANALYST_GROUP
from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.dynamic_analysis.models import (
    AgentRun,
    AgentRunStep,
    AgentRuntime,
    AssessmentPlan,
)
from apps.dynamic_analysis.services.agent_tools import ALL_TOOL_NAMES
from apps.dynamic_analysis.services.agent_controller import (
    COLLECTOR_FROM_PREVIOUS_STEP,
    COLLECTOR_FROM_START,
    PACKAGE_FROM_INSTALL,
    PROXY_CAPTURE_FROM_PREVIOUS_STEP,
    RuntimePlaceholderError,
    resolve_approved_plan_arguments,
)
from apps.dynamic_analysis.services.agent_gateway import (
    AgentGatewayRequestError,
    execute_run_tool_call,
)
from apps.dynamic_analysis.services.assessment_executor import AssessmentExecutor
from apps.dynamic_analysis.services.assessment_planner import AssessmentPlannerService
from apps.projects.models import Project


def _ensure_runtime() -> AgentRuntime:
    runtime, _created = AgentRuntime.objects.get_or_create(
        name="Sprint B Internal Controller",
        defaults={
            "runtime_type": AgentRuntime.RuntimeType.INTERNAL_CONTROLLER,
            "status": AgentRuntime.Status.AVAILABLE,
            "isolation_level": AgentRuntime.IsolationLevel.INTERNAL_ONLY,
            "enabled": True,
        },
    )
    runtime.status = AgentRuntime.Status.AVAILABLE
    runtime.enabled = True
    runtime.capabilities = {
        "tools": sorted(ALL_TOOL_NAMES),
        "objectives": [AgentRun.Objective.ASSESSMENT_PLAN_EXECUTION],
    }
    runtime.save(update_fields=["status", "enabled", "capabilities", "updated_at"])
    return runtime


def _make_role_user(django_user_model, username: str):
    call_command("bootstrap_roles", verbosity=0)
    user = django_user_model.objects.create_user(username=username)
    user.groups.add(Group.objects.get(name=ANALYST_GROUP))
    return user


def _build_approved_plan(django_user_model, suffix: str, steps: list[dict]) -> AssessmentPlan:
    user = _make_role_user(django_user_model, f"executor-{suffix}")
    project = Project.objects.create(name=f"Runtime context project {suffix}")
    audit = Audit.objects.create(project=project, name=f"Runtime context audit {suffix}")
    package_name = f"com.example.{suffix.replace('-', '_')}"
    apk = APKFile.objects.create(
        audit=audit,
        package_name=package_name,
        version_name="1.0.0",
    )
    objective = "Assess authorized runtime behavior with bounded evidence."
    scope = "Capture bounded target-correlated log evidence without a vulnerability verdict."
    intent = {
        "target_package": package_name,
        "assessment_objective": objective,
        "scope": scope,
        "steps": steps,
    }
    plan = AssessmentPlan.objects.create(
        audit=audit,
        target_package=apk.package_name,
        planner_provider=AssessmentPlan.PlannerProvider.DETERMINISTIC,
        planner_model="test-runtime-context-plan",
        objective=objective,
        scope=scope,
        status=AssessmentPlan.Status.GENERATED,
        validation_status=AssessmentPlan.ValidationStatus.PENDING,
        policy_status=AssessmentPlan.PolicyStatus.PENDING,
        generated_plan=intent,
        scenario_contract={},
        planner_input_hash="0" * 64,
    )
    plan = AssessmentPlannerService().validate(plan)
    plan = AssessmentPlannerService().approve(plan, approved_by=user)
    _ensure_runtime()
    return plan


def _logcat_steps(package_name: str, collector_id: str) -> list[dict]:
    return [
        {
            "sequence": 1,
            "step_id": "start_observation",
            "objective": "Start bounded target-correlated log capture.",
            "rationale": "A collector must exist before excerpts or stop calls.",
            "tools": [
                {
                    "name": "start_logcat",
                    "arguments": {
                        "package_name": package_name,
                        "reason": "agent_step",
                        "max_seconds": 30,
                    },
                }
            ],
            "expected_observation": "A collector_id is returned.",
            "success_condition": "collector_id is a bounded identifier.",
            "evidence_requirements": ["tool_output"],
            "dependencies": [],
        },
        {
            "sequence": 2,
            "step_id": "read_observation",
            "objective": "Read a bounded excerpt from the active collector.",
            "rationale": "The collector must already be running.",
            "tools": [
                {
                    "name": "get_logcat_excerpt",
                    "arguments": {"collector_id": collector_id, "max_lines": 50},
                }
            ],
            "expected_observation": "A bounded log excerpt is returned.",
            "success_condition": "line_count is a bounded non-negative integer.",
            "evidence_requirements": ["tool_output"],
            "dependencies": ["start_observation"],
        },
        {
            "sequence": 3,
            "step_id": "close_observation",
            "objective": "Stop the active collector.",
            "rationale": "The collector must already be running.",
            "tools": [
                {
                    "name": "stop_logcat",
                    "arguments": {"collector_id": collector_id},
                }
            ],
            "expected_observation": "The collector reports stopped.",
            "success_condition": "stopped is true.",
            "evidence_requirements": ["tool_output"],
            "dependencies": ["start_observation"],
        },
    ]


def _proxy_steps(package_name: str, capture_id: str) -> list[dict]:
    return [
        {
            "sequence": 1,
            "step_id": "start_proxy",
            "objective": "Start bounded proxy capture.",
            "rationale": "A capture id must exist before capture results can be read.",
            "tools": [
                {
                    "name": "start_proxy_capture",
                    "arguments": {
                        "package_name": package_name,
                        "max_seconds": 30,
                        "phase": "pinning_baseline",
                    },
                }
            ],
            "expected_observation": "A proxy capture id is returned.",
            "success_condition": "capture_id is bounded.",
            "evidence_requirements": ["network_flow"],
            "dependencies": [],
        },
        {
            "sequence": 2,
            "step_id": "stop_proxy",
            "objective": "Stop the bounded proxy capture.",
            "rationale": "The closed placeholder must resolve to the prior capture id.",
            "tools": [
                {
                    "name": "stop_proxy_capture",
                    "arguments": {"capture_id": capture_id},
                }
            ],
            "expected_observation": "A bounded proxy summary is returned.",
            "success_condition": "The capture is stopped.",
            "evidence_requirements": ["network_flow"],
            "dependencies": ["start_proxy"],
        },
        {
            "sequence": 3,
            "step_id": "read_proxy",
            "objective": "Read the bounded proxy summary.",
            "rationale": "The same capture id must flow into subsequent reads.",
            "tools": [
                {
                    "name": "get_proxy_flows",
                    "arguments": {"capture_id": capture_id},
                }
            ],
            "expected_observation": "The redacted flow summary is available.",
            "success_condition": "The flow count is returned.",
            "evidence_requirements": ["network_flow"],
            "dependencies": ["stop_proxy"],
        },
    ]


class _RecordingGateway:
    def __init__(self, *, start_output_extra: dict | None = None):
        self.calls = []
        self.start_output_extra = start_output_extra or {}

    def __call__(self, **kwargs):
        calls = self.calls

        def tool_executor(tool_name, arguments, *, requested_by=None):
            del requested_by
            calls.append({"tool_name": tool_name, "arguments": deepcopy(arguments)})
            if tool_name == "start_logcat":
                return {
                    "collector_id": "collector-abc-123",
                    "started_at": timezone.now().isoformat(),
                    "max_seconds": arguments["max_seconds"],
                    "package_filter_applied": True,
                    **self.start_output_extra,
                }
            if tool_name == "get_logcat_excerpt":
                return {
                    "line_count": 2,
                    "lines": ["line-a", "line-b"],
                    "redaction_applied": False,
                }
            if tool_name == "stop_logcat":
                return {
                    "collector_id": arguments["collector_id"],
                    "stopped": True,
                    "supported": True,
                    "status": "STOPPED",
                }
            raise AssertionError(f"Unexpected tool: {tool_name}")

        return execute_run_tool_call(**kwargs, tool_executor=tool_executor)


class _RecordingProxyGateway:
    def __init__(self):
        self.calls = []

    def __call__(self, **kwargs):
        calls = self.calls

        def tool_executor(tool_name, arguments, *, requested_by=None):
            del requested_by
            calls.append({"tool_name": tool_name, "arguments": deepcopy(arguments)})
            if tool_name == "start_proxy_capture":
                return {
                    "capture_id": "a" * 32,
                    "phase": arguments["phase"],
                    "started_at": timezone.now().isoformat(),
                    "max_seconds": arguments["max_seconds"],
                    "proxy": "10.0.2.2:18080",
                }
            if tool_name == "stop_proxy_capture":
                return {
                    "capture_id": arguments["capture_id"],
                    "phase": "pinning_baseline",
                    "stopped": True,
                    "flow_count": 0,
                    "successful_tls_flow_count": 0,
                    "flows": [],
                    "redaction_applied": True,
                    "raw_flow_retained": False,
                }
            if tool_name == "get_proxy_flows":
                return {
                    "capture_id": arguments["capture_id"],
                    "phase": "pinning_baseline",
                    "flow_count": 0,
                    "successful_tls_flow_count": 0,
                    "flows": [],
                    "redaction_applied": True,
                    "raw_flow_retained": False,
                }
            raise AssertionError(f"Unexpected tool: {tool_name}")

        return execute_run_tool_call(**kwargs, tool_executor=tool_executor)


@pytest.mark.django_db
def test_resolve_approved_plan_arguments_resolves_closed_placeholder_set():
    completed = {
        "start_logcat": {"collector_id": "collector-abc-123"},
        "install_verified_apk": {"package_name": "com.example.app"},
    }
    resolved = resolve_approved_plan_arguments(
        {
            "collector_id": COLLECTOR_FROM_PREVIOUS_STEP,
            "collector_from_start": COLLECTOR_FROM_START,
            "package_name": PACKAGE_FROM_INSTALL,
            "max_lines": 50,
            "verbatim": "plain-value",
        },
        completed,
    )
    assert resolved == {
        "collector_id": "collector-abc-123",
        "collector_from_start": "collector-abc-123",
        "package_name": "com.example.app",
        "max_lines": 50,
        "verbatim": "plain-value",
    }


@pytest.mark.django_db
def test_resolve_approved_plan_arguments_never_interpolates_unknown_values():
    resolved = resolve_approved_plan_arguments(
        {"collector_id": "collector_from_somewhere_else", "max_lines": 50},
        {"start_logcat": {"collector_id": "collector-abc-123"}},
    )
    assert resolved == {"collector_id": "collector_from_somewhere_else", "max_lines": 50}


@pytest.mark.django_db
def test_resolve_approved_plan_arguments_missing_collector_fails_deterministically():
    with pytest.raises(RuntimePlaceholderError) as exc_info:
        resolve_approved_plan_arguments(
            {"collector_id": COLLECTOR_FROM_PREVIOUS_STEP},
            {},
        )
    assert exc_info.value.code == "RUNTIME_PLACEHOLDER_UNRESOLVED"
    assert "logcat collector" in str(exc_info.value)
    with pytest.raises(RuntimePlaceholderError) as exc_info:
        resolve_approved_plan_arguments(
            {"package_name": PACKAGE_FROM_INSTALL},
            {},
        )
    assert "installed package" in str(exc_info.value)


@pytest.mark.django_db
def test_approved_plan_resolves_collector_placeholder_across_steps(django_user_model):
    plan = _build_approved_plan(
        django_user_model,
        "placeholder-full",
        _logcat_steps("com.example.placeholder_full", COLLECTOR_FROM_PREVIOUS_STEP),
    )
    tool = _RecordingGateway()
    executor = AssessmentExecutor(gateway_executor=tool)

    run = executor.create_run(plan=plan, requested_by=plan.approved_by)
    run = executor.execute(run.id)

    run.refresh_from_db()
    plan.refresh_from_db()
    assert run.status == AgentRun.Status.SUCCEEDED
    assert plan.status == AssessmentPlan.Status.COMPLETED
    assert [call["tool_name"] for call in tool.calls] == [
        "start_logcat",
        "get_logcat_excerpt",
        "stop_logcat",
    ]
    assert tool.calls[1]["arguments"]["collector_id"] == "collector-abc-123"
    assert tool.calls[2]["arguments"]["collector_id"] == "collector-abc-123"
    excerpt_step = run.steps.get(tool_name="get_logcat_excerpt")
    stop_step = run.steps.get(tool_name="stop_logcat")
    assert excerpt_step.input_summary == {
        "collector_id": "collector-abc-123",
        "max_lines": 50,
    }
    assert stop_step.input_summary == {"collector_id": "collector-abc-123"}
    assert excerpt_step.status == AgentRunStep.Status.SUCCEEDED
    assert stop_step.status == AgentRunStep.Status.SUCCEEDED


@pytest.mark.django_db
def test_missing_collector_placeholder_fails_deterministically(django_user_model):
    plan = _build_approved_plan(
        django_user_model,
        "placeholder-missing",
        [
            {
                "sequence": 1,
                "step_id": "read_observation",
                "objective": "Read a bounded excerpt from the active collector.",
                "rationale": "The collector must already be running.",
                "tools": [
                    {
                        "name": "get_logcat_excerpt",
                        "arguments": {
                            "collector_id": COLLECTOR_FROM_PREVIOUS_STEP,
                            "max_lines": 50,
                        },
                    }
                ],
                "expected_observation": "A bounded log excerpt is returned.",
                "success_condition": "line_count is a bounded non-negative integer.",
                "evidence_requirements": ["tool_output"],
                "dependencies": [],
            }
        ],
    )
    gateway = Mock()
    executor = AssessmentExecutor(gateway_executor=gateway)

    run = executor.create_run(plan=plan, requested_by=plan.approved_by)
    run = executor.execute(run.id)

    run.refresh_from_db()
    assert run.status == AgentRun.Status.FAILED
    gateway.assert_not_called()
    step = run.steps.get(tool_name="get_logcat_excerpt")
    assert step.status == AgentRunStep.Status.FAILED
    assert "references a logcat collector" in step.failure_message


@pytest.mark.django_db
def test_unresolved_placeholder_reaches_gateway_with_deterministic_error_code(django_user_model):
    plan = _build_approved_plan(
        django_user_model,
        "gateway-placeholder",
        [
            {
                "sequence": 1,
                "step_id": "read_observation",
                "objective": "Read a bounded excerpt from the active collector.",
                "rationale": "The collector must already be running.",
                "tools": [
                    {
                        "name": "get_logcat_excerpt",
                        "arguments": {
                            "collector_id": COLLECTOR_FROM_PREVIOUS_STEP,
                            "max_lines": 50,
                        },
                    }
                ],
                "expected_observation": "A bounded log excerpt is returned.",
                "success_condition": "line_count is a bounded non-negative integer.",
                "evidence_requirements": ["tool_output"],
                "dependencies": [],
            }
        ],
    )
    executor = AssessmentExecutor()
    run = executor.create_run(plan=plan, requested_by=plan.approved_by)
    AgentRun.objects.filter(pk=run.pk).update(status=AgentRun.Status.RUNNING)

    with pytest.raises(AgentGatewayRequestError) as exc_info:
        execute_run_tool_call(
            run_id=run.id,
            tool_name="get_logcat_excerpt",
            arguments={"collector_id": COLLECTOR_FROM_PREVIOUS_STEP, "max_lines": 50},
        )
    assert exc_info.value.code == "RUNTIME_PLACEHOLDER_UNRESOLVED"
    assert exc_info.value.http_status == 409


@pytest.mark.django_db
def test_unknown_placeholder_is_preserved_and_rejected_by_tool_gateway(django_user_model):
    plan = _build_approved_plan(
        django_user_model,
        "placeholder-unknown",
        [
            {
                "sequence": 1,
                "step_id": "read_observation",
                "objective": "Read a bounded excerpt from the active collector.",
                "rationale": "The collector must already be running.",
                "tools": [
                    {
                        "name": "get_logcat_excerpt",
                        "arguments": {
                            "collector_id": "collector_from_somewhere_else",
                            "max_lines": 50,
                        },
                    }
                ],
                "expected_observation": "A bounded log excerpt is returned.",
                "success_condition": "line_count is a bounded non-negative integer.",
                "evidence_requirements": ["tool_output"],
                "dependencies": [],
            }
        ],
    )
    executor = AssessmentExecutor()

    run = executor.create_run(plan=plan, requested_by=plan.approved_by)
    run = executor.execute(run.id)

    run.refresh_from_db()
    assert run.status == AgentRun.Status.FAILED
    step = run.steps.get(tool_name="get_logcat_excerpt")
    assert step.status == AgentRunStep.Status.FAILED
    assert step.failure_message == "Invalid collector_id."


@pytest.mark.django_db
def test_runtime_context_never_copies_unrelated_tool_data(django_user_model):
    plan = _build_approved_plan(
        django_user_model,
        "context-bounded",
        _logcat_steps("com.example.context_bounded", COLLECTOR_FROM_PREVIOUS_STEP),
    )
    gateway = _RecordingGateway(
        start_output_extra={"session_token": "should-never-enter-context"}
    )
    executor = AssessmentExecutor(gateway_executor=gateway)

    run = executor.create_run(plan=plan, requested_by=plan.approved_by)
    run = executor.execute(run.id)

    run.refresh_from_db()
    assert run.status == AgentRun.Status.SUCCEEDED
    assert executor.runtime_context == {"logcat_collector_id": "collector-abc-123"}
    assert gateway.calls[1]["arguments"] == {
        "collector_id": "collector-abc-123",
        "max_lines": 50,
    }
    assert gateway.calls[2]["arguments"] == {"collector_id": "collector-abc-123"}
    start_step = run.steps.get(tool_name="start_logcat")
    assert start_step.output_summary["session_token"] == "[redacted]"


@pytest.mark.django_db
def test_approved_plan_resolves_proxy_capture_placeholder_across_steps(django_user_model):
    package_name = "com.example.proxy_placeholder"
    plan = _build_approved_plan(
        django_user_model,
        "proxy-placeholder",
        _proxy_steps(package_name, PROXY_CAPTURE_FROM_PREVIOUS_STEP),
    )
    gateway = _RecordingProxyGateway()
    executor = AssessmentExecutor(gateway_executor=gateway)

    run = executor.create_run(plan=plan, requested_by=plan.approved_by)
    run = executor.execute(run.id)

    run.refresh_from_db()
    assert run.status == AgentRun.Status.SUCCEEDED
    assert [call["tool_name"] for call in gateway.calls] == [
        "start_proxy_capture",
        "stop_proxy_capture",
        "get_proxy_flows",
    ]
    assert gateway.calls[1]["arguments"]["capture_id"] == "a" * 32
    assert gateway.calls[2]["arguments"]["capture_id"] == "a" * 32
    stop_step = run.steps.get(tool_name="stop_proxy_capture")
    read_step = run.steps.get(tool_name="get_proxy_flows")
    assert stop_step.input_summary == {"capture_id": "a" * 32}
    assert read_step.input_summary == {"capture_id": "a" * 32}


@pytest.mark.django_db
def test_missing_proxy_capture_placeholder_fails_deterministically(django_user_model):
    plan = _build_approved_plan(
        django_user_model,
        "proxy-missing",
        [
            {
                "sequence": 1,
                "step_id": "stop_proxy",
                "objective": "Stop the bounded proxy capture.",
                "rationale": "The closed placeholder must resolve.",
                "tools": [
                    {
                        "name": "stop_proxy_capture",
                        "arguments": {"capture_id": PROXY_CAPTURE_FROM_PREVIOUS_STEP},
                    }
                ],
                "expected_observation": "The capture stops.",
                "success_condition": "A bounded summary is returned.",
                "evidence_requirements": ["network_flow"],
                "dependencies": [],
            }
        ],
    )
    executor = AssessmentExecutor(gateway_executor=Mock())

    run = executor.create_run(plan=plan, requested_by=plan.approved_by)
    run = executor.execute(run.id)

    run.refresh_from_db()
    assert run.status == AgentRun.Status.FAILED
    step = run.steps.get(tool_name="stop_proxy_capture")
    assert "proxy capture" in step.failure_message

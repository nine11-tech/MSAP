"""Focused tests for the hard backend-enforced OpenAI call budget.

Covered guarantees:

- a budget cap prevents a mission-generation OpenAI call
- a budget cap prevents an adaptive decision OpenAI call
- a schema/provider failure after a real request still increments the count
- a local schema-preflight failure (no request sent) does not increment
- a retry run inherits the global mission/adaptive budget
- concurrent reservations cannot exceed the cap
"""
from __future__ import annotations

import threading
from unittest.mock import Mock, patch

import pytest
from django.core.management import call_command
from django.test import override_settings

from apps.dynamic_analysis.models import (
    AgentRun,
    FindingValidationMission,
    OpenAICallBudget,
)
from apps.dynamic_analysis.services.agent_decision_provider import (
    AgentDecisionProvider,
)
from apps.dynamic_analysis.services.agent_retry import (
    is_pre_execution_provider_failure,
)
from apps.dynamic_analysis.services.assessment_agent import AssessmentAgent
from apps.dynamic_analysis.services.assessment_planner import (
    PlannerProviderError,
)
from apps.dynamic_analysis.services.finding_validation_missions import (
    FindingValidationMissionError,
    generate_finding_validation_mission,
)
from apps.dynamic_analysis.services.openai_budget import (
    KIND_DECISION,
    KIND_EVIDENCE_EXPLANATION,
    KIND_GENERATION,
    GLOBAL_SCOPE,
    OpenAIBudgetExhausted,
    budget_status,
    release_call,
    reserve_call,
    reset_budget,
)
from apps.findings.models import Finding
from test_dynamic_analysis import (
    _approved_execution_plan,
    _make_role_user,
)
from apps.api.roles import ANALYST_GROUP


class _BoundedOpenAIProvider(AgentDecisionProvider):
    """Minimal OPENAI decision provider used to observe call behavior."""

    name = "OPENAI"
    model = "gpt-5.6-luna"

    def __init__(self, *, failure_code: str = "", request_sent: bool = True):
        self.last_metadata = {"provider_request_sent": request_sent}
        self.next_action_calls = 0
        self.failure_code = failure_code

    def next_action(self, state):
        self.next_action_calls += 1
        if self.failure_code:
            raise PlannerProviderError(
                "provider failed",
                code=self.failure_code,
            )
        from apps.dynamic_analysis.services.agent_decision_provider import (
            DeterministicAdaptiveDecisionProvider,
        )

        return DeterministicAdaptiveDecisionProvider().next_action(state)


@pytest.fixture
def analyst_user(django_user_model):
    call_command("bootstrap_roles", verbosity=0)
    return _make_role_user(django_user_model, "budget-analyst", ANALYST_GROUP)


@pytest.mark.django_db
@override_settings(
    MSAP_OPENAI_MAX_MISSION_GENERATION_CALLS=1,
    MSAP_OPENAI_MAX_ADAPTIVE_DECISION_CALLS=6,
    MSAP_OPENAI_MAX_TOTAL_CALLS=7,
    MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC",
)
def test_budget_prevents_mission_generation_call(django_user_model):
    budget = reset_budget()
    budget.mission_generation_call_count = 1
    budget.current_openai_call_count = 1
    budget.save()

    from apps.apk_files.models import APKFile
    from apps.audits.models import Audit
    from apps.projects.models import Project

    project = Project.objects.create(name="Budget project")
    audit = Audit.objects.create(project=project, name="Budget audit")
    APKFile.objects.create(
        audit=audit,
        package_name="owasp.sat.agoat",
        sha256="a" * 64,
        size_bytes=1234,
    )
    finding = Finding.objects.create(
        audit=audit,
        rule_id="SDK-ROOT-001",
        title="Root detection via RootBeer",
        severity="Medium",
        confidence="HIGH",
        standard="MASVS",
        category="MASVS-RESILIENCE",
        description="Root detection control can be validated in the lab.",
    )
    user = django_user_model.objects.create_user("budget-gen", password="x")
    from django.contrib.auth.models import Group

    call_command("bootstrap_roles", verbosity=0)
    user.groups.add(Group.objects.get(name=ANALYST_GROUP))

    with patch(
        "apps.dynamic_analysis.services.finding_validation_missions.configured_planner_provider"
    ) as provider_factory:
        provider = _BoundedOpenAIProvider()
        provider_factory.return_value = provider
        with pytest.raises(FindingValidationMissionError) as exc_info:
            generate_finding_validation_mission(
                finding=finding,
                requested_by=user,
            )

    assert exc_info.value.code == "OPENAI_BUDGET_EXHAUSTED"
    assert "Evidence collected so far was preserved" in str(exc_info.value)
    assert provider.next_action_calls == 0
    status = budget_status()
    assert status["current_openai_call_count"] == 1
    assert status["exhausted"] is True


@pytest.mark.django_db
@override_settings(
    MSAP_OPENAI_MAX_MISSION_GENERATION_CALLS=1,
    MSAP_OPENAI_MAX_ADAPTIVE_DECISION_CALLS=6,
    MSAP_OPENAI_MAX_TOTAL_CALLS=7,
)
def test_budget_prevents_adaptive_decision_call(django_user_model):
    user, _audit, _apk, plan = _approved_execution_plan(
        django_user_model,
        "budget-decision",
    )
    budget = reset_budget()
    budget.adaptive_decision_call_count = 6
    budget.current_openai_call_count = 6
    budget.save()

    provider = _BoundedOpenAIProvider()
    agent = AssessmentAgent(decision_provider=provider, gateway_executor=Mock())
    run = agent.create_run(plan=plan, requested_by=user)
    run = agent.execute(run.id)

    assert run.status == AgentRun.Status.FAILED
    assert run.termination_reason == "OPENAI_BUDGET_EXHAUSTED"
    assert run.failure_category == AgentRun.FailureCategory.OPENAI_BUDGET_EXHAUSTED
    assert "Evidence collected so far was preserved" in run.failure_message
    assert provider.next_action_calls == 0
    assert budget_status()["current_openai_call_count"] == 6


@pytest.mark.django_db
@override_settings(
    MSAP_OPENAI_MAX_MISSION_GENERATION_CALLS=1,
    MSAP_OPENAI_MAX_ADAPTIVE_DECISION_CALLS=6,
    MSAP_OPENAI_MAX_TOTAL_CALLS=7,
)
def test_provider_failure_after_request_increments_budget(
    django_user_model,
):
    user, _audit, _apk, plan = _approved_execution_plan(
        django_user_model,
        "budget-provider-failure",
    )
    reset_budget()

    provider = _BoundedOpenAIProvider(
        failure_code="PROVIDER_HTTP_ERROR",
        request_sent=True,
    )
    agent = AssessmentAgent(decision_provider=provider, gateway_executor=Mock())
    run = agent.create_run(plan=plan, requested_by=user)
    run = agent.execute(run.id)

    assert run.status == AgentRun.Status.FAILED
    assert run.termination_reason == "PROVIDER_FAILURE"
    status = budget_status()
    assert status["adaptive_decision_call_count"] == 1
    assert status["current_openai_call_count"] == 1
    assert provider.next_action_calls == 1


@pytest.mark.django_db
@override_settings(
    MSAP_OPENAI_MAX_MISSION_GENERATION_CALLS=1,
    MSAP_OPENAI_MAX_ADAPTIVE_DECISION_CALLS=6,
    MSAP_OPENAI_MAX_TOTAL_CALLS=7,
)
def test_local_schema_preflight_failure_does_not_increment_budget(
    django_user_model,
):
    user, _audit, _apk, plan = _approved_execution_plan(
        django_user_model,
        "budget-schema-preflight",
    )
    reset_budget()

    provider = _BoundedOpenAIProvider(
        failure_code="PROVIDER_SCHEMA_LOCAL_REJECTED",
        request_sent=False,
    )
    agent = AssessmentAgent(decision_provider=provider, gateway_executor=Mock())
    run = agent.create_run(plan=plan, requested_by=user)
    run = agent.execute(run.id)

    assert run.status == AgentRun.Status.FAILED
    assert run.termination_reason == "PROVIDER_FAILURE"
    status = budget_status()
    assert status["adaptive_decision_call_count"] == 0
    assert status["current_openai_call_count"] == 0
    assert provider.next_action_calls == 1


@pytest.mark.django_db
@override_settings(
    MSAP_OPENAI_MAX_MISSION_GENERATION_CALLS=1,
    MSAP_OPENAI_MAX_ADAPTIVE_DECISION_CALLS=6,
    MSAP_OPENAI_MAX_TOTAL_CALLS=1,
)
def test_retry_run_inherits_global_budget(django_user_model):
    user, _audit, _apk, plan = _approved_execution_plan(
        django_user_model,
        "budget-retry",
    )
    reset_budget()

    failing_provider = _BoundedOpenAIProvider(
        failure_code="PROVIDER_HTTP_ERROR",
        request_sent=True,
    )
    agent = AssessmentAgent(
        decision_provider=failing_provider,
        gateway_executor=Mock(),
    )
    first_run = agent.create_run(plan=plan, requested_by=user)
    first_run = agent.execute(first_run.id)
    assert first_run.status == AgentRun.Status.FAILED
    assert is_pre_execution_provider_failure(first_run) is True

    retry_provider = _BoundedOpenAIProvider()
    agent_retry = AssessmentAgent(
        decision_provider=retry_provider,
        gateway_executor=Mock(),
    )
    retry_run = agent_retry.create_run(
        plan=plan,
        requested_by=user,
        retry_of_run=first_run,
    )
    retry_run = agent_retry.execute(retry_run.id)

    assert retry_run.status == AgentRun.Status.FAILED
    assert retry_run.termination_reason == "OPENAI_BUDGET_EXHAUSTED"
    assert retry_provider.next_action_calls == 0
    status = budget_status()
    assert status["current_openai_call_count"] == 1
    assert status["remaining_total_calls"] == 0


@pytest.mark.django_db(transaction=True)
def test_concurrent_reservations_cannot_exceed_cap(tmp_path):
    """Concurrent reservations can never push the counter past the cap.

    Uses a file-backed SQLite database so every worker thread gets its own
    connection and real (per-file) locking instead of the shared in-memory
    test DB. On PostgreSQL the ``select_for_update`` row lock serializes the
    reservations; on SQLite the busy-timeout serializes the writes. Either
    way the invariant asserted here is that the recorded count never exceeds
    the cap.
    """
    from django.db import connections
    from django.test import override_settings as ovs

    db_file = tmp_path / "budget-concurrent.sqlite3"
    new_databases = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": str(db_file),
        }
    }
    connections["default"].close()
    try:
        with ovs(DATABASES=new_databases):
            from django.core.management import call_command as call_migrate

            call_migrate("migrate", database="default", interactive=False, verbosity=0)
            budget = reset_budget()
            budget.max_mission_generation_calls = 1
            budget.max_adaptive_decision_calls = 1
            budget.max_total_openai_calls = 1
            budget.save()
            outcomes: list[tuple[int, bool]] = []
            outcomes_lock = threading.Lock()
            barrier = threading.Barrier(3)

            def worker(worker_id: int) -> None:
                try:
                    barrier.wait(timeout=10)
                except Exception:
                    pass
                for attempt in range(8):
                    try:
                        reserve_call(KIND_DECISION)
                        with outcomes_lock:
                            outcomes.append((worker_id, True))
                        return
                    except OpenAIBudgetExhausted:
                        with outcomes_lock:
                            outcomes.append((worker_id, False))
                        return
                    except Exception:
                        # SQLite busy contention: retry the bounded reservation.
                        import time as time_module

                        time_module.sleep(0.05)
                with outcomes_lock:
                    outcomes.append((worker_id, False))

            threads = [
                threading.Thread(target=worker, args=(index,)) for index in range(3)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=60)

            status = budget_status()
    finally:
        connections["default"].close()
    assert status["current_openai_call_count"] <= 1
    assert status["current_openai_call_count"] >= 1
    assert status["exhausted"] is True


@pytest.mark.django_db
def test_budget_status_endpoint_is_safe(analyst_user):
    from rest_framework.test import APIClient

    client = APIClient()
    client.force_authenticate(analyst_user)
    response = client.get("/api/dynamic/finding-validations/budget-status/")
    assert response.status_code == 200
    payload = response.json()
    assert payload["scope"] == GLOBAL_SCOPE
    assert payload["max_mission_generation_calls"] >= 1
    assert "provider_response_ids" in payload
    assert "budget_exhausted_reason" in payload


@pytest.mark.django_db
def test_release_call_rolls_back_only_unused_reservation():
    reset_budget()
    reserve_call(KIND_DECISION)
    reserve_call(KIND_GENERATION)
    status = budget_status()
    assert status["current_openai_call_count"] == 2

    release_call(KIND_DECISION)
    release_call(KIND_GENERATION)
    status = budget_status()
    assert status["current_openai_call_count"] == 0
    assert status["mission_generation_call_count"] == 0
    assert status["adaptive_decision_call_count"] == 0


@pytest.mark.django_db
def test_response_ids_are_recorded_deduplicated():
    reset_budget()
    reserve_call(KIND_DECISION)

    from apps.dynamic_analysis.services.openai_budget import record_response_id

    record_response_id("resp_abc123")
    record_response_id("resp_abc123")
    record_response_id("resp_def456")
    record_response_id("not-a-real-id!@#")
    assert budget_status()["provider_response_ids"] == [
        "resp_abc123",
        "resp_def456",
    ]


@pytest.mark.django_db
@override_settings(
    MSAP_OPENAI_MAX_EVIDENCE_EXPLANATION_CALLS=2,
    MSAP_OPENAI_MAX_TOTAL_CALLS=5,
)
def test_evidence_explanation_budget_is_separate_from_adaptive_decisions():
    budget = reset_budget()

    reserve_call(KIND_EVIDENCE_EXPLANATION)
    budget.refresh_from_db()

    assert budget.evidence_explanation_call_count == 1
    assert budget.adaptive_decision_call_count == 0
    assert budget.current_openai_call_count == 1

    status = budget_status()
    assert status["evidence_explanation_call_count"] == 1
    assert status["max_evidence_explanation_calls"] == 2

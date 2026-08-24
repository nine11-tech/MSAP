from unittest.mock import Mock

import pytest
from django.test import override_settings

from apps.dynamic_analysis.models import AgentRun, FridaScriptProposal
from apps.dynamic_analysis.services.agent_action_contract import (
    AgentActionDecisionError,
    validate_action_decision,
)
from apps.dynamic_analysis.services.agent_tools import AgentToolError, execute_agent_tool
from apps.dynamic_analysis.services.generated_frida_scripts import (
    approve_frida_script_proposal,
    create_frida_script_proposal,
    generate_frida_script_proposal,
    is_generated_frida_source_identifier,
    mark_frida_script_execution,
    resolve_approved_generated_frida_source,
)
from test_dynamic_analysis import (
    _approved_adaptive_plan,
    _tool_decision,
)


@pytest.mark.django_db
@override_settings(MSAP_FRIDA_SCRIPT_GENERATION_PROVIDER="DETERMINISTIC")
def test_frida_script_proposal_is_generated_and_requires_auditor_approval(
    django_user_model,
):
    user, _audit, _apk, plan = _approved_adaptive_plan(
        django_user_model,
        "generated-frida-proposal",
    )
    from apps.dynamic_analysis.services.assessment_agent import AssessmentAgent
    from apps.dynamic_analysis.services.agent_decision_provider import (
        DeterministicAdaptiveDecisionProvider,
    )

    run = AssessmentAgent(
        decision_provider=DeterministicAdaptiveDecisionProvider()
    ).create_run(plan=plan, requested_by=user)
    proposal = generate_frida_script_proposal(run=run, requested_by=user)

    assert proposal.status == FridaScriptProposal.Status.GENERATED
    assert proposal.generator_provider == "DETERMINISTIC"
    assert is_generated_frida_source_identifier(proposal.source_identifier)
    with pytest.raises(Exception):
        resolve_approved_generated_frida_source(
            proposal.source_identifier,
            run=run,
            requested_by=user,
            target_package=plan.target_package,
        )

    proposal = approve_frida_script_proposal(proposal=proposal, approved_by=user)

    assert proposal.status == FridaScriptProposal.Status.APPROVED
    assert resolve_approved_generated_frida_source(
        proposal.source_identifier,
        run=run,
        requested_by=user,
        target_package=plan.target_package,
    ) == proposal.source_code


@pytest.mark.django_db
def test_action_decision_accepts_only_approved_generated_frida_source(
    django_user_model,
):
    user, _audit, _apk, plan = _approved_adaptive_plan(
        django_user_model,
        "generated-frida-decision",
    )
    from apps.dynamic_analysis.services.assessment_agent import AssessmentAgent
    from apps.dynamic_analysis.services.agent_decision_provider import (
        DeterministicAdaptiveDecisionProvider,
    )

    run = AssessmentAgent(
        decision_provider=DeterministicAdaptiveDecisionProvider()
    ).create_run(plan=plan, requested_by=user)
    hypothesis = run.hypotheses.first()
    source = 'Java.perform(function () { try { send({type: "probe"}); } catch (e) { send({type: "probe_error", error: String(e)}); } });'
    proposal = create_frida_script_proposal(
        run=run,
        requested_by=user,
        hypothesis=hypothesis,
        title="Runtime probe",
        rationale="Collect one runtime event.",
        expected_evidence=["Frida event"],
        source_code=source,
    )
    decision = _tool_decision(
        hypothesis.hypothesis_id,
        "frida_run_js",
        {
            "package_name": plan.target_package,
            "mode": "attach",
            "source": proposal.source_identifier,
            "timeout": 10,
            "capture_logcat": True,
            "capture_screenshot": True,
        },
    )

    with pytest.raises(AgentActionDecisionError) as exc:
        validate_action_decision(decision, run=run)
    assert exc.value.code == "FRIDA_SCRIPT_NOT_APPROVED"

    approve_frida_script_proposal(proposal=proposal, approved_by=user)
    validated = validate_action_decision(decision, run=run)

    assert validated["arguments"]["source"] == proposal.source_identifier


@pytest.mark.django_db
def test_agent_tool_resolves_approved_generated_frida_source_before_host_call(
    django_user_model,
):
    user, _audit, _apk, plan = _approved_adaptive_plan(
        django_user_model,
        "generated-frida-tool",
    )
    from apps.dynamic_analysis.services.assessment_agent import AssessmentAgent
    from apps.dynamic_analysis.services.agent_decision_provider import (
        DeterministicAdaptiveDecisionProvider,
    )

    run = AssessmentAgent(
        decision_provider=DeterministicAdaptiveDecisionProvider()
    ).create_run(plan=plan, requested_by=user)
    source = 'Java.perform(function () { try { send({type: "resolved"}); } catch (e) { send({type: "err"}); } });'
    proposal = approve_frida_script_proposal(
        proposal=create_frida_script_proposal(
            run=run,
            requested_by=user,
            title="Resolved runtime probe",
            rationale="Verify gateway source resolution.",
            expected_evidence=["Frida event"],
            source_code=source,
        ),
        approved_by=user,
    )
    client = Mock()

    def request_json(route, *, method, body):
        assert route == "/actions/frida-run-js"
        assert method == "POST"
        assert body["source"] == source
        return {
            "status": "PASS",
            "package_name": plan.target_package,
            "mode": "attach",
            "pid": 1234,
            "script_sha256": proposal.source_sha256,
            "script_size_bytes": len(source.encode("utf-8")),
            "script_started": True,
            "script_loaded": True,
            "script_completed": True,
            "events": [{"type": "resolved"}],
            "event_count": 1,
            "error_count": 0,
            "cleanup_state": "DETACHED",
        }

    client.request_json.side_effect = request_json

    output = execute_agent_tool(
        "frida_run_js",
        {
            "package_name": plan.target_package,
            "mode": "attach",
            "source": proposal.source_identifier,
            "timeout": 10,
            "capture_logcat": False,
            "capture_screenshot": False,
        },
        requested_by=user,
        client=client,
    )

    assert output["script_sha256"] == proposal.source_sha256
    assert output["events"] == [{"type": "resolved"}]


@pytest.mark.django_db
def test_generated_frida_failure_records_auditor_suggestion(django_user_model):
    user, _audit, _apk, plan = _approved_adaptive_plan(
        django_user_model,
        "generated-frida-failure",
    )
    from apps.dynamic_analysis.services.assessment_agent import AssessmentAgent
    from apps.dynamic_analysis.services.agent_decision_provider import (
        DeterministicAdaptiveDecisionProvider,
    )

    run = AssessmentAgent(
        decision_provider=DeterministicAdaptiveDecisionProvider()
    ).create_run(plan=plan, requested_by=user)
    proposal = approve_frida_script_proposal(
        proposal=create_frida_script_proposal(
            run=run,
            requested_by=user,
            title="Failing probe",
            rationale="Exercise failure reporting.",
            expected_evidence=["Frida event"],
            source_code='Java.perform(function () { try { send({type: "x"}); } catch (e) { send({type: "err"}); } });',
        ),
        approved_by=user,
    )

    mark_frida_script_execution(
        proposal.source_identifier,
        succeeded=False,
        error="Target package is installed but not running",
    )
    proposal.refresh_from_db()

    assert proposal.status == FridaScriptProposal.Status.FAILED
    assert "Launch the target app" in proposal.suggested_fix


@pytest.mark.django_db
def test_raw_generated_frida_javascript_is_still_rejected(django_user_model):
    user, _audit, _apk, plan = _approved_adaptive_plan(
        django_user_model,
        "raw-frida-rejected",
    )
    from apps.dynamic_analysis.services.assessment_agent import AssessmentAgent
    from apps.dynamic_analysis.services.agent_decision_provider import (
        DeterministicAdaptiveDecisionProvider,
    )

    run = AssessmentAgent(
        decision_provider=DeterministicAdaptiveDecisionProvider()
    ).create_run(plan=plan, requested_by=user)
    hypothesis = run.hypotheses.first()
    decision = _tool_decision(
        hypothesis.hypothesis_id,
        "frida_run_js",
        {
            "package_name": plan.target_package,
            "mode": "attach",
            "source": 'Java.perform(function(){ send({type:"raw"}); });',
            "timeout": 10,
            "capture_logcat": True,
            "capture_screenshot": True,
        },
    )

    with pytest.raises(AgentActionDecisionError) as exc:
        validate_action_decision(decision, run=run)

    assert exc.value.code == "AGENT_DECISION_FRIDA_SOURCE_REJECTED"

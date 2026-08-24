import pytest
from django.test import override_settings

from apps.dynamic_analysis.models import AgentRunStep
from apps.dynamic_analysis.services.agent_decision_provider import (
    DeterministicAdaptiveDecisionProvider,
)
from apps.dynamic_analysis.services.assessment_agent import AssessmentAgent
from apps.dynamic_analysis.services.assessment_executor import AssessmentExecutor
from apps.evidence.models import Evidence
from apps.findings.models import Finding
from test_dynamic_analysis import _approved_execution_plan


@pytest.mark.django_db
@override_settings(MSAP_EVIDENCE_EXPLANATION_PROVIDER="DETERMINISTIC")
def test_evidence_creation_persists_agent_explanation_and_source_finding(
    django_user_model,
):
    user, audit, _apk, plan = _approved_execution_plan(
        django_user_model,
        "ai-evidence-explanation",
    )
    finding = Finding.objects.create(
        audit=audit,
        rule_id="MSAP-AND-006",
        title="Exported broadcast receiver is reachable",
        severity="Medium",
        confidence="HIGH",
        standard="MASVS",
        description="A receiver exported without required permission can accept external intents.",
        recommendation="Restrict the receiver or require a signature permission.",
    )
    plan.source_finding = finding
    plan.save(update_fields=["source_finding"])

    run = AssessmentAgent(
        decision_provider=DeterministicAdaptiveDecisionProvider()
    ).create_run(plan=plan, requested_by=user)
    step = AgentRunStep.objects.create(
        run=run,
        sequence_number=99,
        tool_name="send_explicit_broadcast",
        status=AgentRunStep.Status.SUCCEEDED,
        evidence_requirements=["broadcast_result"],
        input_summary={"package_name": plan.target_package},
        output_summary={"delivered": True, "target_correlated": True},
        observation={
            "tool_name": "send_explicit_broadcast",
            "data": {"delivered": True, "target_correlated": True},
            "redaction_applied": False,
        },
    )

    evidence = AssessmentExecutor._create_evidence(
        run,
        step,
        None,
        step.observation,
    )

    assert evidence.finding == finding
    assert evidence.ai_explanation_status == "COMPLETED"
    assert evidence.ai_explanation_provider == "DETERMINISTIC"
    assert evidence.ai_explanation
    assert evidence.ai_conclusion
    assert evidence.ai_security_impact
    assert evidence.ai_evidence_strength == "SUPPORTING"


@pytest.mark.django_db
@override_settings(MSAP_EVIDENCE_EXPLANATION_PROVIDER="DISABLED")
def test_evidence_creation_preserves_record_when_ai_explanation_disabled(
    django_user_model,
):
    user, _audit, _apk, plan = _approved_execution_plan(
        django_user_model,
        "ai-evidence-disabled",
    )
    run = AssessmentAgent(
        decision_provider=DeterministicAdaptiveDecisionProvider()
    ).create_run(plan=plan, requested_by=user)
    step = AgentRunStep.objects.create(
        run=run,
        sequence_number=99,
        tool_name="dump_ui",
        status=AgentRunStep.Status.SUCCEEDED,
        observation={"tool_name": "dump_ui", "data": {"node_count": 3}},
    )

    evidence = AssessmentExecutor._create_evidence(
        run,
        step,
        None,
        step.observation,
    )

    assert Evidence.objects.filter(pk=evidence.pk).exists()
    assert evidence.ai_explanation_status == "SKIPPED"
    assert evidence.ai_explanation == ""

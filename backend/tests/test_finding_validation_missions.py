from unittest.mock import Mock, patch

import pytest
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.test import override_settings
from rest_framework.test import APIClient

from apps.api.roles import ANALYST_GROUP, VIEWER_GROUP
from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.dynamic_analysis.models import (
    AgentRun,
    AgentRuntime,
    DynamicValidationResult,
    FindingValidationMission,
)
from apps.dynamic_analysis.services.agent_tools import ALL_TOOL_NAMES
from apps.dynamic_analysis.services.finding_validation_missions import (
    refresh_mission_from_run,
)
from apps.evidence.models import Evidence
from apps.findings.models import Finding
from apps.projects.models import Project


PASSWORD = "Correct-Horse-Battery-Staple-42!"


@pytest.fixture
def analyst_client(django_user_model):
    call_command("bootstrap_roles", verbosity=0)
    user = django_user_model.objects.create_user("mission-analyst", password=PASSWORD)
    user.groups.add(Group.objects.get(name=ANALYST_GROUP))
    client = APIClient()
    client.force_authenticate(user)
    client.user = user
    return client


@pytest.fixture
def viewer_client(django_user_model):
    call_command("bootstrap_roles", verbosity=0)
    user = django_user_model.objects.create_user("mission-viewer", password=PASSWORD)
    user.groups.add(Group.objects.get(name=VIEWER_GROUP))
    client = APIClient()
    client.force_authenticate(user)
    return client


@pytest.fixture
def audit_with_apk(db):
    project = Project.objects.create(name="Mission project")
    audit = Audit.objects.create(project=project, name="AndroGoat audit")
    apk = APKFile.objects.create(
        audit=audit,
        package_name="owasp.sat.agoat",
        sha256="a" * 64,
        size_bytes=1234,
    )
    AgentRuntime.objects.create(
        name="Internal runtime",
        runtime_type=AgentRuntime.RuntimeType.INTERNAL_CONTROLLER,
        status=AgentRuntime.Status.AVAILABLE,
        enabled=True,
        capabilities={"tools": sorted(ALL_TOOL_NAMES), "objectives": []},
    )
    return audit, apk


@pytest.mark.django_db
@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_generate_mission_from_supported_static_finding(analyst_client, audit_with_apk):
    audit, _apk = audit_with_apk
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

    response = analyst_client.post(
        f"/api/findings/{finding.id}/dynamic-validation/generate/",
        {},
        format="json",
    )

    assert response.status_code == 201
    data = response.json()
    assert data["finding"] == finding.id
    assert data["target_package"] == "owasp.sat.agoat"
    assert data["status"] == "VALIDATED"
    assert data["scenario_contract"]["contract_version"] == "msap.dynamic-validation-scenario/v1"
    assert data["scenario_contract"]["source_finding_id"] == finding.id
    assert data["allowed_capabilities"]
    assert data["assessment_plan"] is not None


@pytest.mark.django_db
@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_unsupported_finding_generates_not_dynamically_testable_without_plan(
    analyst_client,
    audit_with_apk,
):
    audit, _apk = audit_with_apk
    finding = Finding.objects.create(
        audit=audit,
        rule_id="CUSTOM-HARDCODED-SECRET",
        title="Hardcoded API secret",
        severity="High",
        confidence="HIGH",
        standard="MASVS",
        category="CRYPTO",
        description="Static string evidence only.",
    )

    response = analyst_client.post(
        f"/api/findings/{finding.id}/dynamic-validation/generate/",
        {},
        format="json",
    )

    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "NOT_DYNAMICALLY_TESTABLE"
    assert data["assessment_plan"] is None
    assert data["scenario_contract"]["not_assessable_reason"]
    assert data["allowed_capabilities"] == []


@pytest.mark.django_db
@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_approval_and_start_require_analyst(
    analyst_client,
    viewer_client,
    audit_with_apk,
):
    audit, _apk = audit_with_apk
    finding = Finding.objects.create(
        audit=audit,
        rule_id="SDK-ROOT-001",
        title="Root detection via RootBeer",
        severity="Medium",
        confidence="HIGH",
        standard="MASVS",
        category="MASVS-RESILIENCE",
    )
    mission = analyst_client.post(
        f"/api/findings/{finding.id}/dynamic-validation/generate/",
        {},
        format="json",
    ).json()

    assert viewer_client.post(
        f"/api/dynamic/finding-validations/{mission['id']}/approve/",
        {},
        format="json",
    ).status_code == 403

    approved = analyst_client.post(
        f"/api/dynamic/finding-validations/{mission['id']}/approve/",
        {},
        format="json",
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "APPROVED"

    assert viewer_client.post(
        f"/api/dynamic/finding-validations/{mission['id']}/start/",
        {},
        format="json",
    ).status_code == 403

    with patch(
        "apps.dynamic_analysis.views.execute_adaptive_assessment_run_task.delay",
        return_value=Mock(id="task-1"),
    ):
        started = analyst_client.post(
            f"/api/dynamic/finding-validations/{mission['id']}/start/",
            {},
            format="json",
        )
    assert started.status_code == 202
    assert started.json()["mission"]["status"] == "RUNNING"
    assert started.json()["run"]["objective"] == "ASSESSMENT_PLAN_EXECUTION"


@pytest.mark.django_db
def test_oracle_result_controls_final_mission_status(audit_with_apk, django_user_model):
    audit, apk = audit_with_apk
    user = django_user_model.objects.create_user("oracle-owner", password=PASSWORD)
    finding = Finding.objects.create(
        audit=audit,
        rule_id="SDK-ROOT-001",
        title="Root detection via RootBeer",
        severity="Medium",
        confidence="HIGH",
        standard="MASVS",
        category="MASVS-RESILIENCE",
    )
    run = AgentRun.objects.create(
        audit=audit,
        runtime=AgentRuntime.objects.first(),
        target_package=apk.package_name,
        objective=AgentRun.Objective.ASSESSMENT_PLAN_EXECUTION,
        requested_by=user,
        status=AgentRun.Status.SUCCEEDED,
    )
    mission = FindingValidationMission.objects.create(
        audit=audit,
        apk=apk,
        finding=finding,
        agent_run=run,
        target_package=apk.package_name,
        status=FindingValidationMission.Status.RUNNING,
        created_by=user,
    )
    evidence = Evidence.objects.create(
        audit=audit,
        finding=finding,
        agent_run=run,
        evidence_type="tool_output",
        source="test",
        snippet="deterministic evidence",
        redacted=True,
        sha256="b" * 64,
    )
    result = DynamicValidationResult.objects.create(
        audit=audit,
        finding=finding,
        rule_id=finding.rule_id,
        playbook_id="ROOT_DETECTION_SCREEN_VALIDATION",
        agent_run=run,
        oracle_id="root_detection_frida_oracle",
        oracle_result={"result_contract": {"result": "SUPPORTED"}, "summary": "oracle supported"},
        validation_status=DynamicValidationResult.ValidationStatus.SUPPORTED,
        confidence=0.9,
        safe_summary="oracle supported",
        limitations="bounded lab result",
    )
    result.evidence.set([evidence])

    refreshed = refresh_mission_from_run(run)

    assert refreshed.id == mission.id
    assert refreshed.status == FindingValidationMission.Status.CONFIRMED
    assert refreshed.dynamic_validation_result_id == result.id
    assert list(refreshed.evidence.values_list("id", flat=True)) == [evidence.id]

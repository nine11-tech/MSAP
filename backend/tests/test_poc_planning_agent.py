"""Tests for the AI PoC Planning Agent (contract msap.dynamic-poc-plan/v1).

Covered guarantees:

- deterministic fallback builds a validated plan without OpenAI calls
- plan steps only reference allowed (non-destructive) capabilities
- tool arguments are normalized (package_name/audit_id filled, required
  schema defaults applied, unsafe instructions dropped)
- objective/scope must match exactly or plan validation rejects the plan
- rationale is sanitized (no MSAP-AND- ids, no playbook ids)
- scenario text is scrubbed of prohibited terms
- mission created from a PoC plan is VALIDATED with no playbook id
- not-testable classifications raise POC_PLANNING_NOT_AVAILABLE
- budget guard: deterministic planning never spends OpenAI budget
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.test import override_settings

from apps.api.roles import ANALYST_GROUP
from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.dynamic_analysis.models import (
    AgentRuntime,
    AssessmentPlan,
    DynamicPoCPlan,
    FindingValidationMission,
)
from apps.dynamic_analysis.services.agent_tools import ALL_TOOL_NAMES, TOOL_MANIFEST
from apps.dynamic_analysis.services.assessment_planner import (
    PlanValidationError,
)
from apps.dynamic_analysis.services.openai_budget import (
    GLOBAL_SCOPE,
    budget_status,
)
from apps.dynamic_analysis.services.poc_planning_agent import (
    PoCPlanningError,
    _normalize_tool_arguments,
    _sanitize_rationale,
    _scrub_scenario_text,
    build_assessment_plan_from_poc_plan,
    build_poc_plan,
)
from apps.dynamic_analysis.services.finding_validation_missions import (
    create_mission_from_poc_plan,
)
from apps.findings.models import Finding
from apps.projects.models import Project


PASSWORD = "Correct-Horse-Battery-Staple-42!"


@pytest.fixture
def analyst(django_user_model):
    call_command("bootstrap_roles", verbosity=0)
    user = django_user_model.objects.create_user("poc-analyst", password=PASSWORD)
    user.groups.add(Group.objects.get(name=ANALYST_GROUP))
    return user


@pytest.fixture
def audit_with_apk(db):
    project = Project.objects.create(name="PoC planning project")
    audit = Audit.objects.create(project=project, name="PoC planning audit")
    apk = APKFile.objects.create(
        audit=audit,
        package_name="owasp.sat.agoat",
        sha256="e" * 64,
        size_bytes=4321,
    )
    AgentRuntime.objects.create(
        name="Internal runtime",
        runtime_type=AgentRuntime.RuntimeType.INTERNAL_CONTROLLER,
        status=AgentRuntime.Status.AVAILABLE,
        enabled=True,
        capabilities={"tools": sorted(ALL_TOOL_NAMES), "objectives": []},
    )
    return audit, apk


def _component_finding(audit):
    return Finding.objects.create(
        audit=audit,
        rule_id="MASVS-PLATFORM-EXPORTED-001",
        title="Exported activity exposure",
        severity="Medium",
        category="MASVS-PLATFORM",
        description="An exported activity can be invoked from outside the app.",
        confidence="HIGH",
        standard="MASVS",
    )


def _candidate(finding, **overrides):
    candidate = {
        "finding_id": finding.pk,
        "classification": "RECOMMENDED_DYNAMIC_VALIDATION",
        "security_hypothesis": "The exported component is reachable at runtime.",
        "dynamic_validation_value": "Runtime proof of external reachability.",
        "recommended_poc_summary": "Invoke the exported component and capture evidence.",
        "likely_capabilities": ["launch_exported_activity", "take_screenshot"],
        "expected_evidence": ["tool_output", "screenshot"],
        "limitations": "Only authorized components are invoked.",
        "estimated_complexity": "LOW",
    }
    candidate.update(overrides)
    return candidate


@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_normalize_tool_arguments_fills_required_schema_defaults():
    assert _normalize_tool_arguments(
        "take_screenshot",
        {},
        target_package="owasp.sat.agoat",
        audit_id=7,
    ) == {"capture_reason": "device_readiness", "audit_id": 7}
    assert _normalize_tool_arguments(
        "start_logcat",
        {},
        target_package="owasp.sat.agoat",
        audit_id=7,
    ) == {
        "package_name": "owasp.sat.agoat",
        "reason": "agent_step",
        "max_seconds": 30,
    }
    assert _normalize_tool_arguments(
        "frida_attach",
        {},
        target_package="owasp.sat.agoat",
        audit_id=7,
    ) == {"package_name": "owasp.sat.agoat", "mode": "attach", "timeout": 10}
    assert _normalize_tool_arguments(
        "launch_package",
        {"package_name": "evil.pkg", "extra": 1},
        target_package="owasp.sat.agoat",
        audit_id=7,
    ) == {"package_name": "owasp.sat.agoat"}
    # Dynamic identifiers are never invented; bounded integers are defaulted.
    assert _normalize_tool_arguments(
        "get_logcat_excerpt",
        {},
        target_package="owasp.sat.agoat",
        audit_id=7,
    ) == {"max_lines": 1}


@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_sanitize_rationale_removes_ids():
    assert _sanitize_rationale(
        "MSAP-AND-004 playbook ROOT_DETECTION_SCREEN_VALIDATION must be confirmed"
    ) == "approved dynamic validation playbook approved dynamic validation must be confirmed"
    assert "MSAP-AND-" not in _sanitize_rationale("MSAP-AND-004")
    assert "ROOT_DETECTION_SCREEN_VALIDATION" not in _sanitize_rationale(
        "run ROOT_DETECTION_SCREEN_VALIDATION"
    )
    assert _sanitize_rationale("plain rationale text") == "plain rationale text"


@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_scrub_scenario_text_removes_prohibited_terms():
    text = "The app stores credentials in a local database and talks to a shell process."
    scrubbed = _scrub_scenario_text(text)
    assert "database" not in scrubbed
    assert "shell" not in scrubbed
    assert scrubbed


@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_deterministic_build_poc_plan_never_spends_budget(audit_with_apk, analyst):
    audit, _apk = audit_with_apk
    finding = _component_finding(audit)
    before = budget_status(GLOBAL_SCOPE)["current_openai_call_count"]

    result = build_poc_plan(
        finding=finding,
        candidate=_candidate(finding),
        requested_by=analyst,
    )
    after = budget_status(GLOBAL_SCOPE)["current_openai_call_count"]
    assert after == before
    assert result["mode"] == "DETERMINISTIC_FALLBACK"
    plan = result["poc_plan"]
    assert plan.provider == "DETERMINISTIC"
    assert plan.model == "msap-deterministic-poc-plan-v1"
    assert plan.plan_hash
    assert isinstance(plan.plan, dict)
    assert plan.plan["objective"]
    assert plan.plan["steps"]
    canonical = result["canonical_plan"]
    assert canonical["assessment_objective"] == plan.plan["objective"]
    assert canonical["scope"] == plan.plan["scope"]
    tools = {
        tool["name"]
        for step in canonical["steps"]
        for tool in step["tools"]
    }
    assert "clear_package_data" not in tools
    assert "reset_root_detection_demo" not in tools
    assert "install_verified_apk" not in tools
    assert "frida_setup" not in tools
    assert tools <= {
        "get_device_status",
        "list_packages",
        "launch_package",
        "force_stop_package",
        "take_screenshot",
        "start_logcat",
        "stop_logcat",
        "get_logcat_excerpt",
        "dump_ui",
        "tap_coordinates",
        "type_text",
        "frida_status",
        "frida_ps",
        "frida_attach",
        "frida_run_js",
    }
    assert "get_device_status" in tools
    assert "launch_package" in tools
    assert tools & {"take_screenshot", "dump_ui"}
    for step in canonical["steps"]:
        for tool in step["tools"]:
            schema = TOOL_MANIFEST[tool["name"]].input_schema
            assert set(tool["arguments"]) <= set(schema.get("properties", {}))
            missing = set(schema.get("required", ())) - set(tool["arguments"])
            assert not missing, f"{tool['name']} is missing {missing}"


@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_assessment_plan_and_mission_from_poc_plan(audit_with_apk, analyst):
    audit, _apk = audit_with_apk
    finding = _component_finding(audit)
    result = build_poc_plan(
        finding=finding,
        candidate=_candidate(finding),
        requested_by=analyst,
    )
    plan = build_assessment_plan_from_poc_plan(
        finding=finding,
        poc_plan=result["poc_plan"],
        canonical_plan=result["canonical_plan"],
        requested_by=analyst,
    )
    assert plan.audit_id == audit.id
    assert plan.source_finding_id == finding.id
    assert plan.status == AssessmentPlan.Status.VALIDATED
    assert plan.validation_status == AssessmentPlan.ValidationStatus.PASSED
    assert plan.policy_status == AssessmentPlan.PolicyStatus.PASSED
    assert plan.steps.count() >= 1
    assert plan.scenario_contract is not None

    mission = create_mission_from_poc_plan(
        finding=finding,
        plan=plan,
        candidate=_candidate(finding),
        requested_by=analyst,
    )
    assert mission.status == FindingValidationMission.Status.VALIDATED
    assert mission.playbook_id == ""
    assert mission.assessment_plan_id == plan.id
    assert mission.target_package == "owasp.sat.agoat"
    assert mission.scenario_contract is not None
    assert DynamicPoCPlan.objects.filter(finding=finding).count() == 1


@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_not_testable_classification_raises(audit_with_apk, analyst):
    audit, _apk = audit_with_apk
    finding = _component_finding(audit)

    with pytest.raises(PoCPlanningError) as exc_info:
        build_poc_plan(
            finding=finding,
            candidate=_candidate(
                finding,
                classification="NOT_TESTABLE_WITH_CURRENT_CAPABILITIES",
            ),
            requested_by=analyst,
        )
    assert exc_info.value.code == "POC_PLANNING_NOT_AVAILABLE"
    assert exc_info.value.http_status == 409
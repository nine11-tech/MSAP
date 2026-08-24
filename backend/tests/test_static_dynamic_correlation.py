"""Focused tests for the AI Static -> Dynamic correlation flow (v2).

Covered guarantees:

- correlation returns concise v2 candidate cards, never raw backend objects
- NOT_TESTABLE candidates carry missing capabilities and no Start PoC
- ALREADY_VALIDATED findings carry their current validation status
- latest_correlation reuses the cache when nothing changed
- correlation never spends OpenAI budget and never leaks secrets
- capability-gap report aggregates missing capabilities across findings
- Start PoC builds a PoC plan + AssessmentPlan + VALIDATED mission (no
  playbook id) and reuses an existing mission lifecycle stage
- Start PoC rejects cross-audit and not-testable candidates
- observation summaries map common tools to human text
- evidence previews are clean, labeled, and bounded
- new fields (result_label, result_explanation, scenario_summary) are present
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.test import override_settings
from rest_framework.test import APIClient

from apps.api.roles import ANALYST_GROUP, VIEWER_GROUP
from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.dynamic_analysis.models import (
    AgentRuntime,
    AssessmentPlan,
    DynamicPoCPlan,
    FindingValidationMission,
    StaticDynamicCorrelationRun,
)
from apps.dynamic_analysis.services.agent_tools import ALL_TOOL_NAMES
from apps.dynamic_analysis.services.capability_registry import (
    build_capability_manifest,
)
from apps.dynamic_analysis.services.openai_budget import (
    GLOBAL_SCOPE,
    budget_status,
)
from apps.dynamic_analysis.services.static_dynamic_correlation import (
    evidence_preview_type,
    evidence_title,
    friendly_action_label,
    observation_summary_for_tool,
    result_explanation,
    result_label,
)
from apps.evidence.models import Evidence
from apps.findings.models import Finding
from apps.projects.models import Project


PASSWORD = "Correct-Horse-Battery-Staple-42!"


@pytest.fixture
def analyst_client(django_user_model):
    call_command("bootstrap_roles", verbosity=0)
    user = django_user_model.objects.create_user("correlation-analyst", password=PASSWORD)
    user.groups.add(Group.objects.get(name=ANALYST_GROUP))
    client = APIClient()
    client.force_authenticate(user)
    client.user = user
    return client


@pytest.fixture
def viewer_client(django_user_model):
    call_command("bootstrap_roles", verbosity=0)
    user = django_user_model.objects.create_user("correlation-viewer", password=PASSWORD)
    user.groups.add(Group.objects.get(name=VIEWER_GROUP))
    client = APIClient()
    client.force_authenticate(user)
    return client


@pytest.fixture
def audit_with_apk(db):
    project = Project.objects.create(name="Correlation project")
    audit = Audit.objects.create(project=project, name="AndroGoat correlation audit")
    apk = APKFile.objects.create(
        audit=audit,
        package_name="owasp.sat.agoat",
        sha256="b" * 64,
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


def _component_finding(audit, **kwargs):
    """Exported-component finding: deterministically RECOMMENDED when the
    component invocation capability is present in the manifest."""
    defaults = {
        "rule_id": "MASVS-PLATFORM-EXPORTED-001",
        "title": "Exported activity exposure",
        "severity": "Medium",
        "category": "MASVS-PLATFORM",
        "description": "An exported activity can be invoked from outside the app.",
    }
    defaults.update(kwargs)
    return Finding.objects.create(
        audit=audit,
        confidence="HIGH",
        standard="MASVS",
        **defaults,
    )


def _crypto_finding(audit, **kwargs):
    defaults = {
        "rule_id": "CUSTOM-INSECURE-TLS",
        "title": "Insecure TLS configuration",
        "severity": "High",
        "category": "CRYPTO",
        "description": "Network traffic uses a weak certificate chain.",
    }
    defaults.update(kwargs)
    return Finding.objects.create(
        audit=audit,
        confidence="HIGH",
        standard="MASVS",
        **defaults,
    )


def _mission(audit, apk, finding, status="VALIDATED"):
    return FindingValidationMission.objects.create(
        audit=audit,
        apk=apk,
        finding=finding,
        target_package=apk.package_name,
        status=status,
        scenario_contract={
            "steps": [{"step_id": "s1", "objective": "Launch", "tools": []}]
        },
    )


def _connected_manifest(*available_tools):
    return build_capability_manifest(
        host_agent_connected=True,
        runtime_tools=set(available_tools),
    )


@pytest.mark.django_db
@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_correlation_returns_v2_candidate_cards(analyst_client, audit_with_apk):
    audit, _apk = audit_with_apk
    _component_finding(audit)
    _crypto_finding(audit)

    with patch(
        "apps.dynamic_analysis.services.correlation_agent._live_manifest",
        return_value=_connected_manifest("launch_exported_activity", "dump_ui"),
    ):
        response = analyst_client.post(
            f"/api/dynamic/static-dynamic-correlation/{audit.id}/start/",
            {},
            format="json",
        )

    assert response.status_code == 200
    data = response.json()
    assert data["audit_id"] == audit.id
    assert data["target_package"] == "owasp.sat.agoat"
    assert data["contract_version"] == "msap.static-dynamic-correlation/v2"
    assert data["total_static_findings"] == 2
    assert data["recommended_count"] == 1
    assert data["not_testable_count"] == 1
    assert data["optional_count"] == 0
    assert data["static_sufficient_count"] == 0
    assert data["already_validated_count"] == 0
    assert data["blocked_count"] == 0
    assert data["correlation_mode"] == "DETERMINISTIC_FALLBACK"
    assert data["model"] == "msap-deterministic-correlation-v1"
    assert "generated_at" in data

    by_finding = {item["finding_id"]: item for item in data["candidates"]}
    assert set(by_finding) == {f.pk for f in audit.findings.all()}
    recommended = [
        item for item in data["candidates"]
        if item["classification"] == "RECOMMENDED_DYNAMIC_VALIDATION"
    ]
    assert len(recommended) == 1
    card = recommended[0]
    assert card["finding_title"]
    assert card["severity"] == "Medium"
    assert card["rule_id"] == "MASVS-PLATFORM-EXPORTED-001"
    assert card["security_hypothesis"]
    assert card["dynamic_validation_value"]
    assert card["recommended_poc_summary"]
    assert card["likely_capabilities"]
    assert card["expected_evidence"]
    assert card["estimated_complexity"] in {"LOW", "MEDIUM", "HIGH"}
    assert card["start_poc_available"] is True
    assert card["current_validation_status"] == ""
    assert card["missing_capabilities"] == []
    # The card must not embed raw backend objects.
    assert "scenario_contract" not in card
    assert "mission_hash" not in card
    assert "provider_metadata" not in card
    assert "description" not in card


@pytest.mark.django_db
@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_not_testable_findings_carry_missing_capabilities(analyst_client, audit_with_apk):
    audit, _apk = audit_with_apk
    finding = _crypto_finding(audit)

    with patch(
        "apps.dynamic_analysis.services.correlation_agent._live_manifest",
        return_value=_connected_manifest("launch_exported_activity"),
    ):
        response = analyst_client.post(
            f"/api/dynamic/static-dynamic-correlation/{audit.id}/start/",
            {},
            format="json",
        )

    assert response.status_code == 200
    data = response.json()
    card = data["candidates"][0]
    assert card["finding_id"] == finding.id
    assert card["classification"] == "NOT_TESTABLE_WITH_CURRENT_CAPABILITIES"
    assert card["start_poc_available"] is False
    assert "network request capture" in card["missing_capabilities"]
    assert "TLS interception" in card["missing_capabilities"]
    assert data["not_testable_count"] == 1
    gaps = data["capability_gaps"]
    assert any(gap["missing_capability"] == "TLS interception" for gap in gaps)
    assert any(
        finding.id in gap["affected_finding_ids"]
        for gap in gaps
    )


@pytest.mark.django_db
@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_already_validated_findings_show_current_status(analyst_client, audit_with_apk):
    audit, apk = audit_with_apk
    finding = _component_finding(audit)
    _mission(audit, apk, finding, status="CONFIRMED")

    with patch(
        "apps.dynamic_analysis.services.correlation_agent._live_manifest",
        return_value=_connected_manifest("launch_exported_activity"),
    ):
        result = __import__(
            "apps.dynamic_analysis.services.correlation_agent",
            fromlist=["correlate_audit_findings"],
        ).correlate_audit_findings(audit.id)

    card = result["candidates"][0]
    assert card["classification"] == "ALREADY_VALIDATED"
    assert card["current_validation_status"] == "CONFIRMED"
    assert card["start_poc_available"] is False
    assert result["already_validated_count"] == 1


@pytest.mark.django_db
@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_correlation_prefers_confirmed_mission_over_newer_failed_rerun(
    analyst_client, audit_with_apk
):
    audit, apk = audit_with_apk
    finding = Finding.objects.create(
        audit=audit,
        rule_id="MSAP-AND-001",
        title="Debuggable build enables runtime instrumentation",
        severity="Medium",
        confidence="HIGH",
        standard="MASVS",
        category="MASVS-RESILIENCE",
    )
    confirmed = FindingValidationMission.objects.create(
        audit=audit,
        apk=apk,
        finding=finding,
        target_package=apk.package_name,
        playbook_id="ROOT_DETECTION_SCREEN_VALIDATION",
        status="CONFIRMED",
        final_conclusion="Confirmed root manipulation evidence.",
        scenario_contract={"steps": []},
    )
    newer_failed = FindingValidationMission.objects.create(
        audit=audit,
        apk=apk,
        finding=finding,
        target_package=apk.package_name,
        playbook_id="ROOT_DETECTION_SCREEN_VALIDATION",
        status="INCONCLUSIVE",
        final_conclusion="Required evidence did not complete: frida_run_js.",
        scenario_contract={"steps": []},
    )

    with patch(
        "apps.dynamic_analysis.services.correlation_agent._live_manifest",
        return_value=_connected_manifest("frida_setup", "frida_run_js", "take_screenshot", "dump_ui", "launch_package"),
    ):
        result = __import__(
            "apps.dynamic_analysis.services.correlation_agent",
            fromlist=["correlate_audit_findings"],
        ).correlate_audit_findings(audit.id)

    card = result["candidates"][0]
    assert card["classification"] == "ALREADY_VALIDATED"
    assert card["current_validation_status"] == "CONFIRMED"
    assert card["existing_mission_id"] == confirmed.id
    assert card["existing_mission_id"] != newer_failed.id


@pytest.mark.django_db
@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_latest_correlation_reuses_cache_when_nothing_changed(analyst_client, audit_with_apk):
    audit, _apk = audit_with_apk
    _component_finding(audit)
    _crypto_finding(audit)

    with patch(
        "apps.dynamic_analysis.services.correlation_agent._live_manifest",
        return_value=_connected_manifest("launch_exported_activity"),
    ):
        analyst_client.post(
            f"/api/dynamic/static-dynamic-correlation/{audit.id}/start/",
            {},
            format="json",
        )
        first = analyst_client.get(
            f"/api/dynamic/static-dynamic-correlation/{audit.id}/latest/",
        )
        second = analyst_client.get(
            f"/api/dynamic/static-dynamic-correlation/{audit.id}/latest/",
        )

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["generated_at"] == second.json()["generated_at"]
    assert StaticDynamicCorrelationRun.objects.filter(audit=audit).count() == 1


@pytest.mark.django_db
@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_correlation_never_spends_openai_budget(analyst_client, audit_with_apk):
    audit, _apk = audit_with_apk
    _component_finding(audit)
    before = budget_status(GLOBAL_SCOPE)["current_openai_call_count"]

    with patch(
        "apps.dynamic_analysis.services.correlation_agent._live_manifest",
        return_value=_connected_manifest("launch_exported_activity"),
    ):
        response = analyst_client.post(
            f"/api/dynamic/static-dynamic-correlation/{audit.id}/start/",
            {},
            format="json",
        )
    after = budget_status(GLOBAL_SCOPE)["current_openai_call_count"]
    assert response.status_code == 200
    assert after == before


@pytest.mark.django_db
@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_capability_gap_report_endpoint(analyst_client, audit_with_apk):
    audit, _apk = audit_with_apk
    _crypto_finding(audit)

    with patch(
        "apps.dynamic_analysis.services.correlation_agent._live_manifest",
        return_value=_connected_manifest("launch_exported_activity"),
    ):
        analyst_client.post(
            f"/api/dynamic/static-dynamic-correlation/{audit.id}/start/",
            {},
            format="json",
        )
        response = analyst_client.get(
            f"/api/dynamic/static-dynamic-correlation/{audit.id}/capability-gaps/",
        )

    assert response.status_code == 200
    data = response.json()
    assert data["audit_id"] == audit.id
    assert data["total_static_findings"] == 1
    assert data["testable_with_current_primitives"] == 0
    assert data["available_capabilities"] == ["launch_exported_activity"]
    assert any(
        gap["missing_capability"] == "network request capture"
        for gap in data["highest_value_missing_capabilities"]
    )


@pytest.mark.django_db
@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_start_poc_creates_mission_from_ai_plan(analyst_client, audit_with_apk):
    audit, _apk = audit_with_apk
    finding = _component_finding(audit)

    with patch(
        "apps.dynamic_analysis.services.correlation_agent._live_manifest",
        return_value=_connected_manifest(
            "launch_exported_activity", "get_device_status", "take_screenshot"
        ),
    ):
        response = analyst_client.post(
            f"/api/dynamic/static-dynamic-correlation/{audit.id}/start-poc/",
            {"finding_id": finding.id},
            format="json",
        )

    assert response.status_code == 201
    data = response.json()
    assert data["next_step"] == "review"
    mission = data["mission"]
    assert mission["finding"] == finding.id
    assert mission["status"] == "VALIDATED"
    assert not mission["playbook_id"]
    assert mission["result_label"] == "Ready for approval"
    assert mission["result_explanation"]
    assert mission["scenario_summary"]
    assert FindingValidationMission.objects.filter(finding=finding).count() == 1
    plan = DynamicPoCPlan.objects.filter(finding=finding).first()
    assert plan is not None
    assert plan.provider == "DETERMINISTIC"
    assert plan.plan_hash
    assessment = AssessmentPlan.objects.filter(source_finding=finding).first()
    assert assessment is not None
    assert assessment.status == AssessmentPlan.Status.VALIDATED
    assert assessment.validation_status == AssessmentPlan.ValidationStatus.PASSED
    assert assessment.steps.count() >= 1
    assert mission["assessment_plan"] == assessment.id


@pytest.mark.django_db
@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_start_poc_reuses_existing_validated_mission(analyst_client, audit_with_apk):
    audit, apk = audit_with_apk
    finding = _component_finding(audit)
    existing = _mission(audit, apk, finding, status="VALIDATED")

    with patch(
        "apps.dynamic_analysis.services.correlation_agent._live_manifest",
        return_value=_connected_manifest("launch_exported_activity"),
    ):
        response = analyst_client.post(
            f"/api/dynamic/static-dynamic-correlation/{audit.id}/start-poc/",
            {"finding_id": finding.id},
            format="json",
        )

    assert response.status_code == 201
    data = response.json()
    assert data["mission"]["id"] == existing.id
    assert data["next_step"] == "approve"
    assert FindingValidationMission.objects.filter(finding=finding).count() == 1


@pytest.mark.django_db
@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_start_poc_rejects_cross_audit_candidate(analyst_client, audit_with_apk, db):
    audit, _apk = audit_with_apk
    project = Project.objects.create(name="Other project")
    other_audit = Audit.objects.create(project=project, name="Other audit")
    other_finding = _crypto_finding(other_audit, rule_id="OTHER-001")

    response = analyst_client.post(
        f"/api/dynamic/static-dynamic-correlation/{audit.id}/start-poc/",
        {"finding_id": other_finding.id},
        format="json",
    )
    assert response.status_code == 404


@pytest.mark.django_db
@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_start_poc_rejects_not_testable_candidate(analyst_client, audit_with_apk):
    audit, _apk = audit_with_apk
    _crypto_finding(audit)

    with patch(
        "apps.dynamic_analysis.services.correlation_agent._live_manifest",
        return_value=_connected_manifest("launch_exported_activity"),
    ):
        response = analyst_client.post(
            f"/api/dynamic/static-dynamic-correlation/{audit.id}/start-poc/",
            {"finding_id": audit.findings.first().id},
            format="json",
        )

    assert response.status_code == 409
    assert response.json()["code"] == "POC_PLANNING_NOT_AVAILABLE"
    assert FindingValidationMission.objects.filter(audit=audit).count() == 0


@pytest.mark.django_db
@override_settings(MSAP_ASSESSMENT_PLANNER_PROVIDER="DETERMINISTIC")
def test_correlation_does_not_expose_secrets_or_internal_records(
    analyst_client,
    audit_with_apk,
):
    audit, _apk = audit_with_apk
    secret = "super-secret-api-key-42-abcdef"
    finding = _crypto_finding(
        audit,
        title="Hardcoded API secret",
        description=f"App contains the value {secret} in plain text.",
    )

    with patch(
        "apps.dynamic_analysis.services.correlation_agent._live_manifest",
        return_value=_connected_manifest("launch_exported_activity"),
    ):
        result = __import__(
            "apps.dynamic_analysis.services.correlation_agent",
            fromlist=["correlate_audit_findings"],
        ).correlate_audit_findings(audit.id)
    serialized = str(result)
    assert secret not in serialized
    assert "description" not in result["candidates"][0]
    assert "oracle_result" not in result["candidates"][0]
    assert "scenario_contract" not in result["candidates"][0]


def test_observation_summaries_map_common_tools():
    assert observation_summary_for_tool(
        "launch_package", {"launched": True}
    ) == "The target app was launched and is foregrounded."
    assert observation_summary_for_tool(
        "tap_coordinates", {"x": 540, "y": 1200}
    ) == "Approved UI interaction executed."
    assert observation_summary_for_tool(
        "take_screenshot", {}
    ) == "Screenshot captured."
    assert observation_summary_for_tool(
        "dump_ui", {"node_count": 42}
    ) == "UI hierarchy captured."
    assert observation_summary_for_tool(
        "frida_run_js", {"event_count": 2}
    ) == "Approved Frida runtime proof executed."
    assert observation_summary_for_tool(
        "get_logcat_excerpt", {"line_count": 30}
    ) == "Bounded logcat excerpt captured."
    assert observation_summary_for_tool("unknown_tool", {}) == "Tool observation captured."
    assert observation_summary_for_tool(
        "", {"event_count": 3}
    ) == "3 approved runtime events recorded."


def test_friendly_action_labels():
    assert friendly_action_label("launch_package") == "Launch target app"
    assert friendly_action_label("frida_run_js") == "Run controlled instrumentation proof"
    assert friendly_action_label("nope") == "nope"


def test_evidence_labels_and_preview_types():
    assert evidence_title("screenshot") == "Screenshot"
    assert evidence_title("logcat") == "Bounded log excerpt"
    assert evidence_title("frida_events") == "Approved Frida event"
    assert evidence_title("unknown_type") == "unknown_type"
    assert evidence_preview_type("screenshot") == "screenshot"
    assert evidence_preview_type("ui_hierarchy") == "ui"
    assert evidence_preview_type("logcat") == "logs"
    assert evidence_preview_type("frida_events") == "runtime"
    assert evidence_preview_type("tool_output") == "tool_output"


def test_result_labels_and_explanations():
    assert result_label("CONFIRMED") == "Confirmed"
    assert result_label("INCONCLUSIVE") == "Inconclusive"
    assert "deterministic oracle" in result_explanation("INCONCLUSIVE")
    assert "confirm the static finding" in result_explanation("CONFIRMED")
    assert result_label("NOT_DYNAMICALLY_TESTABLE") == "Not dynamically testable"


@pytest.mark.django_db
def test_mission_evidence_previews_are_labeled_and_bounded(
    analyst_client,
    audit_with_apk,
):
    audit, apk = audit_with_apk
    finding = _component_finding(audit)
    mission = _mission(audit, apk, finding, status="CONFIRMED")
    Evidence.objects.create(
        audit=audit,
        finding=finding,
        evidence_type="screenshot",
        source="screenshot",
        snippet="raw-png-bytes-are-not-inline",
        sha256="c" * 64,
    )
    Evidence.objects.create(
        audit=audit,
        finding=finding,
        evidence_type="logcat",
        source="logcat",
        snippet="line one\nline two",
        sha256="d" * 64,
    )
    mission.evidence.set(Evidence.objects.filter(audit=audit))

    response = analyst_client.get(
        f"/api/dynamic/finding-validations/{mission.id}/evidence/",
    )
    assert response.status_code == 200
    records = response.json()
    assert len(records) == 2
    by_type = {item["evidence_type"]: item for item in records}
    screenshot = by_type["screenshot"]
    assert screenshot["evidence_title"] == "Screenshot"
    assert screenshot["evidence_preview_type"] == "screenshot"
    logcat = by_type["logcat"]
    assert logcat["evidence_title"] == "Bounded log excerpt"
    assert logcat["evidence_preview_type"] == "logs"


@pytest.mark.django_db
def test_mission_serializer_carries_result_ui_fields(analyst_client, audit_with_apk):
    audit, apk = audit_with_apk
    finding = _component_finding(audit)
    mission = _mission(audit, apk, finding, status="INCONCLUSIVE")
    mission.final_conclusion = "The PoC executed and collected evidence."
    mission.save(update_fields=["final_conclusion"])

    response = analyst_client.get(
        f"/api/dynamic/finding-validations/{mission.id}/",
    )
    assert response.status_code == 200
    data = response.json()
    assert data["result_label"] == "Inconclusive"
    assert "deterministic oracle" in data["result_explanation"]
    assert "PoC" in data["scenario_summary"]
    assert data["evidence_count"] == 0
    assert data["final_conclusion"] == "The PoC executed and collected evidence."

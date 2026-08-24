"""Required-vs-optional evidence gating for deterministic validation results.

A failed core (required) tool step must never confirm a finding, while a
failed supplementary (optional) tool step produces a deterministic
``Confirmed with warning`` conclusion instead of invalidating the run.
"""

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
    DynamicValidationResult,
    FindingValidationMission,
)
from apps.dynamic_analysis.services.dynamic_validation import (
    apply_evidence_gate,
    record_dynamic_validation,
)
from apps.dynamic_analysis.services.finding_validation_missions import (
    refresh_mission_from_run,
)
from apps.evidence.models import Evidence
from apps.findings.models import Finding
from apps.projects.models import Project


def _make_context(django_user_model, rule_id="MSAP-AND-006"):
    call_command("bootstrap_roles", verbosity=0)
    user = django_user_model.objects.create_user("gate-owner")
    user.groups.add(Group.objects.get(name=ANALYST_GROUP))
    project = Project.objects.create(name="Evidence gate project")
    audit = Audit.objects.create(project=project, name="Evidence gate audit")
    apk = APKFile.objects.create(
        audit=audit,
        package_name="owasp.sat.agoat",
        sha256="a" * 64,
        size_bytes=1234,
    )
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
    runtime.save(update_fields=["status", "enabled", "updated_at"])
    finding = Finding.objects.create(
        audit=audit,
        rule_id=rule_id,
        title="Exported receiver",
        severity="High",
        confidence="HIGH",
        standard="MASVS",
        category="MASVS-CODE",
    )
    return user, audit, apk, finding


def _run_with_steps(user, audit, apk, *, run_status, steps):
    run = AgentRun.objects.create(
        audit=audit,
        runtime=AgentRuntime.objects.first(),
        target_package=apk.package_name,
        objective=AgentRun.Objective.ASSESSMENT_PLAN_EXECUTION,
        requested_by=user,
        status=run_status,
    )
    for index, (tool_name, status, output) in enumerate(steps, start=1):
        AgentRunStep.objects.create(
            run=run,
            sequence_number=index,
            tool_name=tool_name,
            status=status,
            output_summary=output,
            failure_message="boom" if status != AgentRunStep.Status.SUCCEEDED else "",
        )
    return run


@pytest.mark.django_db
def test_required_evidence_failure_downgrades_confirmed_to_inconclusive(django_user_model):
    _user, audit, apk, finding = _make_context(django_user_model)
    run = _run_with_steps(
        _user,
        audit,
        apk,
        run_status=AgentRun.Status.FAILED,
        steps=[("send_explicit_broadcast", AgentRunStep.Status.FAILED, {"error": "boom"})],
    )
    result = record_dynamic_validation(
        finding=finding,
        audit=audit,
        playbook_id="EXPORTED_RECEIVER_BROADCAST_VERIFICATION",
        evidence={"delivered": True},
        agent_run=run,
        rule_id=finding.rule_id,
    )
    oracle = result.oracle_result
    assert result.validation_status == DynamicValidationResult.ValidationStatus.INCONCLUSIVE
    assert oracle["status"] == "INCONCLUSIVE"
    assert oracle["evidence_gate"]["required_evidence_failed"] == ["send_explicit_broadcast"]
    assert "cannot be confirmed" in oracle["summary"]


@pytest.mark.django_db
def test_required_tool_absent_downgrades_confirmed_to_inconclusive(django_user_model):
    _user, audit, apk, finding = _make_context(django_user_model)
    run = _run_with_steps(
        _user,
        audit,
        apk,
        run_status=AgentRun.Status.SUCCEEDED,
        steps=[("get_logcat_excerpt", AgentRunStep.Status.SUCCEEDED, {"delivered": True})],
    )
    result = record_dynamic_validation(
        finding=finding,
        audit=audit,
        playbook_id="EXPORTED_RECEIVER_BROADCAST_VERIFICATION",
        evidence={"delivered": True},
        agent_run=run,
        rule_id=finding.rule_id,
    )
    assert result.validation_status == DynamicValidationResult.ValidationStatus.INCONCLUSIVE
    assert result.oracle_result["status"] == "INCONCLUSIVE"


@pytest.mark.django_db
def test_failed_required_frida_evidence_does_not_confirm(django_user_model):
    _user, audit, apk, finding = _make_context(django_user_model, rule_id="MSAP-ROOT-001")
    run = _run_with_steps(
        _user,
        audit,
        apk,
        run_status=AgentRun.Status.FAILED,
        steps=[
            ("take_screenshot", AgentRunStep.Status.SUCCEEDED, {"screenshot_sha256": "1" * 64}),
            ("frida_run_js", AgentRunStep.Status.FAILED, {"error": "frida unavailable"}),
            ("dump_ui", AgentRunStep.Status.SUCCEEDED, {"text_values": ["Device is rooted"]}),
        ],
    )
    result = record_dynamic_validation(
        finding=finding,
        audit=audit,
        playbook_id="ROOT_DETECTION_SCREEN_VALIDATION",
        evidence={
            "events": [{"type": "root_detection_native_hooks_installed"}],
            "before_screenshot_sha256": "1" * 64,
            "after_screenshot_sha256": "2" * 64,
            "text_values": ["Device is rooted"],
        },
        agent_run=run,
        rule_id=finding.rule_id,
    )

    assert result.validation_status == DynamicValidationResult.ValidationStatus.INCONCLUSIVE
    assert result.oracle_result["status"] == "INCONCLUSIVE"
    assert result.oracle_result["evidence_gate"]["required_evidence_failed"] == [
        "frida_run_js"
    ]


@pytest.mark.django_db
def test_tls_pinning_gate_accepts_stop_proxy_capture_summary_without_get_proxy_flows(
    django_user_model,
):
    _user, audit, apk, finding = _make_context(django_user_model, rule_id="MSAP-AND-016")
    run = _run_with_steps(
        _user,
        audit,
        apk,
        run_status=AgentRun.Status.SUCCEEDED,
        steps=[
            ("start_proxy_capture", AgentRunStep.Status.SUCCEEDED, {"capture_id": "a" * 32}),
            ("stop_proxy_capture", AgentRunStep.Status.SUCCEEDED, {"successful_tls_flow_count": 1}),
            ("frida_run_js", AgentRunStep.Status.SUCCEEDED, {"events": [{"type": "tls_pinned_request_triggered", "success": True}]}),
            ("take_screenshot", AgentRunStep.Status.SUCCEEDED, {"screenshot_sha256": "1" * 64}),
        ],
    )

    result = apply_evidence_gate(
        "TLS_PINNING_FRIDA_BYPASS",
        run,
        {
            "status": "CONFIRMED",
            "oracle_id": "tls_pinning_bypass_oracle",
            "summary": "The unmodified pinned request produced no successful decrypted proxy flow; after approved Frida instrumentation, the same AndroGoat workflow produced a successful TLS flow through the controlled proxy.",
        },
    )

    assert result["status"] == "CONFIRMED"
    assert "evidence_gate" not in result


@pytest.mark.django_db
def test_tls_pinning_oracle_accepts_single_terminal_screenshot_shape(
    django_user_model,
):
    _user, audit, apk, finding = _make_context(django_user_model, rule_id="MSAP-AND-016")
    run = _run_with_steps(
        _user,
        audit,
        apk,
        run_status=AgentRun.Status.SUCCEEDED,
        steps=[
            ("start_proxy_capture", AgentRunStep.Status.SUCCEEDED, {"capture_id": "a" * 32}),
            ("stop_proxy_capture", AgentRunStep.Status.SUCCEEDED, {"phase": "pinning_baseline", "successful_tls_flow_count": 0}),
            ("start_proxy_capture", AgentRunStep.Status.SUCCEEDED, {"capture_id": "b" * 32}),
            ("frida_run_js", AgentRunStep.Status.SUCCEEDED, {"events": [
                {"type": "tls_pinning_bypass_hooks_installed", "success": True},
                {"type": "tls_pinned_request_triggered", "success": True},
            ]}),
            ("stop_proxy_capture", AgentRunStep.Status.SUCCEEDED, {"phase": "pinning_bypass", "successful_tls_flow_count": 1}),
            ("take_screenshot", AgentRunStep.Status.SUCCEEDED, {"sha256": "1" * 64, "object_reference_id": 1}),
        ],
    )
    evidence_record = Evidence.objects.create(
        audit=audit,
        finding=finding,
        agent_run=run,
        evidence_type="network_flow",
        source="test",
        snippet="bounded flow summary",
        redacted=True,
        sha256="c" * 64,
    )
    result = record_dynamic_validation(
        finding=finding,
        audit=audit,
        playbook_id="TLS_PINNING_FRIDA_BYPASS",
        evidence={
            "events": [
                {"type": "tls_pinning_bypass_hooks_installed", "success": True},
                {"type": "tls_pinned_request_triggered", "success": True},
            ],
            "tls_baseline_successful_flow_count": 0,
            "tls_bypass_successful_flow_count": 1,
            "sha256": "1" * 64,
            "object_reference_id": 1,
        },
        agent_run=run,
        evidence_records=[evidence_record],
        rule_id=finding.rule_id,
        confidence=0.9,
    )

    assert result.validation_status == DynamicValidationResult.ValidationStatus.SUPPORTED
    assert result.oracle_result["status"] == "CONFIRMED"


@pytest.mark.django_db
def test_optional_failure_confirms_with_warning(django_user_model):
    _user, audit, apk, finding = _make_context(django_user_model)
    run = _run_with_steps(
        _user,
        audit,
        apk,
        run_status=AgentRun.Status.SUCCEEDED,
        steps=[
            ("send_explicit_broadcast", AgentRunStep.Status.SUCCEEDED, {"delivered": True}),
            ("get_logcat_excerpt", AgentRunStep.Status.FAILED, {"error": "boom"}),
        ],
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
    result = record_dynamic_validation(
        finding=finding,
        audit=audit,
        playbook_id="EXPORTED_RECEIVER_BROADCAST_VERIFICATION",
        evidence={"delivered": True},
        agent_run=run,
        evidence_records=[evidence],
        rule_id=finding.rule_id,
    )
    oracle = result.oracle_result
    assert result.validation_status == DynamicValidationResult.ValidationStatus.SUPPORTED
    assert oracle["status"] == "CONFIRMED"
    assert oracle["verdict"] == "CONFIRMED_WITH_WARNING"
    assert oracle["warnings"] == ["log excerpt collection failed (get_logcat_excerpt)"]
    assert "Confirmed with warning: log excerpt collection failed" in oracle["summary"]


@pytest.mark.django_db
def test_all_required_succeeded_has_no_warnings(django_user_model):
    _user, audit, apk, finding = _make_context(django_user_model)
    run = _run_with_steps(
        _user,
        audit,
        apk,
        run_status=AgentRun.Status.SUCCEEDED,
        steps=[("send_explicit_broadcast", AgentRunStep.Status.SUCCEEDED, {"delivered": True})],
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
    result = record_dynamic_validation(
        finding=finding,
        audit=audit,
        playbook_id="EXPORTED_RECEIVER_BROADCAST_VERIFICATION",
        evidence={"delivered": True},
        agent_run=run,
        evidence_records=[evidence],
        rule_id=finding.rule_id,
    )
    assert result.validation_status == DynamicValidationResult.ValidationStatus.SUPPORTED
    assert "verdict" not in result.oracle_result
    assert "warnings" not in result.oracle_result


@pytest.mark.django_db
def test_mission_conclusion_contains_confirmed_with_warning(django_user_model):
    user, audit, apk, finding = _make_context(django_user_model)
    run = _run_with_steps(
        user,
        audit,
        apk,
        run_status=AgentRun.Status.SUCCEEDED,
        steps=[
            ("send_explicit_broadcast", AgentRunStep.Status.SUCCEEDED, {"delivered": True}),
            ("get_logcat_excerpt", AgentRunStep.Status.FAILED, {"error": "boom"}),
        ],
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
    record_dynamic_validation(
        finding=finding,
        audit=audit,
        playbook_id="EXPORTED_RECEIVER_BROADCAST_VERIFICATION",
        evidence={"delivered": True},
        agent_run=run,
        evidence_records=[evidence],
        rule_id=finding.rule_id,
        confidence=0.9,
    )

    refreshed = refresh_mission_from_run(run)

    assert refreshed.id == mission.id
    assert refreshed.status == FindingValidationMission.Status.CONFIRMED
    assert refreshed.final_conclusion.startswith(
        "Confirmed with warning: log excerpt collection failed (get_logcat_excerpt)."
    )


@pytest.mark.django_db
def test_mission_is_inconclusive_when_required_evidence_failed(django_user_model):
    user, audit, apk, finding = _make_context(django_user_model)
    run = _run_with_steps(
        user,
        audit,
        apk,
        run_status=AgentRun.Status.FAILED,
        steps=[("send_explicit_broadcast", AgentRunStep.Status.FAILED, {"error": "boom"})],
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
    record_dynamic_validation(
        finding=finding,
        audit=audit,
        playbook_id="EXPORTED_RECEIVER_BROADCAST_VERIFICATION",
        evidence={"delivered": True},
        agent_run=run,
        rule_id=finding.rule_id,
        confidence=0.9,
    )

    refreshed = refresh_mission_from_run(run)

    assert refreshed.status == FindingValidationMission.Status.INCONCLUSIVE
    assert "cannot be confirmed" in refreshed.final_conclusion


@pytest.mark.django_db
def test_gate_is_pure_and_does_not_mutate_input(django_user_model):
    _user, audit, apk, finding = _make_context(django_user_model)
    run = _run_with_steps(
        _user,
        audit,
        apk,
        run_status=AgentRun.Status.SUCCEEDED,
        steps=[("send_explicit_broadcast", AgentRunStep.Status.SUCCEEDED, {"delivered": True})],
    )
    original = {
        "status": "CONFIRMED",
        "oracle_id": "exported_receiver_oracle",
        "summary": "Receiver delivery or target-correlated behavior was observed.",
    }
    result = apply_evidence_gate(
        "EXPORTED_RECEIVER_BROADCAST_VERIFICATION",
        run,
        original,
    )
    assert original == {
        "status": "CONFIRMED",
        "oracle_id": "exported_receiver_oracle",
        "summary": "Receiver delivery or target-correlated behavior was observed.",
    }
    assert result["status"] == "CONFIRMED"

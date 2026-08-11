from contextlib import nullcontext
from datetime import timedelta
from hashlib import sha256 as file_sha256
import inspect
from io import BytesIO, StringIO
import sys
from unittest.mock import Mock, patch
from urllib import error as urllib_error

import pytest
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db import IntegrityError, transaction
from django.test import override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.api.roles import ANALYST_GROUP, VIEWER_GROUP
from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.dynamic_analysis.models import (
    AgentRun,
    AgentRunArtifact,
    AgentRuntime,
    AgentRunStep,
    DynamicAnalysisJob,
    DynamicDevice,
    DynamicDeviceCapability,
    DynamicDeviceEvent,
    DynamicDeviceLease,
    DynamicDevicePool,
    DynamicEmulatorSnapshot,
    DynamicSession,
    DynamicSessionArtifact,
    DynamicSessionEvent,
    DynamicSessionStage,
)
from apps.dynamic_analysis.services.leases import (
    DynamicLeaseError,
    create_lease,
    heartbeat_lease,
    quarantine_device,
    release_lease,
)
from apps.dynamic_analysis.services.agent_controller import AgentController
from apps.dynamic_analysis.services.agent_tools import (
    AgentToolError,
    TOOL_MANIFEST,
    execute_agent_tool,
    public_tool_manifest,
)
from apps.dynamic_analysis.services.host_agent_client import (
    DynamicHostAgentClient,
    HostAgentClientError,
)
from apps.dynamic_analysis.services.host_agent import (
    DynamicHostAgent,
    HostAgentRequestError,
    _run_process,
)
from apps.dynamic_analysis.services.job_control import recover_stale_dynamic_jobs
from apps.dynamic_analysis.services.local_scripts import (
    DynamicScriptExecutionError,
    DynamicScriptResult,
    get_dynamic_stage_timeout,
    run_dynamic_lab_script,
)
from apps.dynamic_analysis.services import local_scripts
from apps.dynamic_analysis.services.mvp_runner import (
    DynamicMvpRunnerError,
    create_dynamic_mvp_job,
    run_dynamic_mvp_job,
)
from apps.dynamic_analysis.services.state_machine import (
    DynamicStateTransitionError,
    mark_session_cancelled,
    mark_session_failed,
    transition_session,
)
from apps.projects.models import Project
from apps.storage.models import ObjectStorageReference
from apps.dynamic_analysis.services.runner_readiness import get_dynamic_runner_readiness


PASSWORD = "Correct-Horse-Battery-Staple-42!"


@pytest.fixture
def api_client(django_user_model):
    user = django_user_model.objects.create_superuser(
        username="dynamic-admin",
        email="dynamic-admin@example.test",
        password=PASSWORD,
    )
    client = APIClient()
    client.force_authenticate(user=user)
    return client


@pytest.fixture
def analyst_client(django_user_model):
    call_command("bootstrap_roles", verbosity=0)
    user = django_user_model.objects.create_user(
        username="dynamic-analyst",
        email="dynamic-analyst@example.test",
        password=PASSWORD,
    )
    user.groups.add(Group.objects.get(name=ANALYST_GROUP))
    client = APIClient()
    client.force_authenticate(user=user)
    return client


@pytest.fixture
def viewer_client(django_user_model):
    call_command("bootstrap_roles", verbosity=0)
    user = django_user_model.objects.create_user(
        username="dynamic-viewer",
        email="dynamic-viewer@example.test",
        password=PASSWORD,
    )
    user.groups.add(Group.objects.get(name=VIEWER_GROUP))
    client = APIClient()
    client.force_authenticate(user=user)
    return client


@pytest.mark.django_db
def test_agent_runtime_model_defaults_are_restricted():
    runtime = AgentRuntime.objects.create(name="Restricted runtime defaults")

    assert runtime.runtime_type == AgentRuntime.RuntimeType.INTERNAL_CONTROLLER
    assert runtime.status == AgentRuntime.Status.AVAILABLE
    assert runtime.isolation_level == AgentRuntime.IsolationLevel.INTERNAL_ONLY
    assert runtime.enabled is True
    assert runtime.capabilities == {
        "objectives": ["DEVICE_READINESS_CHECK"],
        "tools": ["get_device_status", "take_screenshot"],
    }


@pytest.mark.django_db
def test_agent_run_model_lifecycle_calculates_duration(django_user_model):
    user = django_user_model.objects.create_user(username="agent-lifecycle")
    started_at = timezone.now()
    run = AgentRun.objects.create(
        objective=AgentRun.Objective.DEVICE_READINESS_CHECK,
        requested_by=user,
        status=AgentRun.Status.QUEUED,
    )

    run.status = AgentRun.Status.RUNNING
    run.started_at = started_at
    run.save()
    run.status = AgentRun.Status.SUCCEEDED
    run.finished_at = started_at + timedelta(seconds=2.25)
    run.save()

    run.refresh_from_db()
    assert run.status == AgentRun.Status.SUCCEEDED
    assert run.duration_seconds == 2.25


@pytest.mark.django_db
def test_agent_run_step_sequence_is_unique(django_user_model):
    user = django_user_model.objects.create_user(username="agent-step-unique")
    run = AgentRun.objects.create(
        objective=AgentRun.Objective.DEVICE_READINESS_CHECK,
        requested_by=user,
    )
    AgentRunStep.objects.create(
        run=run,
        sequence_number=1,
        tool_name="get_device_status",
    )

    with pytest.raises(IntegrityError):
        with transaction.atomic():
            AgentRunStep.objects.create(
                run=run,
                sequence_number=1,
                tool_name="take_screenshot",
            )


def test_agent_tool_manifest_only_exposes_allowlisted_tools():
    assert set(TOOL_MANIFEST) == {"get_device_status", "take_screenshot"}
    assert set(public_tool_manifest()) == {
        "get_device_status",
        "take_screenshot",
    }
    assert TOOL_MANIFEST["get_device_status"].input_schema[
        "additionalProperties"
    ] is False
    assert TOOL_MANIFEST["take_screenshot"].timeout_seconds == 15


def test_agent_tool_gateway_rejects_unknown_tool():
    with pytest.raises(AgentToolError) as exc_info:
        execute_agent_tool("run_shell", {"command": "id"})

    assert exc_info.value.code == "UNKNOWN_TOOL"
    assert "allowlisted" in str(exc_info.value)


@pytest.mark.django_db
def test_get_device_status_tool_normalizes_mocked_success():
    client = Mock()
    client.get_status.return_value = _agent_status_payload(serial="agent-tool-status")

    output = execute_agent_tool("get_device_status", {}, client=client)

    assert output == {
        "host_agent_status": "REACHABLE",
        "emulator_status": "REACHABLE",
        "serial": "agent-tool-status",
        "android_version": "15",
        "api_level": 35,
        "abi": "x86_64",
        "root_uid": 0,
        "selinux": "Enforcing",
        "proxy": ":0",
        "focused_app": "com.android.settings",
        "ready": True,
    }
    assert DynamicDevice.objects.filter(serial="agent-tool-status").exists()


def test_take_screenshot_tool_normalizes_mocked_success():
    client = Mock()
    client.request_screenshot.return_value = _agent_png(width=1080, height=1920)

    output = execute_agent_tool(
        "take_screenshot",
        {"capture_reason": "device_readiness"},
        client=client,
    )

    assert output["content_type"] == "image/png"
    assert output["width"] == 1080
    assert output["height"] == 1920
    assert output["size_bytes"] == 24
    assert len(output["sha256"]) == 64
    assert output["captured_at"]


@pytest.mark.django_db
def test_agent_controller_marks_host_agent_unavailable(django_user_model):
    user = _make_role_user(django_user_model, "agent-host-offline", ANALYST_GROUP)
    _ensure_agent_runtime()
    tool_executor = Mock(
        side_effect=AgentToolError(
            "The dynamic host agent is unavailable.",
            code="HOST_AGENT_UNREACHABLE",
            failure_category=AgentRun.FailureCategory.HOST_AGENT_UNAVAILABLE,
        )
    )

    run = AgentController(tool_executor=tool_executor).run(
        objective=AgentRun.Objective.DEVICE_READINESS_CHECK,
        requested_by=user,
    )

    assert run.status == AgentRun.Status.FAILED
    assert run.failure_category == AgentRun.FailureCategory.HOST_AGENT_UNAVAILABLE
    assert list(run.steps.values_list("status", flat=True)) == [
        AgentRunStep.Status.FAILED,
        AgentRunStep.Status.SKIPPED,
    ]


@pytest.mark.django_db
def test_agent_api_requires_authentication():
    assert APIClient().get("/api/dynamic/agent/runs/").status_code in {401, 403}
    assert APIClient().get("/api/dynamic/agent/runtimes/").status_code in {401, 403}


@pytest.mark.django_db
def test_agent_viewer_can_read_but_cannot_create(viewer_client, django_user_model):
    user = django_user_model.objects.create_user(username="existing-agent-requester")
    AgentRun.objects.create(
        objective=AgentRun.Objective.DEVICE_READINESS_CHECK,
        requested_by=user,
    )

    assert viewer_client.get("/api/dynamic/agent/runs/").status_code == 200
    assert viewer_client.get("/api/dynamic/agent/runtimes/").status_code == 200
    response = viewer_client.post(
        "/api/dynamic/agent/runs/",
        {"objective": "DEVICE_READINESS_CHECK"},
        format="json",
    )
    assert response.status_code == 403


@pytest.mark.django_db
@pytest.mark.parametrize("client_fixture", ["analyst_client", "api_client"])
def test_analyst_and_admin_can_create_device_readiness_run(
    request,
    client_fixture,
):
    client = request.getfixturevalue(client_fixture)
    _ensure_agent_runtime()
    with patch(
        "apps.dynamic_analysis.services.agent_tools.DynamicHostAgentClient.get_status",
        return_value=_agent_status_payload(serial=f"agent-api-{client_fixture}"),
    ), patch(
        "apps.dynamic_analysis.services.agent_tools.DynamicHostAgentClient.request_screenshot",
        return_value=_agent_png(),
    ):
        response = client.post(
            "/api/dynamic/agent/runs/",
            {"objective": "DEVICE_READINESS_CHECK"},
            format="json",
        )

    assert response.status_code == 201
    assert response.json()["status"] == AgentRun.Status.SUCCEEDED
    run = AgentRun.objects.get(pk=response.json()["id"])
    assert list(run.steps.values_list("tool_name", flat=True)) == [
        "get_device_status",
        "take_screenshot",
    ]
    assert run.steps.filter(status=AgentRunStep.Status.SUCCEEDED).count() == 2
    screenshot_artifact = run.artifacts.get(
        artifact_type=AgentRunArtifact.ArtifactType.SCREENSHOT
    )
    assert screenshot_artifact.object_reference is None
    assert "sha256" in screenshot_artifact.metadata


@pytest.mark.django_db
def test_agent_api_rejects_unknown_objective_and_caller_selected_tools(
    analyst_client,
):
    unknown_response = analyst_client.post(
        "/api/dynamic/agent/runs/",
        {"objective": "AUTONOMOUS_PENTEST"},
        format="json",
    )
    tools_response = analyst_client.post(
        "/api/dynamic/agent/runs/",
        {
            "objective": "DEVICE_READINESS_CHECK",
            "tools": ["run_shell"],
        },
        format="json",
    )

    assert unknown_response.status_code == 400
    assert tools_response.status_code == 400
    assert AgentRun.objects.count() == 0


@override_settings(MSAP_DYNAMIC_HOST_AGENT_TOKEN="never-leak-agent-token")
@pytest.mark.django_db
def test_agent_failure_run_does_not_leak_host_agent_token(analyst_client):
    _ensure_agent_runtime()
    with patch(
        "apps.dynamic_analysis.services.agent_tools.DynamicHostAgentClient.get_status",
        return_value={
            "connected": False,
            "enabled": True,
            "code": "HOST_AGENT_UNREACHABLE",
            "detail": "token=never-leak-agent-token",
        },
    ):
        response = analyst_client.post(
            "/api/dynamic/agent/runs/",
            {"objective": "DEVICE_READINESS_CHECK"},
            format="json",
        )

    assert response.status_code == 201
    assert response.json()["status"] == AgentRun.Status.FAILED
    assert response.json()["failure_category"] == "HOST_AGENT_UNAVAILABLE"
    steps_response = analyst_client.get(
        f"/api/dynamic/agent/runs/{response.json()['id']}/steps/"
    )
    assert "never-leak-agent-token" not in str(response.json())
    assert "never-leak-agent-token" not in str(steps_response.json())


@pytest.mark.django_db
def test_dynamic_device_serial_is_unique():
    device = _make_device()

    with pytest.raises(IntegrityError):
        with transaction.atomic():
            DynamicDevice.objects.create(
                pool=device.pool,
                name="Duplicate serial",
                serial=device.serial,
                kind=DynamicDevice.Kind.EMULATOR,
                host_type=DynamicDevice.HostType.LINUX,
                host_identifier="host-duplicate",
                status=DynamicDevice.Status.AVAILABLE,
                api_level=35,
                abi="x86_64",
            )


@pytest.mark.django_db
def test_dynamic_device_pool_slug_is_unique():
    DynamicDevicePool.objects.create(name="Pool one", slug="local-pool")

    with pytest.raises(IntegrityError):
        with transaction.atomic():
            DynamicDevicePool.objects.create(name="Pool two", slug="local-pool")


@pytest.mark.django_db
def test_dynamic_snapshot_is_unique_per_device_and_name():
    device = _make_device()
    DynamicEmulatorSnapshot.objects.create(
        device=device,
        name="msap-clean-base",
        snapshot_type=DynamicEmulatorSnapshot.SnapshotType.CLEAN_BASE,
        api_level=35,
        abi="x86_64",
    )

    with pytest.raises(IntegrityError):
        with transaction.atomic():
            DynamicEmulatorSnapshot.objects.create(
                device=device,
                name="msap-clean-base",
                snapshot_type=DynamicEmulatorSnapshot.SnapshotType.CLEAN_BASE,
                api_level=35,
                abi="x86_64",
            )


@pytest.mark.django_db
def test_dynamic_active_lease_conflict_is_prevented_by_database():
    audit, _apk = _make_audit_with_apk()
    device = _make_device()
    expires_at = timezone.now() + timedelta(minutes=30)
    DynamicDeviceLease.objects.create(
        device=device,
        audit=audit,
        lease_status=DynamicDeviceLease.LeaseStatus.ACTIVE,
        lease_token="lease-token-one",
        expires_at=expires_at,
    )

    with pytest.raises(IntegrityError):
        with transaction.atomic():
            DynamicDeviceLease.objects.create(
                device=device,
                audit=audit,
                lease_status=DynamicDeviceLease.LeaseStatus.ACTIVE,
                lease_token="lease-token-two",
                expires_at=expires_at,
            )


@pytest.mark.django_db
def test_dynamic_completed_session_requires_cleanup_success():
    session = _make_session()
    session.state = DynamicSession.State.COMPLETED
    session.cleanup_status = DynamicSession.CleanupStatus.NOT_STARTED

    with pytest.raises(ValidationError):
        session.full_clean()


@pytest.mark.django_db
def test_dynamic_baseline_snapshot_cannot_contain_target_apk():
    device = _make_device()
    snapshot = DynamicEmulatorSnapshot(
        device=device,
        name="unsafe-clean-base",
        snapshot_type=DynamicEmulatorSnapshot.SnapshotType.CLEAN_BASE,
        api_level=35,
        abi="x86_64",
        contains_target_apk=True,
    )

    with pytest.raises(ValidationError):
        snapshot.full_clean()


@pytest.mark.django_db
def test_dynamic_available_device_can_be_leased():
    audit, _apk = _make_audit_with_apk()
    device = _make_device()

    lease = create_lease(device=device, audit=audit, ttl_minutes=30)

    assert lease.lease_status == DynamicDeviceLease.LeaseStatus.ACTIVE
    assert lease.lease_token
    device.refresh_from_db()
    assert device.status == DynamicDevice.Status.LEASED
    assert DynamicDeviceEvent.objects.filter(
        device=device,
        lease=lease,
        event_type=DynamicDeviceEvent.EventType.LEASE_CREATED,
    ).exists()


@pytest.mark.django_db
def test_dynamic_leased_device_cannot_be_leased_again():
    audit, _apk = _make_audit_with_apk()
    device = _make_device()
    create_lease(device=device, audit=audit, ttl_minutes=30)

    with pytest.raises(DynamicLeaseError):
        create_lease(device=device, audit=audit, ttl_minutes=30)


@pytest.mark.django_db
def test_dynamic_release_returns_device_to_available():
    audit, _apk = _make_audit_with_apk()
    device = _make_device()
    lease = create_lease(device=device, audit=audit, ttl_minutes=30)

    release_lease(lease, reason="COMPLETED")

    lease.refresh_from_db()
    device.refresh_from_db()
    assert lease.lease_status == DynamicDeviceLease.LeaseStatus.RELEASED
    assert lease.released_at is not None
    assert device.status == DynamicDevice.Status.AVAILABLE


@pytest.mark.django_db
def test_dynamic_quarantine_prevents_leasing():
    audit, _apk = _make_audit_with_apk()
    device = _make_device()
    quarantine_device(device, reason="Cleanup integrity uncertain.")

    with pytest.raises(DynamicLeaseError):
        create_lease(device=device, audit=audit, ttl_minutes=30)


@pytest.mark.django_db
def test_dynamic_lease_heartbeat_updates_timestamp():
    audit, _apk = _make_audit_with_apk()
    device = _make_device()
    lease = create_lease(device=device, audit=audit, ttl_minutes=30)
    original_heartbeat = lease.heartbeat_at

    updated = heartbeat_lease(lease)

    assert updated.heartbeat_at >= original_heartbeat


@pytest.mark.django_db
def test_dynamic_valid_state_transition_records_event():
    session = _make_session()

    transition_session(
        session,
        DynamicSession.State.WAITING_FOR_DEVICE,
        reason="Scheduler started matching.",
    )

    session.refresh_from_db()
    assert session.state == DynamicSession.State.WAITING_FOR_DEVICE
    assert DynamicSessionEvent.objects.filter(
        session=session,
        sequence_number=1,
        event_type=DynamicSessionEvent.EventType.STATE_TRANSITION,
    ).exists()


@pytest.mark.django_db
def test_dynamic_invalid_state_transition_fails_and_records_event():
    session = _make_session()

    with pytest.raises(DynamicStateTransitionError):
        transition_session(session, DynamicSession.State.INSTALLING_APK)

    session.refresh_from_db()
    assert session.state == DynamicSession.State.QUEUED
    assert DynamicSessionEvent.objects.filter(
        session=session,
        event_type=DynamicSessionEvent.EventType.INVALID_TRANSITION,
    ).exists()


@pytest.mark.django_db
def test_dynamic_completed_transition_requires_cleanup_succeeded():
    session = _make_session(state=DynamicSession.State.CLEANING_UP)

    with pytest.raises(DynamicStateTransitionError):
        transition_session(session, DynamicSession.State.COMPLETED)

    session.cleanup_status = DynamicSession.CleanupStatus.SUCCEEDED
    session.save(update_fields=["cleanup_status", "updated_at"])
    transition_session(session, DynamicSession.State.COMPLETED)
    session.refresh_from_db()
    assert session.state == DynamicSession.State.COMPLETED


@pytest.mark.django_db
def test_dynamic_failed_session_records_failure_category_and_message():
    session = _make_session(
        state=DynamicSession.State.CLEANING_UP,
        cleanup_status=DynamicSession.CleanupStatus.SUCCEEDED,
    )

    mark_session_failed(
        session,
        category=DynamicAnalysisJob.FailureCategory.TIMEOUT,
        message="Session timed out after cleanup.",
    )

    session.refresh_from_db()
    session.job.refresh_from_db()
    assert session.state == DynamicSession.State.FAILED
    assert session.summary["failure"]["category"] == (
        DynamicAnalysisJob.FailureCategory.TIMEOUT
    )
    assert session.job.status == DynamicAnalysisJob.Status.FAILED
    assert session.job.failure_message == "Session timed out after cleanup."


@pytest.mark.django_db
def test_dynamic_cancelled_session_does_not_skip_cleanup_tracking():
    session = _make_session(
        state=DynamicSession.State.CLEANING_UP,
        cleanup_status=DynamicSession.CleanupStatus.NOT_STARTED,
    )

    with pytest.raises(DynamicStateTransitionError):
        mark_session_cancelled(session, reason="Operator cancelled.")

    session.refresh_from_db()
    session.job.refresh_from_db()
    assert session.state == DynamicSession.State.CLEANING_UP
    assert session.cleanup_status == DynamicSession.CleanupStatus.NOT_STARTED
    assert session.job.status == DynamicAnalysisJob.Status.QUEUED


@pytest.mark.django_db
def test_dynamic_api_lists_and_creates_device_pool(api_client):
    create_response = api_client.post(
        "/api/dynamic/device-pools/",
        {
            "name": "Local dynamic lab",
            "slug": "local-dynamic-lab",
            "description": "Single emulator pool",
            "max_concurrent_leases": 1,
        },
        format="json",
    )

    assert create_response.status_code == 201
    list_response = api_client.get("/api/dynamic/device-pools/")
    assert list_response.status_code == 200
    assert list_response.json()[0]["slug"] == "local-dynamic-lab"


@pytest.mark.django_db
def test_dynamic_api_creates_device(api_client):
    pool = DynamicDevicePool.objects.create(name="Pool", slug="api-pool")

    response = api_client.post(
        "/api/dynamic/devices/",
        {
            "pool": pool.id,
            "name": "API emulator",
            "serial": "emulator-api",
            "kind": DynamicDevice.Kind.EMULATOR,
            "host_type": DynamicDevice.HostType.LINUX,
            "host_identifier": "api-host",
            "status": DynamicDevice.Status.AVAILABLE,
            "api_level": 35,
            "android_version": "15",
            "abi": "x86_64",
            "is_rooted": True,
            "selinux_mode": "Enforcing",
        },
        format="json",
    )

    assert response.status_code == 201
    assert response.json()["serial"] == "emulator-api"


@override_settings(MSAP_DYNAMIC_RUNNER_ENABLED=True)
@pytest.mark.django_db
def test_dynamic_api_creates_job(api_client):
    audit, apk = _make_audit_with_apk()

    with patch(
        "apps.dynamic_analysis.views.get_dynamic_runner_readiness",
        return_value={"ready": True},
    ):
        response = api_client.post(
            "/api/dynamic/jobs/",
            {
                "audit": audit.id,
                "apk": apk.id,
                "mode": DynamicAnalysisJob.Mode.COMBINED,
                "requested_tool_profile": DynamicAnalysisJob.ToolProfile.ADB_ONLY,
                "requested_interaction_mode": DynamicAnalysisJob.InteractionMode.PASSIVE,
            },
            format="json",
        )

    assert response.status_code == 201
    assert response.json()["audit"] == audit.id
    assert response.json()["apk"] == apk.id
    assert response.json()["status"] == DynamicAnalysisJob.Status.QUEUED


@pytest.mark.django_db
def test_dynamic_api_creates_and_releases_lease(api_client):
    audit, _apk = _make_audit_with_apk()
    device = _make_device()

    create_response = api_client.post(
        "/api/dynamic/device-leases/",
        {
            "device": device.id,
            "audit": audit.id,
            "ttl_minutes": 30,
        },
        format="json",
    )

    assert create_response.status_code == 201
    data = create_response.json()
    assert "lease_token" not in data
    release_response = api_client.post(
        f"/api/dynamic/device-leases/{data['id']}/release/",
        {"reason": "COMPLETED"},
        format="json",
    )
    assert release_response.status_code == 200
    assert release_response.json()["lease_status"] == (
        DynamicDeviceLease.LeaseStatus.RELEASED
    )


@pytest.mark.django_db
def test_dynamic_api_lists_sessions(api_client):
    session = _make_session()

    response = api_client.get("/api/dynamic/sessions/")

    assert response.status_code == 200
    assert response.json()[0]["id"] == session.id


@pytest.mark.django_db
def test_dynamic_api_requires_authentication():
    response = APIClient().get("/api/dynamic/device-pools/")

    assert response.status_code in {401, 403}


@pytest.mark.django_db
def test_dynamic_viewer_cannot_perform_unsafe_write(django_user_model):
    call_command("bootstrap_roles", verbosity=0)
    user = django_user_model.objects.create_user(
        username="dynamic-viewer",
        password=PASSWORD,
    )
    user.groups.add(Group.objects.get(name=VIEWER_GROUP))
    client = APIClient()
    client.force_authenticate(user=user)

    response = client.post(
        "/api/dynamic/device-pools/",
        {"name": "Denied", "slug": "denied"},
        format="json",
    )

    assert response.status_code == 403


def test_host_agent_client_disabled_returns_clear_status():
    result = DynamicHostAgentClient(
        enabled=False,
        base_url="",
        token="",
    ).get_status()

    assert result == {
        "connected": False,
        "enabled": False,
        "code": "HOST_AGENT_DISABLED",
        "detail": "Start the local dynamic host agent on WSL to control the emulator.",
    }


def test_host_agent_client_connection_error_is_structured_and_hides_token():
    local_token = "never-print-this-local-token"
    client = DynamicHostAgentClient(
        enabled=True,
        base_url="http://127.0.0.1:8765",
        token=local_token,
        timeout_seconds=1,
    )

    with patch(
        "apps.dynamic_analysis.services.host_agent_client.urllib_request.urlopen",
        side_effect=urllib_error.URLError("connection refused"),
    ):
        result = client.get_status()

    assert result["connected"] is False
    assert result["code"] == "HOST_AGENT_UNREACHABLE"
    assert "Backend cannot reach host-agent" in result["detail"]
    assert local_token not in str(result)


def test_host_agent_client_redacts_token_from_http_errors():
    local_token = "never-return-this-token"
    client = DynamicHostAgentClient(
        enabled=True,
        base_url="http://127.0.0.1:8765",
        token=local_token,
        timeout_seconds=1,
    )
    response_body = (
        f'{{"detail":"token={local_token} authorization=Bearer-value"}}'
    ).encode()
    http_error = urllib_error.HTTPError(
        client._url("/actions/force-stop"),
        400,
        "Bad Request",
        {},
        BytesIO(response_body),
    )

    with patch(
        "apps.dynamic_analysis.services.host_agent_client.urllib_request.urlopen",
        side_effect=http_error,
    ), pytest.raises(HostAgentClientError) as exc_info:
        client.request_json(
            "/actions/force-stop",
            method="POST",
            body={"package_name": "com.example.safe"},
        )

    assert exc_info.value.status_code == 400
    assert local_token not in str(exc_info.value)
    assert "Bearer-value" not in str(exc_info.value)


def test_host_agent_rejects_package_action_when_package_is_not_installed():
    agent = DynamicHostAgent(token="test-token", serial="emulator-5554")
    missing_package_result = {
        "return_code": 0,
        "stdout_preview": "",
        "stderr_preview": "",
        "duration_seconds": 0.1,
        "timed_out": False,
        "redaction_applied": False,
    }

    with patch.object(
        agent,
        "_run_adb",
        return_value=missing_package_result,
    ) as run_adb, pytest.raises(HostAgentRequestError) as exc_info:
        agent.package_action(
            "force-stop",
            {"package_name": "com.example.missing"},
        )

    assert "not installed" in str(exc_info.value)
    run_adb.assert_called_once_with(
        "shell",
        "pm",
        "path",
        "com.example.missing",
        timeout_seconds=15,
    )


def test_host_agent_binary_output_uses_screenshot_limit_not_text_preview_limit():
    expected_size = 300 * 1024

    result = _run_process(
        [
            sys.executable,
            "-c",
            f"import sys; sys.stdout.buffer.write(b'x' * {expected_size})",
        ],
        timeout_seconds=10,
        binary=True,
    )

    assert result["return_code"] == 0
    assert len(result["stdout"]) == expected_size


@pytest.mark.django_db
def test_host_agent_status_api_requires_authentication():
    response = APIClient().get("/api/dynamic/host-agent/status/")

    assert response.status_code in {401, 403}


@pytest.mark.django_db
def test_dynamic_sync_device_api_uses_stable_payload(api_client):
    payload = {
        "connected": True,
        "enabled": True,
        "code": "HOST_AGENT_CONNECTED",
        "detail": "Dynamic host agent is connected.",
        "device": {
            "serial": "emulator-5554",
            "state": "device",
            "api_level": 35,
        },
    }
    with patch(
        "apps.dynamic_analysis.views.fetch_and_sync_host_agent",
        return_value=payload,
    ) as sync_host_agent:
        response = api_client.post(
            "/api/dynamic/host-agent/sync/",
            {},
            format="json",
        )

    assert response.status_code == 200
    assert response.json() == payload
    sync_host_agent.assert_called_once()
    assert sync_host_agent.call_args.kwargs["requested_by"].is_superuser


@override_settings(
    MSAP_DYNAMIC_HOST_AGENT_ENABLED=True,
    MSAP_DYNAMIC_HOST_AGENT_URL="http://127.0.0.1:8765",
    MSAP_DYNAMIC_HOST_AGENT_TOKEN="test-only-token",
)
@pytest.mark.django_db
def test_host_agent_screenshot_negotiates_binary_png(api_client):
    png = b"\x89PNG\r\n\x1a\n" + b"bounded-test-png"
    _make_device("5554")
    with patch(
        "apps.dynamic_analysis.views.DynamicHostAgentClient.request_screenshot",
        return_value=png,
    ):
        response = api_client.post(
            "/api/dynamic/host-agent/screenshot/",
            {},
            format="json",
            HTTP_ACCEPT="image/png",
        )

    assert response.status_code == 200
    assert response["Content-Type"] == "image/png"
    assert response.content.startswith(b"\x89PNG\r\n\x1a\n")
    assert DynamicDeviceEvent.objects.filter(
        device__serial="emulator-5554",
        metadata__action="screenshot",
    ).exists()


@pytest.mark.django_db
def test_dynamic_package_list_uses_bounded_host_agent_response(viewer_client):
    package_result = {
        "success": True,
        "serial": "emulator-5554",
        "count": 2,
        "packages": ["com.example.one", "com.example.two"],
        "truncated": False,
        "return_code": 0,
        "duration_seconds": 0.2,
    }
    with patch(
        "apps.dynamic_analysis.views.DynamicHostAgentClient.request_json",
        return_value=package_result,
    ) as request_json:
        response = viewer_client.get("/api/dynamic/host-agent/packages/")

    assert response.status_code == 200
    assert response.json()["packages"] == package_result["packages"]
    request_json.assert_called_once_with(
        "/actions/list-packages",
        method="POST",
        body={},
    )


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("endpoint", "action"),
    [
        ("launch-package", "launch-package"),
        ("force-stop", "force-stop"),
        ("clear-data", "clear-data"),
        ("uninstall", "uninstall"),
    ],
)
def test_dynamic_analyst_can_run_mocked_package_actions(
    analyst_client,
    endpoint,
    action,
):
    _make_device("5554")
    action_result = {
        "action": action,
        "package_name": "com.example.safe",
        "success": True,
        "status": "PASS",
        "duration_seconds": 0.25,
    }

    with patch(
        "apps.dynamic_analysis.views.DynamicHostAgentClient.request_json",
        return_value=action_result,
    ) as request_json:
        response = analyst_client.post(
            f"/api/dynamic/host-agent/{endpoint}/",
            {"package_name": "com.example.safe"},
            format="json",
        )

    assert response.status_code == 200
    assert response.json()["status"] == "PASS"
    request_json.assert_called_once_with(
        f"/actions/{action}",
        method="POST",
        body={"package_name": "com.example.safe"},
    )
    assert DynamicDeviceEvent.objects.filter(
        device__serial="emulator-5554",
        metadata__action=action,
    ).exists()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "endpoint,payload",
    [
        ("force-stop", {"package_name": "com.example.safe"}),
        ("launch-package", {"package_name": "com.example.safe"}),
        ("clear-data", {"package_name": "com.example.safe"}),
        ("uninstall", {"package_name": "com.example.safe"}),
        ("install-audit-apk", {"audit": 1}),
    ],
)
def test_dynamic_viewer_cannot_call_mutating_host_agent_actions(
    django_user_model,
    endpoint,
    payload,
):
    call_command("bootstrap_roles", verbosity=0)
    user = django_user_model.objects.create_user(
        username=f"host-agent-viewer-{endpoint}",
        password=PASSWORD,
    )
    user.groups.add(Group.objects.get(name=VIEWER_GROUP))
    client = APIClient()
    client.force_authenticate(user=user)

    response = client.post(
        f"/api/dynamic/host-agent/{endpoint}/",
        payload,
        format="json",
    )

    assert response.status_code == 403


@pytest.mark.django_db
@pytest.mark.parametrize(
    "package_name",
    [
        "com.example.app;id",
        "../../data/local/tmp/app",
        "com.example.$(id)",
        "singlelabel",
        "1com.example.app",
    ],
)
def test_host_agent_package_name_validation_rejects_unsafe_input(
    api_client,
    package_name,
):
    with patch(
        "apps.dynamic_analysis.views.DynamicHostAgentClient.request_json"
    ) as request_json:
        response = api_client.post(
            "/api/dynamic/host-agent/force-stop/",
            {"package_name": package_name},
            format="json",
        )

    assert response.status_code == 400
    request_json.assert_not_called()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "path",
    [
        "/api/dynamic/scripts/",
        "/api/dynamic/script-runs/",
        "/api/dynamic/frida/status/",
        "/api/dynamic/host-agent/preflight/",
        "/api/dynamic/host-agent/frida-smoke/",
        "/api/dynamic/host-agent/mitmproxy-smoke/",
        "/api/dynamic/host-agent/platform-tls-probe/",
    ],
)
def test_dynamic_lab_experimental_routes_are_removed(api_client, path):
    response = api_client.post(path, {}, format="json")

    assert response.status_code == 404


@pytest.mark.django_db
def test_install_audit_apk_refuses_missing_audit_or_apk(api_client):
    missing_audit_response = api_client.post(
        "/api/dynamic/host-agent/install-audit-apk/",
        {"audit": 999999},
        format="json",
    )
    project = Project.objects.create(name="No APK project")
    audit = Audit.objects.create(project=project, name="No APK audit")
    missing_apk_response = api_client.post(
        "/api/dynamic/host-agent/install-audit-apk/",
        {"audit": audit.id},
        format="json",
    )

    assert missing_audit_response.status_code == 404
    assert missing_apk_response.status_code == 400
    assert "No uploaded APK" in missing_apk_response.json()["detail"]


@override_settings(MSAP_DYNAMIC_HOST_AGENT_MAX_APK_SIZE_BYTES=1024 * 1024)
@pytest.mark.django_db
def test_install_verified_audit_apk_returns_and_persists_package_metadata(
    api_client,
    tmp_path,
):
    project = Project.objects.create(name="Install project")
    audit = Audit.objects.create(project=project, name="Install audit")
    apk_bytes = b"PK\x03\x04" + b"bounded-apk-test"
    digest = file_sha256(apk_bytes).hexdigest()
    storage_reference = ObjectStorageReference.objects.create(
        project=project,
        audit=audit,
        bucket="msap-apk-uploads",
        object_key="projects/1/audits/1/apk_upload/test.apk",
        object_type=ObjectStorageReference.ObjectType.APK_UPLOAD,
        storage_status=ObjectStorageReference.StorageStatus.VERIFIED,
        content_type="application/vnd.android.package-archive",
        size_bytes=len(apk_bytes),
        sha256=digest,
    )
    apk_file = APKFile.objects.create(
        audit=audit,
        storage_reference=storage_reference,
        size_bytes=len(apk_bytes),
        sha256=digest,
    )
    local_apk = tmp_path / "verified.apk"
    local_apk.write_bytes(apk_bytes)
    _make_device("5554")
    package_metadata = {
        "package_name": "owasp.sat.agoat",
        "version_name": "1.0",
        "version_code": "1",
        "installed_apk_path": "/data/app/owasp.sat.agoat/base.apk",
        "launchable_activity": "owasp.sat.agoat/.MainActivity",
        "requested_permission_count": 12,
        "granted_permission_count": 8,
    }

    with patch(
        "apps.dynamic_analysis.views.APKFileProvider.open_apk_local_copy",
        return_value=nullcontext(local_apk),
    ), patch(
        "apps.dynamic_analysis.views.DynamicHostAgentClient.install_apk",
        return_value={
            "action": "install-apk",
            "success": True,
            "status": "PASS",
            "install_status": "PASS",
            "sha256": digest,
            "size_bytes": len(apk_bytes),
            "duration_seconds": 1.2,
            "package_name": "owasp.sat.agoat",
            "package_metadata": package_metadata,
        },
    ) as install_apk:
        response = api_client.post(
            "/api/dynamic/host-agent/install-audit-apk/",
            {"audit": audit.id, "apk_file": apk_file.id},
            format="json",
        )

    assert response.status_code == 200
    assert response.json()["package_metadata"] == package_metadata
    install_apk.assert_called_once_with(local_apk, expected_sha256=digest)
    apk_file.refresh_from_db()
    assert apk_file.package_name == "owasp.sat.agoat"
    assert apk_file.version_name == "1.0"
    event = DynamicDeviceEvent.objects.filter(
        device__serial="emulator-5554",
        metadata__action="install-apk",
    ).latest("created_at")
    assert event.metadata["package_metadata"]["launchable_activity"].endswith(
        ".MainActivity"
    )


@override_settings(
    MSAP_DYNAMIC_RUNNER_ENABLED=True,
    MSAP_DYNAMIC_RUNNER_SYNC_DEMO_ENABLED=False,
)
def test_dynamic_runner_readiness_reports_worker_online():
    inspector = Mock()
    inspector.ping.return_value = {"worker@example": {"ok": "pong"}}
    with patch(
        "apps.dynamic_analysis.services.runner_readiness.current_app.control.inspect",
        return_value=inspector,
    ):
        result = get_dynamic_runner_readiness()

    assert result["ready"] is True
    assert result["worker_status"] == "ONLINE"
    assert result["workers_responding"] == 1


@override_settings(
    MSAP_DYNAMIC_RUNNER_ENABLED=True,
    MSAP_DYNAMIC_RUNNER_SYNC_DEMO_ENABLED=False,
)
def test_dynamic_runner_readiness_reports_no_worker():
    inspector = Mock()
    inspector.ping.return_value = {}
    with patch(
        "apps.dynamic_analysis.services.runner_readiness.current_app.control.inspect",
        return_value=inspector,
    ):
        result = get_dynamic_runner_readiness()

    assert result["ready"] is False
    assert result["worker_status"] == "OFFLINE"
    assert result["code"] == "CELERY_WORKER_OFFLINE"


@pytest.mark.django_db
def test_sync_dynamic_host_agent_command_updates_device():
    output = StringIO()
    agent_response = {
        "connected": True,
        "enabled": True,
        "code": "HOST_AGENT_CONNECTED",
        "detail": "Dynamic host agent is connected.",
        "agent": {
            "version": "1.0",
            "dynamic_env_detected": True,
            "adb_path_present": True,
            "serial": "emulator-5554",
        },
        "device": {
            "serial": "emulator-5554",
            "state": "device",
            "adb_path_present": True,
            "root_uid": 0,
            "api_level": 35,
            "android_version": "15",
            "abi": "x86_64",
            "selinux": "Enforcing",
            "proxy": ":0",
            "focused_app": "com.android.settings",
            "frida_server_running": False,
            "frida_smoke": True,
            "mitmproxy_smoke": True,
        },
    }

    with patch(
        "apps.dynamic_analysis.services.host_agent_sync."
        "DynamicHostAgentClient.get_status",
        return_value=agent_response,
    ):
        call_command("sync_dynamic_host_agent", stdout=output)

    device = DynamicDevice.objects.get(serial="emulator-5554")
    assert device.status == DynamicDevice.Status.AVAILABLE
    assert device.api_level == 35
    assert device.android_version == "15"
    assert device.abi == "x86_64"
    assert device.is_rooted is True
    assert device.selinux_mode == "Enforcing"
    assert device.has_frida is True
    assert device.has_mitm_ready is True
    assert device.last_seen_at is not None
    assert device.last_health_check_at is not None
    assert "SYNC_DYNAMIC_HOST_AGENT_RESULT=PASS" in output.getvalue()


@pytest.mark.django_db
def test_seed_dynamic_lab_command_creates_local_lab_metadata():
    output = StringIO()

    call_command("seed_dynamic_lab", stdout=output)

    assert "SEED_DYNAMIC_LAB_RESULT=PASS" in output.getvalue()
    pool = DynamicDevicePool.objects.get(slug="local-android-lab")
    device = DynamicDevice.objects.get(serial="emulator-5554")
    assert pool.name == "Local Android Lab"
    assert device.name == "Lab-Root"
    assert device.status == DynamicDevice.Status.AVAILABLE
    assert device.kind == DynamicDevice.Kind.EMULATOR
    assert device.host_type == DynamicDevice.HostType.WINDOWS_WSL
    assert device.api_level == 35
    assert device.abi == "x86_64"
    assert device.is_rooted is True
    assert device.selinux_mode == "Enforcing"
    assert device.has_frida is True
    assert device.has_mitm_ready is True
    assert DynamicDeviceCapability.objects.filter(device=device).count() == 7
    assert DynamicEmulatorSnapshot.objects.filter(device=device).count() == 2


@override_settings(MSAP_DYNAMIC_RUNNER_ENABLED=False)
@pytest.mark.django_db
def test_dynamic_mvp_runner_refuses_when_disabled():
    audit, _apk = _make_audit_with_apk("runner-disabled")
    job = DynamicAnalysisJob.objects.create(audit=audit)

    with pytest.raises(DynamicMvpRunnerError):
        run_dynamic_mvp_job(job.id)


@override_settings(MSAP_DYNAMIC_RUNNER_ENABLED=True)
def test_dynamic_local_script_wrapper_rejects_non_allowlisted_script(tmp_path):
    with override_settings(MSAP_DYNAMIC_LAB_SCRIPT_DIR=tmp_path, PROJECT_ROOT=tmp_path):
        with pytest.raises(DynamicScriptExecutionError):
            run_dynamic_lab_script("not-allowed.sh", timeout_seconds=1)


@override_settings(MSAP_DYNAMIC_RUNNER_ENABLED=True)
def test_dynamic_local_script_wrapper_handles_pass_markers(tmp_path):
    _write_test_script(tmp_path, "preflight.sh", "echo PREFLIGHT_RESULT=PASS\n")

    with override_settings(MSAP_DYNAMIC_LAB_SCRIPT_DIR=tmp_path, PROJECT_ROOT=tmp_path):
        result = run_dynamic_lab_script("preflight.sh", timeout_seconds=5)

    assert result.return_code == 0
    assert result.pass_markers == ["PREFLIGHT_RESULT=PASS"]
    assert result.fail_markers == []


@override_settings(MSAP_DYNAMIC_RUNNER_ENABLED=True)
def test_dynamic_local_script_wrapper_handles_fail_markers_and_nonzero(tmp_path):
    _write_test_script(
        tmp_path,
        "frida-smoke.sh",
        "echo FRIDA_SMOKE_RESULT=FAIL\nexit 7\n",
    )

    with override_settings(MSAP_DYNAMIC_LAB_SCRIPT_DIR=tmp_path, PROJECT_ROOT=tmp_path):
        with pytest.raises(DynamicScriptExecutionError) as exc:
            run_dynamic_lab_script("frida-smoke.sh", timeout_seconds=5)

    assert exc.value.result.return_code == 7
    assert exc.value.result.fail_markers == ["FRIDA_SMOKE_RESULT=FAIL"]


@override_settings(
    MSAP_DYNAMIC_STAGE_TIMEOUT_SECONDS=0,
    MSAP_DYNAMIC_STAGE_TIMEOUTS_JSON="",
    MSAP_DYNAMIC_STAGE_TIMEOUT_MIN_SECONDS=1,
    MSAP_DYNAMIC_STAGE_TIMEOUT_MAX_SECONDS=1800,
)
def test_dynamic_stage_timeout_mapping_defaults_and_overrides():
    assert get_dynamic_stage_timeout("preflight") == 420
    assert get_dynamic_stage_timeout("restore-instrumented-snapshot.sh") == 600
    assert get_dynamic_stage_timeout("platform_tls_probe") == 900
    assert get_dynamic_stage_timeout("cleanup_runtime_state") == 420

    with override_settings(MSAP_DYNAMIC_STAGE_TIMEOUT_SECONDS=222):
        assert get_dynamic_stage_timeout("preflight") == 222
        assert get_dynamic_stage_timeout("cleanup-runtime-state.sh") == 222

    with override_settings(
        MSAP_DYNAMIC_STAGE_TIMEOUT_SECONDS=0,
        MSAP_DYNAMIC_STAGE_TIMEOUTS_JSON=(
            '{"preflight": 333, "cleanup-runtime-state.sh": 444}'
        ),
    ):
        assert get_dynamic_stage_timeout("preflight") == 333
        assert get_dynamic_stage_timeout("cleanup_runtime_state") == 444

    with override_settings(
        MSAP_DYNAMIC_STAGE_TIMEOUT_SECONDS=0,
        MSAP_DYNAMIC_STAGE_TIMEOUTS_JSON='{"platform_tls_probe": 9999}',
        MSAP_DYNAMIC_STAGE_TIMEOUT_MAX_SECONDS=500,
    ):
        assert get_dynamic_stage_timeout("platform-tls-probe.sh") == 500


@override_settings(MSAP_DYNAMIC_RUNNER_ENABLED=True)
def test_dynamic_local_script_timeout_failure_includes_previews(tmp_path):
    _write_test_script(
        tmp_path,
        "preflight.sh",
        "echo before-timeout\n"
        "echo err-before-timeout >&2\n"
        "sleep 2\n"
        "echo after-timeout\n",
    )

    with override_settings(MSAP_DYNAMIC_LAB_SCRIPT_DIR=tmp_path, PROJECT_ROOT=tmp_path):
        with pytest.raises(DynamicScriptExecutionError) as exc:
            run_dynamic_lab_script("preflight.sh", timeout_seconds=1)

    message = str(exc.value)
    assert exc.value.stage_name == "preflight"
    assert exc.value.script_name == "preflight.sh"
    assert exc.value.timeout_seconds == 1
    assert exc.value.result.timed_out is True
    assert exc.value.result.timeout_seconds == 1
    assert "stage=preflight" in message
    assert "script=preflight.sh" in message
    assert "timeout=1s" in message
    assert "stdout_preview:" in message
    assert "stderr_preview:" in message
    assert "before-timeout" in exc.value.result.stdout_preview
    assert "err-before-timeout" in exc.value.result.stderr_preview


@override_settings(
    MSAP_DYNAMIC_RUNNER_ENABLED=True,
    MSAP_DYNAMIC_MVP_DEVICE_SERIAL="emulator-test",
)
def test_dynamic_local_script_env_includes_safe_runner_defaults(tmp_path, monkeypatch):
    monkeypatch.delenv("MSAP_ANDROID_SERIAL", raising=False)
    monkeypatch.setenv("MSAP_DYNAMIC_HOME", "/tmp/msap-dynamic-home")
    _write_test_script(
        tmp_path,
        "preflight.sh",
        'echo "ENABLED=$MSAP_DYNAMIC_RUNNER_ENABLED"\n'
        'echo "SERIAL=$MSAP_ANDROID_SERIAL"\n'
        'echo "DYNAMIC_HOME=$MSAP_DYNAMIC_HOME"\n'
        'case ":$PATH:" in *":$HOME/.local/bin:"*) echo "LOCAL_BIN_IN_PATH=yes";; '
        '*) echo "LOCAL_BIN_IN_PATH=no";; esac\n'
        "echo PREFLIGHT_RESULT=PASS\n",
    )

    with override_settings(MSAP_DYNAMIC_LAB_SCRIPT_DIR=tmp_path, PROJECT_ROOT=tmp_path):
        result = run_dynamic_lab_script("preflight.sh", timeout_seconds=5)

    assert "ENABLED=true" in result.stdout_preview
    assert "SERIAL=emulator-test" in result.stdout_preview
    assert "DYNAMIC_HOME=/tmp/msap-dynamic-home" in result.stdout_preview
    assert "LOCAL_BIN_IN_PATH=yes" in result.stdout_preview


def test_dynamic_local_script_wrapper_does_not_use_shell_true():
    source = inspect.getsource(local_scripts.run_dynamic_lab_script)

    assert "shell" + "=True" not in source
    assert "subprocess" + ".run(" not in source


@override_settings(
    MSAP_DYNAMIC_RUNNER_ENABLED=True,
    MSAP_DYNAMIC_PLATFORM_TLS_PROBE_ENABLED=False,
)
@pytest.mark.django_db
def test_dynamic_mvp_runner_creates_session_stages_artifacts_on_pass():
    audit, _apk = _make_audit_with_apk("runner-pass")
    job = create_dynamic_mvp_job(audit)

    with patch(
        "apps.dynamic_analysis.services.mvp_runner.run_dynamic_lab_script",
        side_effect=_mock_successful_dynamic_script,
    ):
        result = run_dynamic_mvp_job(job.id)

    job.refresh_from_db()
    session = DynamicSession.objects.get(job=job)
    lease = DynamicDeviceLease.objects.get(job=job)
    device = session.device
    device.refresh_from_db()
    assert result["job_status"] == DynamicAnalysisJob.Status.COMPLETED
    assert job.status == DynamicAnalysisJob.Status.COMPLETED
    assert session.state == DynamicSession.State.COMPLETED
    assert session.cleanup_status == DynamicSession.CleanupStatus.SUCCEEDED
    assert lease.lease_status == DynamicDeviceLease.LeaseStatus.RELEASED
    assert device.status == DynamicDevice.Status.AVAILABLE
    assert DynamicSessionStage.objects.filter(session=session).count() == 7
    assert DynamicSessionArtifact.objects.filter(session=session).count() == 7
    assert DynamicSessionStage.objects.get(
        session=session,
        name="platform_tls_probe",
    ).status == DynamicSessionStage.StageStatus.SKIPPED


@override_settings(
    MSAP_DYNAMIC_RUNNER_ENABLED=True,
    MSAP_DYNAMIC_PLATFORM_TLS_PROBE_ENABLED=False,
    MSAP_DYNAMIC_STAGE_TIMEOUT_SECONDS=0,
)
@pytest.mark.django_db
def test_run_dynamic_mvp_command_prints_stage_progress():
    audit, _apk = _make_audit_with_apk("command-progress")
    output = StringIO()

    with patch(
        "apps.dynamic_analysis.services.mvp_runner.run_dynamic_lab_script",
        side_effect=_mock_successful_dynamic_script,
    ):
        call_command(
            "run_dynamic_mvp",
            "--audit-id",
            str(audit.id),
            stdout=output,
        )

    value = output.getvalue()
    assert "Job ID:" in value
    assert "Session ID:" in value
    assert "STAGE START preflight script=preflight.sh timeout=420s" in value
    assert "PASS preflight script=preflight.sh" in value
    assert "SKIP platform_tls_probe script=platform-tls-probe.sh" in value
    assert "Final job status: COMPLETED" in value
    assert "Final session state: COMPLETED" in value
    assert "DYNAMIC_MVP_RUNNER_RESULT=PASS" in value


@override_settings(
    MSAP_DYNAMIC_RUNNER_ENABLED=True,
    MSAP_DYNAMIC_PLATFORM_TLS_PROBE_ENABLED=False,
)
@pytest.mark.django_db
def test_dynamic_mvp_runner_marks_failed_and_attempts_cleanup_after_stage_failure():
    audit, _apk = _make_audit_with_apk("runner-fail")
    job = create_dynamic_mvp_job(audit)
    calls = []

    def script_side_effect(script_name, timeout_seconds=None, extra_env=None):
        calls.append(script_name)
        if script_name == "frida-smoke.sh":
            result = _dynamic_script_result(
                "frida_smoke",
                script_name,
                fail_markers=["FRIDA_SMOKE_RESULT=FAIL"],
                return_code=1,
            )
            raise DynamicScriptExecutionError("Frida smoke failed.", result=result)
        return _mock_successful_dynamic_script(script_name, timeout_seconds, extra_env)

    with patch(
        "apps.dynamic_analysis.services.mvp_runner.run_dynamic_lab_script",
        side_effect=script_side_effect,
    ):
        result = run_dynamic_mvp_job(job.id)

    job.refresh_from_db()
    session = DynamicSession.objects.get(job=job)
    lease = DynamicDeviceLease.objects.get(job=job)
    assert result["job_status"] == DynamicAnalysisJob.Status.FAILED
    assert job.failure_category == DynamicAnalysisJob.FailureCategory.FRIDA_START_FAILED
    assert session.state == DynamicSession.State.FAILED
    assert session.cleanup_status == DynamicSession.CleanupStatus.SUCCEEDED
    assert lease.lease_status == DynamicDeviceLease.LeaseStatus.RELEASED
    assert "cleanup-runtime-state.sh" in calls
    assert calls.index("cleanup-runtime-state.sh") > calls.index("frida-smoke.sh")


@override_settings(
    MSAP_DYNAMIC_RUNNER_ENABLED=True,
    MSAP_DYNAMIC_PLATFORM_TLS_PROBE_ENABLED=False,
)
@pytest.mark.django_db
def test_dynamic_mvp_runner_quarantines_device_if_cleanup_fails():
    audit, _apk = _make_audit_with_apk("runner-cleanup-fail")
    job = create_dynamic_mvp_job(audit)

    def script_side_effect(script_name, timeout_seconds=None, extra_env=None):
        if script_name == "cleanup-runtime-state.sh":
            result = _dynamic_script_result(
                "cleanup_runtime_state",
                script_name,
                fail_markers=["CLEANUP_RUNTIME_STATE_RESULT=FAIL"],
                return_code=1,
            )
            raise DynamicScriptExecutionError("Cleanup failed.", result=result)
        return _mock_successful_dynamic_script(script_name, timeout_seconds, extra_env)

    with patch(
        "apps.dynamic_analysis.services.mvp_runner.run_dynamic_lab_script",
        side_effect=script_side_effect,
    ):
        result = run_dynamic_mvp_job(job.id)

    job.refresh_from_db()
    session = DynamicSession.objects.get(job=job)
    lease = DynamicDeviceLease.objects.get(job=job)
    device = session.device
    device.refresh_from_db()
    assert result["job_status"] == DynamicAnalysisJob.Status.FAILED
    assert job.failure_category == DynamicAnalysisJob.FailureCategory.CLEANUP_FAILED
    assert session.state == DynamicSession.State.QUARANTINED
    assert session.cleanup_status == DynamicSession.CleanupStatus.FAILED
    assert lease.lease_status == DynamicDeviceLease.LeaseStatus.RELEASED
    assert device.status == DynamicDevice.Status.QUARANTINED


@override_settings(
    MSAP_DYNAMIC_RUNNER_ENABLED=True,
    MSAP_DYNAMIC_PLATFORM_TLS_PROBE_ENABLED=False,
)
@pytest.mark.django_db
def test_dynamic_mvp_runner_cleanup_timeout_quarantines_without_running_records():
    audit, _apk = _make_audit_with_apk("runner-cleanup-timeout")
    job = create_dynamic_mvp_job(audit)

    def script_side_effect(script_name, timeout_seconds=None, extra_env=None):
        if script_name == "cleanup-runtime-state.sh":
            result = _dynamic_script_result(
                "cleanup_runtime_state",
                script_name,
                return_code=-1,
                stdout_preview="cleanup started",
                stderr_preview="PowerShell relay did not exit",
                timed_out=True,
                timeout_seconds=timeout_seconds,
            )
            raise DynamicScriptExecutionError(
                "Dynamic lab script timed out. "
                "stage=cleanup_runtime_state "
                "script=cleanup-runtime-state.sh "
                f"timeout={timeout_seconds}s\n"
                "stdout_preview:\ncleanup started\n"
                "stderr_preview:\nPowerShell relay did not exit",
                result=result,
                timeout_seconds=timeout_seconds,
            )
        return _mock_successful_dynamic_script(script_name, timeout_seconds, extra_env)

    with patch(
        "apps.dynamic_analysis.services.mvp_runner.run_dynamic_lab_script",
        side_effect=script_side_effect,
    ):
        result = run_dynamic_mvp_job(job.id)

    job.refresh_from_db()
    session = DynamicSession.objects.get(job=job)
    lease = DynamicDeviceLease.objects.get(job=job)
    device = session.device
    device.refresh_from_db()
    cleanup_stage = DynamicSessionStage.objects.get(
        session=session,
        name="cleanup_runtime_state",
    )
    assert result["job_status"] == DynamicAnalysisJob.Status.FAILED
    assert job.status == DynamicAnalysisJob.Status.FAILED
    assert job.failure_category == DynamicAnalysisJob.FailureCategory.CLEANUP_FAILED
    assert "cleanup-runtime-state.sh" in job.failure_message
    assert session.state == DynamicSession.State.QUARANTINED
    assert session.cleanup_status == DynamicSession.CleanupStatus.FAILED
    assert session.quarantine_required is True
    assert lease.lease_status == DynamicDeviceLease.LeaseStatus.RELEASED
    assert device.status == DynamicDevice.Status.QUARANTINED
    assert cleanup_stage.status == DynamicSessionStage.StageStatus.FAILED
    assert cleanup_stage.metadata["timed_out"] is True
    assert "cleanup started" in cleanup_stage.message
    assert not DynamicSessionStage.objects.filter(
        session=session,
        status=DynamicSessionStage.StageStatus.RUNNING,
    ).exists()
    assert not DynamicSession.objects.filter(
        job=job,
        cleanup_status=DynamicSession.CleanupStatus.IN_PROGRESS,
    ).exists()
    assert not DynamicAnalysisJob.objects.filter(
        id=job.id,
        status=DynamicAnalysisJob.Status.RUNNING,
    ).exists()


@override_settings(MSAP_DYNAMIC_RUNNER_ENABLED=False)
@pytest.mark.django_db
def test_dynamic_api_run_mvp_action_refuses_when_disabled(api_client):
    audit, _apk = _make_audit_with_apk("api-run-disabled")
    job = DynamicAnalysisJob.objects.create(audit=audit)

    response = api_client.post(
        f"/api/dynamic/jobs/{job.id}/run-mvp/",
        {},
        format="json",
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Dynamic MVP runner is disabled."


@override_settings(
    MSAP_DYNAMIC_RUNNER_ENABLED=True,
    MSAP_DYNAMIC_PLATFORM_TLS_PROBE_ENABLED=False,
)
@pytest.mark.django_db
def test_dynamic_api_run_mvp_action_queues_when_enabled(api_client):
    audit, _apk = _make_audit_with_apk("api-run-enabled")
    job = DynamicAnalysisJob.objects.create(audit=audit)
    async_result = Mock(id="task-dynamic-mvp")

    with patch(
        "apps.dynamic_analysis.views.get_dynamic_runner_readiness",
        return_value={"ready": True},
    ), patch(
        "apps.dynamic_analysis.views.run_dynamic_mvp_job_task.delay",
        return_value=async_result,
    ) as delay:
        response = api_client.post(
            f"/api/dynamic/jobs/{job.id}/run-mvp/",
            {},
            format="json",
        )

    assert response.status_code == 202
    assert response.json()["task_id"] == "task-dynamic-mvp"
    delay.assert_called_once_with(job.id, include_platform_tls_probe=False)


@override_settings(MSAP_DYNAMIC_RUNNER_ENABLED=True)
@pytest.mark.django_db
def test_dynamic_api_does_not_create_job_without_worker(api_client):
    audit, apk = _make_audit_with_apk("no-worker")
    readiness = {
        "ready": False,
        "runner_enabled": True,
        "sync_demo_enabled": False,
        "execution_mode": "celery",
        "worker_status": "OFFLINE",
        "workers_responding": 0,
        "code": "CELERY_WORKER_OFFLINE",
        "detail": "No Celery worker responded.",
    }
    with patch(
        "apps.dynamic_analysis.views.get_dynamic_runner_readiness",
        return_value=readiness,
    ):
        response = api_client.post(
            "/api/dynamic/jobs/",
            {
                "audit": audit.id,
                "apk": apk.id,
                "mode": DynamicAnalysisJob.Mode.COMBINED,
                "requested_tool_profile": DynamicAnalysisJob.ToolProfile.ADB_ONLY,
                "requested_interaction_mode": DynamicAnalysisJob.InteractionMode.PASSIVE,
            },
            format="json",
        )

    assert response.status_code == 503
    assert response.json()["worker_status"] == "OFFLINE"
    assert not DynamicAnalysisJob.objects.filter(audit=audit).exists()


@override_settings(
    MSAP_DYNAMIC_RUNNER_ENABLED=True,
    MSAP_DYNAMIC_RUNNER_SYNC_DEMO_ENABLED=True,
    MSAP_DYNAMIC_PLATFORM_TLS_PROBE_ENABLED=False,
)
@pytest.mark.django_db
def test_dynamic_api_synchronous_demo_invokes_runner(api_client):
    audit, _apk = _make_audit_with_apk("sync-demo")
    job = DynamicAnalysisJob.objects.create(audit=audit)
    final_result = {"job_id": job.id, "job_status": DynamicAnalysisJob.Status.COMPLETED}

    with patch(
        "apps.dynamic_analysis.views.get_dynamic_runner_readiness",
        return_value={"ready": True},
    ), patch(
        "apps.dynamic_analysis.views.run_dynamic_mvp_job",
        return_value=final_result,
    ) as runner:
        response = api_client.post(
            f"/api/dynamic/jobs/{job.id}/run-mvp/",
            {},
            format="json",
        )

    assert response.status_code == 200
    assert response.json()["execution_mode"] == "synchronous"
    assert response.json()["task_id"] is None
    runner.assert_called_once_with(job.id, include_platform_tls_probe=False)


@pytest.mark.django_db
def test_stale_queued_job_recovery_cancels_without_deleting_evidence():
    audit, _apk = _make_audit_with_apk("stale-queued")
    job = DynamicAnalysisJob.objects.create(
        audit=audit,
        queued_at=timezone.now() - timedelta(minutes=30),
    )
    DynamicAnalysisJob.objects.filter(pk=job.pk).update(
        updated_at=timezone.now() - timedelta(minutes=30)
    )

    result = recover_stale_dynamic_jobs(older_than_minutes=5)

    job.refresh_from_db()
    assert result["recovered_job_ids"] == [job.id]
    assert job.status == DynamicAnalysisJob.Status.CANCELLED
    assert job.failure_category == DynamicAnalysisJob.FailureCategory.OPERATOR_CANCELLED


@pytest.mark.django_db
def test_cancel_endpoint_allows_queued_job(api_client):
    audit, _apk = _make_audit_with_apk("cancel-queued")
    job = DynamicAnalysisJob.objects.create(audit=audit)

    response = api_client.post(f"/api/dynamic/jobs/{job.id}/cancel/", {}, format="json")

    assert response.status_code == 200
    assert response.json()["status"] == DynamicAnalysisJob.Status.CANCELLED


@pytest.mark.django_db
def test_viewer_cannot_cancel_queued_job(django_user_model):
    call_command("bootstrap_roles", verbosity=0)
    user = django_user_model.objects.create_user(
        username="dynamic-job-viewer",
        password=PASSWORD,
    )
    user.groups.add(Group.objects.get(name=VIEWER_GROUP))
    client = APIClient()
    client.force_authenticate(user=user)
    audit, _apk = _make_audit_with_apk("viewer-cancel")
    job = DynamicAnalysisJob.objects.create(audit=audit)

    response = client.post(f"/api/dynamic/jobs/{job.id}/cancel/", {}, format="json")

    assert response.status_code == 403
    job.refresh_from_db()
    assert job.status == DynamicAnalysisJob.Status.QUEUED


def _make_role_user(django_user_model, username: str, group_name: str):
    call_command("bootstrap_roles", verbosity=0)
    user = django_user_model.objects.create_user(username=username)
    user.groups.add(Group.objects.get(name=group_name))
    return user


def _ensure_agent_runtime() -> AgentRuntime:
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
    return runtime


def _agent_status_payload(*, serial: str = "agent-emulator") -> dict:
    return {
        "connected": True,
        "enabled": True,
        "code": "HOST_AGENT_CONNECTED",
        "detail": "Dynamic host agent is connected.",
        "agent": {
            "version": "1.0",
            "dynamic_env_detected": True,
            "adb_path_present": True,
            "serial": serial,
        },
        "device": {
            "serial": serial,
            "state": "device",
            "adb_path_present": True,
            "root_uid": 0,
            "api_level": 35,
            "android_version": "15",
            "abi": "x86_64",
            "selinux": "Enforcing",
            "proxy": ":0",
            "focused_app": "com.android.settings",
        },
    }


def _agent_png(*, width: int = 1080, height: int = 1920) -> bytes:
    return (
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\rIHDR"
        + width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
    )


def _make_audit_with_apk(suffix: str = "default") -> tuple[Audit, APKFile]:
    project = Project.objects.create(name=f"Dynamic project {suffix}")
    audit = Audit.objects.create(project=project, name=f"Dynamic audit {suffix}")
    apk = APKFile.objects.create(
        audit=audit,
        package_name=f"com.example.{suffix}",
        version_name="1.0.0",
    )
    return audit, apk


def _make_pool(suffix: str = "default") -> DynamicDevicePool:
    return DynamicDevicePool.objects.create(
        name=f"Dynamic pool {suffix}",
        slug=f"dynamic-pool-{suffix}",
        max_concurrent_leases=1,
    )


def _make_device(suffix: str = "default") -> DynamicDevice:
    return DynamicDevice.objects.create(
        pool=_make_pool(suffix),
        name=f"Dynamic emulator {suffix}",
        serial=f"emulator-{suffix}",
        kind=DynamicDevice.Kind.EMULATOR,
        host_type=DynamicDevice.HostType.LINUX,
        host_identifier=f"host-{suffix}",
        status=DynamicDevice.Status.AVAILABLE,
        api_level=35,
        android_version="15",
        abi="x86_64",
        avd_name=f"msap-api35-{suffix}",
        is_rooted=True,
        selinux_mode="Enforcing",
        has_frida=True,
        has_mitm_ready=True,
    )


def _make_session(
    *,
    state: str = DynamicSession.State.QUEUED,
    cleanup_status: str = DynamicSession.CleanupStatus.NOT_STARTED,
) -> DynamicSession:
    audit, apk = _make_audit_with_apk()
    device = _make_device()
    job = DynamicAnalysisJob.objects.create(audit=audit, apk=apk)
    lease = create_lease(device=device, audit=audit, job=job, ttl_minutes=30)
    return DynamicSession.objects.create(
        job=job,
        audit=audit,
        apk=apk,
        device=device,
        lease=lease,
        state=state,
        cleanup_status=cleanup_status,
        started_at=timezone.now(),
    )


def _write_test_script(tmp_path, script_name: str, body: str):
    script_path = tmp_path / script_name
    script_path.write_text(f"#!/usr/bin/env sh\n{body}", encoding="utf-8")
    script_path.chmod(0o755)
    return script_path


def _mock_successful_dynamic_script(
    script_name,
    timeout_seconds=None,
    extra_env=None,
) -> DynamicScriptResult:
    markers = {
        "preflight.sh": "PREFLIGHT_RESULT=PASS",
        "restore-instrumented-snapshot.sh": "RESTORE_INSTRUMENTED_SNAPSHOT_RESULT=PASS",
        "refresh-frida-bridge.sh": "FRIDA_BRIDGE_REFRESH_RESULT=PASS",
        "frida-smoke.sh": "FRIDA_SMOKE_RESULT=PASS",
        "mitmproxy-smoke.sh": "MITMPROXY_SMOKE_RESULT=PASS",
        "platform-tls-probe.sh": "PLATFORM_TLS_PROBE_RESULT=PASS",
        "cleanup-runtime-state.sh": "CLEANUP_RUNTIME_STATE_RESULT=PASS",
    }
    return _dynamic_script_result(
        script_name.removesuffix(".sh").replace("-", "_"),
        script_name,
        pass_markers=[markers[script_name]],
        timeout_seconds=timeout_seconds,
    )


def _dynamic_script_result(
    stage_name: str,
    script_name: str,
    *,
    pass_markers: list[str] | None = None,
    fail_markers: list[str] | None = None,
    return_code: int = 0,
    stdout_preview: str | None = None,
    stderr_preview: str = "",
    timed_out: bool = False,
    timeout_seconds: int | None = None,
) -> DynamicScriptResult:
    now = timezone.now()
    markers = pass_markers or fail_markers or []
    return DynamicScriptResult(
        stage_name=stage_name,
        script_name=script_name,
        return_code=return_code,
        stdout_preview=(
            stdout_preview if stdout_preview is not None else "\n".join(markers)
        ),
        stderr_preview=stderr_preview,
        stdout_path=None,
        stderr_path=None,
        started_at=now,
        finished_at=now,
        duration_seconds=1.0,
        pass_markers=pass_markers or [],
        fail_markers=fail_markers or [],
        redaction_applied=False,
        timed_out=timed_out,
        timeout_seconds=timeout_seconds,
    )

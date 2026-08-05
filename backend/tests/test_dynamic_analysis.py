from datetime import timedelta

import pytest
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db import IntegrityError, transaction
from django.utils import timezone
from rest_framework.test import APIClient

from apps.api.roles import VIEWER_GROUP
from apps.apk_files.models import APKFile
from apps.audits.models import Audit
from apps.dynamic_analysis.models import (
    DynamicAnalysisJob,
    DynamicDevice,
    DynamicDeviceEvent,
    DynamicDeviceLease,
    DynamicDevicePool,
    DynamicEmulatorSnapshot,
    DynamicSession,
    DynamicSessionEvent,
)
from apps.dynamic_analysis.services.leases import (
    DynamicLeaseError,
    create_lease,
    heartbeat_lease,
    quarantine_device,
    release_lease,
)
from apps.dynamic_analysis.services.state_machine import (
    DynamicStateTransitionError,
    mark_session_cancelled,
    mark_session_failed,
    transition_session,
)
from apps.projects.models import Project


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


@pytest.mark.django_db
def test_dynamic_api_creates_job(api_client):
    audit, apk = _make_audit_with_apk()

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

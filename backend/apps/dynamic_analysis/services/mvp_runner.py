from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from django.conf import settings
from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from apps.dynamic_analysis.models import (
    DynamicAnalysisJob,
    DynamicDevice,
    DynamicDeviceCapability,
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
    quarantine_device,
    release_lease,
)
from apps.dynamic_analysis.services.local_scripts import (
    DynamicScriptExecutionError,
    DynamicScriptResult,
    get_dynamic_stage_timeout,
    run_dynamic_lab_script,
)
from apps.dynamic_analysis.services.state_machine import (
    DynamicStateTransitionError,
    mark_session_completed,
    mark_session_failed,
    transition_session,
)


class DynamicMvpRunnerError(RuntimeError):
    pass


ProgressCallback = Callable[[str, dict], None]


@dataclass(frozen=True)
class StageDefinition:
    name: str
    script_name: str
    state: str
    artifact_type: str
    failure_category: str
    required: bool = True


REQUIRED_STAGE_SEQUENCE = (
    StageDefinition(
        name="preflight",
        script_name="preflight.sh",
        state=DynamicSession.State.LEASING_DEVICE,
        artifact_type=DynamicSessionArtifact.ArtifactType.DEVICE_STATE,
        failure_category=DynamicAnalysisJob.FailureCategory.DEVICE_UNAVAILABLE,
    ),
    StageDefinition(
        name="restore_instrumented_snapshot",
        script_name="restore-instrumented-snapshot.sh",
        state=DynamicSession.State.RESTORING_BASELINE,
        artifact_type=DynamicSessionArtifact.ArtifactType.DEVICE_STATE,
        failure_category=DynamicAnalysisJob.FailureCategory.SNAPSHOT_RESTORE_FAILED,
    ),
    StageDefinition(
        name="refresh_frida_bridge",
        script_name="refresh-frida-bridge.sh",
        state=DynamicSession.State.PREPARING_DEVICE,
        artifact_type=DynamicSessionArtifact.ArtifactType.DEVICE_STATE,
        failure_category=DynamicAnalysisJob.FailureCategory.FRIDA_START_FAILED,
    ),
    StageDefinition(
        name="frida_smoke",
        script_name="frida-smoke.sh",
        state=DynamicSession.State.STARTING_INSTRUMENTATION,
        artifact_type=DynamicSessionArtifact.ArtifactType.DYNAMIC_SESSION,
        failure_category=DynamicAnalysisJob.FailureCategory.FRIDA_START_FAILED,
    ),
    StageDefinition(
        name="mitmproxy_smoke",
        script_name="mitmproxy-smoke.sh",
        state=DynamicSession.State.STARTING_CAPTURE,
        artifact_type=DynamicSessionArtifact.ArtifactType.DYNAMIC_SESSION,
        failure_category=DynamicAnalysisJob.FailureCategory.PROXY_FAILED,
    ),
)
PLATFORM_TLS_STAGE = StageDefinition(
    name="platform_tls_probe",
    script_name="platform-tls-probe.sh",
    state=DynamicSession.State.COLLECTING_EVIDENCE,
    artifact_type=DynamicSessionArtifact.ArtifactType.TLS_EVENT,
    failure_category=DynamicAnalysisJob.FailureCategory.TLS_INTERCEPTION_FAILED,
)
CLEANUP_STAGE = StageDefinition(
    name="cleanup_runtime_state",
    script_name="cleanup-runtime-state.sh",
    state=DynamicSession.State.CLEANING_UP,
    artifact_type=DynamicSessionArtifact.ArtifactType.DEVICE_STATE,
    failure_category=DynamicAnalysisJob.FailureCategory.CLEANUP_FAILED,
)


def ensure_local_mvp_device() -> DynamicDevice:
    pool, _created = DynamicDevicePool.objects.update_or_create(
        slug=settings.MSAP_DYNAMIC_MVP_DEVICE_POOL_SLUG,
        defaults={
            "name": "Local Android Lab",
            "description": "Single local rooted Android emulator for MSAP dynamic MVP validation.",
            "is_active": True,
            "max_concurrent_leases": 1,
        },
    )

    device, _created = DynamicDevice.objects.get_or_create(
        serial=settings.MSAP_DYNAMIC_MVP_DEVICE_SERIAL,
        defaults={
            "pool": pool,
            "name": settings.MSAP_DYNAMIC_MVP_DEVICE_NAME,
            "kind": DynamicDevice.Kind.EMULATOR,
            "host_type": DynamicDevice.HostType.WINDOWS_WSL,
            "host_identifier": "local-android-lab",
            "status": DynamicDevice.Status.AVAILABLE,
            "api_level": 35,
            "android_version": "15",
            "abi": "x86_64",
            "avd_name": "Lab-Root",
            "is_rooted": True,
            "selinux_mode": "Enforcing",
            "has_frida": True,
            "has_mitm_ready": True,
            "current_snapshot": "msap-instrumented-base",
            "metadata": {"managed_by": "dynamic_mvp_runner"},
        },
    )
    active_lease_exists = DynamicDeviceLease.objects.filter(
        device=device,
        lease_status=DynamicDeviceLease.LeaseStatus.ACTIVE,
    ).exists()
    status = device.status
    quarantine_reason = device.quarantine_reason
    if status != DynamicDevice.Status.QUARANTINED and not active_lease_exists:
        status = DynamicDevice.Status.AVAILABLE
        quarantine_reason = ""

    device.pool = pool
    device.name = settings.MSAP_DYNAMIC_MVP_DEVICE_NAME
    device.kind = DynamicDevice.Kind.EMULATOR
    device.host_type = DynamicDevice.HostType.WINDOWS_WSL
    device.host_identifier = "local-android-lab"
    device.status = status
    device.api_level = 35
    device.android_version = "15"
    device.abi = "x86_64"
    device.avd_name = "Lab-Root"
    device.is_rooted = True
    device.selinux_mode = "Enforcing"
    device.has_frida = True
    device.has_mitm_ready = True
    device.current_snapshot = "msap-instrumented-base"
    device.quarantine_reason = quarantine_reason
    metadata = device.metadata if isinstance(device.metadata, dict) else {}
    metadata["managed_by"] = "dynamic_mvp_runner"
    device.metadata = metadata
    device.save()

    _upsert_capabilities(device)
    _upsert_snapshots(device)
    return device


def create_dynamic_mvp_job(
    audit,
    requested_by=None,
    include_platform_tls_probe: bool = False,
) -> DynamicAnalysisJob:
    device = ensure_local_mvp_device()
    apk = audit.apk_files.order_by("-created_at", "-id").first()
    return DynamicAnalysisJob.objects.create(
        audit=audit,
        apk=apk,
        requested_by=(
            requested_by
            if getattr(requested_by, "is_authenticated", False)
            else None
        ),
        mode=DynamicAnalysisJob.Mode.COMBINED,
        requested_tool_profile=DynamicAnalysisJob.ToolProfile.FULL,
        requested_interaction_mode=DynamicAnalysisJob.InteractionMode.PASSIVE,
        requested_device_pool=device.pool,
        timeout_seconds=settings.MSAP_DYNAMIC_RUNNER_TIMEOUT_SECONDS,
        summary={
            "runner": "dynamic_mvp",
            "include_platform_tls_probe": include_platform_tls_probe,
            "target_apk_execution": False,
            "claim_scope": (
                "Local lab orchestration and platform TLS capability validation only; "
                "no target APK behavioral analysis is performed."
            ),
        },
    )


def run_dynamic_mvp_job(
    job_id: int,
    include_platform_tls_probe: bool = False,
    progress_callback: ProgressCallback | None = None,
) -> dict:
    return DynamicMvpRunner(
        include_platform_tls_probe=include_platform_tls_probe,
        progress_callback=progress_callback,
    ).run(job_id)


def dynamic_mvp_stage_plan(
    *,
    include_platform_tls_probe: bool = False,
) -> list[dict]:
    plan = [_stage_plan_item(stage) for stage in REQUIRED_STAGE_SEQUENCE]
    if include_platform_tls_probe:
        plan.append(_stage_plan_item(PLATFORM_TLS_STAGE))
    else:
        skipped = _stage_plan_item(PLATFORM_TLS_STAGE)
        skipped["required"] = False
        skipped["skipped"] = True
        skipped["skip_reason"] = "platform TLS probe not requested"
        plan.append(skipped)
    plan.append(_stage_plan_item(CLEANUP_STAGE))
    return plan


class DynamicMvpRunner:
    def __init__(
        self,
        *,
        include_platform_tls_probe: bool = False,
        progress_callback: ProgressCallback | None = None,
    ):
        self.include_platform_tls_probe = bool(include_platform_tls_probe)
        self.progress_callback = progress_callback

    def run(self, job_id: int) -> dict:
        if not settings.MSAP_DYNAMIC_RUNNER_ENABLED:
            raise DynamicMvpRunnerError("Dynamic MVP runner is disabled.")
        if (
            self.include_platform_tls_probe
            and not settings.MSAP_DYNAMIC_PLATFORM_TLS_PROBE_ENABLED
        ):
            raise DynamicMvpRunnerError(
                "Platform TLS probe was requested but is disabled by settings."
            )

        ensure_local_mvp_device()
        job = self._start_job(job_id)
        self._emit(
            "job_started",
            job_id=job.id,
            audit_id=job.audit_id,
            include_platform_tls_probe=self.include_platform_tls_probe,
        )
        device = self._get_available_local_device()
        if device is None:
            return self._finish_with_result(
                self._mark_job_failed_without_session(
                    job,
                    DynamicAnalysisJob.FailureCategory.DEVICE_UNAVAILABLE,
                    "Local dynamic MVP device is not available.",
                )
            )

        lease = None
        session = None
        stage_failure: tuple[str, str] | None = None
        cleanup_failed = False
        try:
            try:
                lease = create_lease(
                    device=device,
                    audit=job.audit,
                    job=job,
                    leased_by=job.requested_by,
                    ttl_minutes=max(1, int(job.timeout_seconds / 60)),
                )
            except DynamicLeaseError as exc:
                return self._finish_with_result(
                    self._mark_job_failed_without_session(
                        job,
                        DynamicAnalysisJob.FailureCategory.DEVICE_UNAVAILABLE,
                        str(exc),
                    )
                )

            session = self._create_session(job, device, lease)
            self._emit(
                "session_created",
                job_id=job.id,
                session_id=session.id,
                lease_id=lease.id,
                device_serial=device.serial,
            )
            transition_session(
                session,
                DynamicSession.State.WAITING_FOR_DEVICE,
                reason="Dynamic MVP runner selected the local lab device.",
            )
            transition_session(
                session,
                DynamicSession.State.LEASING_DEVICE,
                reason="Dynamic MVP runner leased the local lab device.",
            )

            for stage in REQUIRED_STAGE_SEQUENCE:
                stage_failure = self._run_required_stage(session, stage)
                if stage_failure is not None:
                    break

            if stage_failure is None:
                transition_session(
                    session,
                    DynamicSession.State.COLLECTING_EVIDENCE,
                    reason="Dynamic MVP runner collected lab smoke evidence.",
                )
                if self.include_platform_tls_probe:
                    stage_failure = self._run_required_stage(
                        session,
                        PLATFORM_TLS_STAGE,
                    )
                else:
                    self._record_skipped_platform_tls_stage(session)

            if stage_failure is None:
                transition_session(
                    session,
                    DynamicSession.State.EVALUATING,
                    reason="Dynamic MVP runner evaluated stage markers.",
                )

            cleanup_failure = self._run_cleanup_stage(session)
            if cleanup_failure is not None:
                cleanup_failed = True
                stage_failure = cleanup_failure

            if stage_failure is None:
                self._finish_session_success(session)
                release_lease(lease, reason="COMPLETED", released_by=job.requested_by)
            else:
                failure_category, failure_message = stage_failure
                if cleanup_failed:
                    quarantine_device(
                        device,
                        reason=failure_message,
                        created_by=job.requested_by,
                        lease=lease,
                    )
                    release_lease(
                        lease,
                        reason="QUARANTINED",
                        released_by=job.requested_by,
                    )
                else:
                    release_lease(lease, reason="FAILED", released_by=job.requested_by)
                self._finish_session_failed(
                    session,
                    failure_category=failure_category,
                    failure_message=failure_message,
                )
        except Exception as exc:
            if session is not None and lease is not None:
                stage_failure = (
                    DynamicAnalysisJob.FailureCategory.UNKNOWN,
                    f"Dynamic MVP runner failed unexpectedly: {exc}",
                )
                if session.state != DynamicSession.State.CLEANING_UP:
                    try:
                        transition_session(
                            session,
                            DynamicSession.State.CLEANING_UP,
                            reason="Dynamic MVP runner entered cleanup after an unexpected failure.",
                        )
                    except DynamicStateTransitionError:
                        pass
                if session.cleanup_status != DynamicSession.CleanupStatus.SUCCEEDED:
                    session.cleanup_status = DynamicSession.CleanupStatus.PARTIAL
                    session.quarantine_required = True
                    session.save(
                        update_fields=[
                            "cleanup_status",
                            "quarantine_required",
                            "updated_at",
                        ]
                    )
                quarantine_device(
                    session.device,
                    reason=stage_failure[1],
                    created_by=job.requested_by,
                    lease=lease,
                )
                release_lease(
                    lease,
                    reason="QUARANTINED",
                    released_by=job.requested_by,
                )
                self._finish_session_failed(
                    session,
                    failure_category=stage_failure[0],
                    failure_message=stage_failure[1],
                )
                return self._finish_with_result(self._result(job.id, session.id))
            if lease is not None:
                release_lease(
                    lease,
                    reason="FAILED",
                    released_by=job.requested_by,
                )
                return self._finish_with_result(
                    self._mark_job_failed_without_session(
                        job,
                        DynamicAnalysisJob.FailureCategory.UNKNOWN,
                        f"Dynamic MVP runner failed before session creation: {exc}",
                    )
                )
            raise

        return self._finish_with_result(
            self._result(job.id, session.id if session is not None else None)
        )

    def _start_job(self, job_id: int) -> DynamicAnalysisJob:
        with transaction.atomic():
            job = (
                DynamicAnalysisJob.objects.select_for_update()
                .select_related("audit", "apk", "requested_by", "requested_device_pool")
                .get(pk=job_id)
            )
            if job.status not in {
                DynamicAnalysisJob.Status.QUEUED,
                DynamicAnalysisJob.Status.RUNNING,
            }:
                raise DynamicMvpRunnerError(
                    f"Dynamic job {job.id} cannot be run from status {job.status}."
                )
            summary = job.summary if isinstance(job.summary, dict) else {}
            summary.update(
                {
                    "runner": "dynamic_mvp",
                    "include_platform_tls_probe": self.include_platform_tls_probe,
                    "target_apk_execution": False,
                }
            )
            job.status = DynamicAnalysisJob.Status.RUNNING
            job.started_at = job.started_at or timezone.now()
            job.finished_at = None
            job.failure_category = ""
            job.failure_message = ""
            job.summary = summary
            job.save(
                update_fields=[
                    "status",
                    "started_at",
                    "finished_at",
                    "failure_category",
                    "failure_message",
                    "summary",
                    "updated_at",
                ]
            )
            return job

    def _get_available_local_device(self) -> DynamicDevice | None:
        return (
            DynamicDevice.objects.select_related("pool")
            .filter(
                serial=settings.MSAP_DYNAMIC_MVP_DEVICE_SERIAL,
                status=DynamicDevice.Status.AVAILABLE,
            )
            .first()
        )

    def _create_session(
        self,
        job: DynamicAnalysisJob,
        device: DynamicDevice,
        lease,
    ) -> DynamicSession:
        snapshot = DynamicEmulatorSnapshot.objects.filter(
            device=device,
            name="msap-instrumented-base",
        ).first()
        return DynamicSession.objects.create(
            job=job,
            audit=job.audit,
            apk=job.apk,
            device=device,
            lease=lease,
            snapshot=snapshot,
            state=DynamicSession.State.QUEUED,
            started_at=timezone.now(),
            tool_versions={
                "frida": "17.16.4",
                "mitmproxy": "12.2.3",
                "android_api": 35,
                "abi": "x86_64",
            },
            network_capture_enabled=True,
            frida_enabled=True,
            runtime_ca_enabled=self.include_platform_tls_probe,
            ui_automation_enabled=False,
            summary={
                "runner": "dynamic_mvp",
                "target_apk_execution": False,
            },
        )

    def _run_required_stage(
        self,
        session: DynamicSession,
        stage_def: StageDefinition,
    ) -> tuple[str, str] | None:
        timeout_seconds = get_dynamic_stage_timeout(stage_def.name)
        session.refresh_from_db(fields=["state"])
        if session.state != stage_def.state:
            transition_session(
                session,
                stage_def.state,
                reason=f"Dynamic MVP stage started: {stage_def.name}.",
            )
            session.state = stage_def.state
        stage = DynamicSessionStage.objects.create(
            session=session,
            name=stage_def.name,
            state=stage_def.state,
            status=DynamicSessionStage.StageStatus.RUNNING,
            started_at=timezone.now(),
            message=f"Running {stage_def.script_name}.",
            metadata={
                "script_name": stage_def.script_name,
                "required": stage_def.required,
                "timeout_seconds": timeout_seconds,
            },
        )
        self._emit(
            "stage_started",
            job_id=session.job_id,
            session_id=session.id,
            stage_id=stage.id,
            stage=stage_def.name,
            script_name=stage_def.script_name,
            timeout_seconds=timeout_seconds,
        )
        self._create_session_event(
            session,
            DynamicSessionEvent.EventType.ARTIFACT,
            f"Dynamic MVP stage running: {stage_def.name}.",
            metadata={
                "stage": stage_def.name,
                "script_name": stage_def.script_name,
                "timeout_seconds": timeout_seconds,
            },
        )
        try:
            result = run_dynamic_lab_script(
                stage_def.script_name,
                timeout_seconds=timeout_seconds,
                extra_env=self._script_env(session, stage_def),
            )
        except DynamicScriptExecutionError as exc:
            result = exc.result or _empty_failed_result(stage_def, str(exc))
            message = str(exc)
            self._finish_stage(stage, result, DynamicSessionStage.StageStatus.FAILED, message)
            self._create_artifact(
                session=session,
                stage_def=stage_def,
                result=result,
                status=DynamicSessionStage.StageStatus.FAILED,
                manual_validation_required=True,
                summary=f"{stage_def.name} failed: {message}",
            )
            self._create_session_event(
                session,
                DynamicSessionEvent.EventType.ERROR,
                f"Dynamic MVP stage failed: {stage_def.name}.",
                severity=DynamicSessionEvent.Severity.ERROR,
                metadata={
                    "stage": stage_def.name,
                    "script_name": stage_def.script_name,
                    "return_code": result.return_code,
                    "pass_markers": result.pass_markers,
                    "fail_markers": result.fail_markers,
                    "timed_out": result.timed_out,
                },
            )
            self._emit_stage_result(
                "stage_failed",
                session=session,
                stage=stage,
                stage_def=stage_def,
                result=result,
                message=message,
                status=DynamicSessionStage.StageStatus.FAILED,
            )
            return stage_def.failure_category, message
        except Exception as exc:
            result = _empty_failed_result(stage_def, str(exc))
            message = f"Dynamic MVP stage failed unexpectedly: {exc}"
            self._finish_stage(
                stage,
                result,
                DynamicSessionStage.StageStatus.FAILED,
                message,
            )
            self._create_artifact(
                session=session,
                stage_def=stage_def,
                result=result,
                status=DynamicSessionStage.StageStatus.FAILED,
                manual_validation_required=True,
                summary=f"{stage_def.name} failed unexpectedly: {exc}",
            )
            self._create_session_event(
                session,
                DynamicSessionEvent.EventType.ERROR,
                f"Dynamic MVP stage failed unexpectedly: {stage_def.name}.",
                severity=DynamicSessionEvent.Severity.ERROR,
                metadata={
                    "stage": stage_def.name,
                    "script_name": stage_def.script_name,
                    "error": str(exc),
                },
            )
            self._emit_stage_result(
                "stage_failed",
                session=session,
                stage=stage,
                stage_def=stage_def,
                result=result,
                message=message,
                status=DynamicSessionStage.StageStatus.FAILED,
            )
            return stage_def.failure_category, message

        if not result.pass_markers:
            message = (
                "Dynamic lab script completed without PASS marker: "
                f"{stage_def.script_name}"
            )
            self._finish_stage(stage, result, DynamicSessionStage.StageStatus.FAILED, message)
            self._create_artifact(
                session=session,
                stage_def=stage_def,
                result=result,
                status=DynamicSessionStage.StageStatus.FAILED,
                manual_validation_required=True,
                summary=f"{stage_def.name} failed: no PASS marker.",
            )
            self._create_session_event(
                session,
                DynamicSessionEvent.EventType.ERROR,
                f"Dynamic MVP stage lacked PASS marker: {stage_def.name}.",
                severity=DynamicSessionEvent.Severity.ERROR,
                metadata={
                    "stage": stage_def.name,
                    "script_name": stage_def.script_name,
                },
            )
            self._emit_stage_result(
                "stage_failed",
                session=session,
                stage=stage,
                stage_def=stage_def,
                result=result,
                message=message,
                status=DynamicSessionStage.StageStatus.FAILED,
            )
            return stage_def.failure_category, message

        self._finish_stage(
            stage,
            result,
            DynamicSessionStage.StageStatus.SUCCEEDED,
            f"{stage_def.name} passed.",
        )
        self._create_artifact(
            session=session,
            stage_def=stage_def,
            result=result,
            status=DynamicSessionStage.StageStatus.SUCCEEDED,
            manual_validation_required=False,
            summary=f"{stage_def.name} passed with {', '.join(result.pass_markers)}.",
        )
        self._create_session_event(
            session,
            DynamicSessionEvent.EventType.ARTIFACT,
            f"Dynamic MVP stage passed: {stage_def.name}.",
            metadata={
                "stage": stage_def.name,
                "script_name": stage_def.script_name,
                "return_code": result.return_code,
                "pass_markers": result.pass_markers,
            },
        )
        self._emit_stage_result(
            "stage_succeeded",
            session=session,
            stage=stage,
            stage_def=stage_def,
            result=result,
            message=f"{stage_def.name} passed.",
            status=DynamicSessionStage.StageStatus.SUCCEEDED,
        )
        return None

    def _record_skipped_platform_tls_stage(self, session: DynamicSession) -> None:
        timeout_seconds = get_dynamic_stage_timeout(PLATFORM_TLS_STAGE.name)
        stage = DynamicSessionStage.objects.create(
            session=session,
            name=PLATFORM_TLS_STAGE.name,
            state=PLATFORM_TLS_STAGE.state,
            status=DynamicSessionStage.StageStatus.SKIPPED,
            started_at=timezone.now(),
            finished_at=timezone.now(),
            duration_seconds=0,
            message="Platform TLS probe skipped by configuration.",
            metadata={
                "script_name": PLATFORM_TLS_STAGE.script_name,
                "required": False,
                "timeout_seconds": timeout_seconds,
                "reason": "MSAP_DYNAMIC_PLATFORM_TLS_PROBE_ENABLED is false or the probe was not requested.",
            },
        )
        self._emit(
            "stage_skipped",
            job_id=session.job_id,
            session_id=session.id,
            stage_id=stage.id,
            stage=PLATFORM_TLS_STAGE.name,
            script_name=PLATFORM_TLS_STAGE.script_name,
            timeout_seconds=timeout_seconds,
            message=stage.message,
        )
        result = _empty_skipped_result(PLATFORM_TLS_STAGE)
        self._create_artifact(
            session=session,
            stage_def=PLATFORM_TLS_STAGE,
            result=result,
            status=DynamicSessionStage.StageStatus.SKIPPED,
            manual_validation_required=True,
            summary=(
                "Platform TLS probe skipped. MVP run validates orchestration, Frida, "
                "and mitmproxy smoke checks but does not store platform TLS proof."
            ),
        )
        self._create_session_event(
            session,
            DynamicSessionEvent.EventType.ARTIFACT,
            "Dynamic MVP platform TLS probe skipped.",
            severity=DynamicSessionEvent.Severity.WARNING,
            metadata={"stage": stage.name, "script_name": PLATFORM_TLS_STAGE.script_name},
        )

    def _run_cleanup_stage(self, session: DynamicSession) -> tuple[str, str] | None:
        session.refresh_from_db(fields=["state", "cleanup_status"])
        if session.state != DynamicSession.State.CLEANING_UP:
            transition_session(
                session,
                DynamicSession.State.CLEANING_UP,
                reason="Dynamic MVP runner cleaning up runtime state.",
            )
            session.state = DynamicSession.State.CLEANING_UP
        session.cleanup_status = DynamicSession.CleanupStatus.IN_PROGRESS
        session.save(update_fields=["cleanup_status", "updated_at"])
        cleanup_failure = self._run_required_stage(session, CLEANUP_STAGE)
        if cleanup_failure is None:
            session.cleanup_status = DynamicSession.CleanupStatus.SUCCEEDED
            session.save(update_fields=["cleanup_status", "updated_at"])
            self._create_session_event(
                session,
                DynamicSessionEvent.EventType.CLEANUP,
                "Dynamic MVP cleanup completed.",
            )
            return None

        session.cleanup_status = DynamicSession.CleanupStatus.FAILED
        session.quarantine_required = True
        session.save(
            update_fields=["cleanup_status", "quarantine_required", "updated_at"]
        )
        self._create_session_event(
            session,
            DynamicSessionEvent.EventType.CLEANUP,
            "Dynamic MVP cleanup failed; quarantine required.",
            severity=DynamicSessionEvent.Severity.ERROR,
        )
        return cleanup_failure

    def _finish_stage(
        self,
        stage: DynamicSessionStage,
        result: DynamicScriptResult,
        status: str,
        message: str,
    ) -> None:
        metadata = stage.metadata if isinstance(stage.metadata, dict) else {}
        timeout_seconds = result.timeout_seconds or metadata.get("timeout_seconds")
        stage.status = status
        stage.finished_at = timezone.now()
        stage.duration_seconds = int(result.duration_seconds)
        stage.message = message
        stage.metadata = {
            **metadata,
            "return_code": result.return_code,
            "duration_seconds": result.duration_seconds,
            "pass_markers": result.pass_markers,
            "fail_markers": result.fail_markers,
            "timed_out": result.timed_out,
            "timeout_seconds": timeout_seconds,
        }
        stage.save(
            update_fields=[
                "status",
                "finished_at",
                "duration_seconds",
                "message",
                "metadata",
                "updated_at",
            ]
        )

    def _create_artifact(
        self,
        *,
        session: DynamicSession,
        stage_def: StageDefinition,
        result: DynamicScriptResult,
        status: str,
        manual_validation_required: bool,
        summary: str,
    ) -> DynamicSessionArtifact:
        pass_markers = result.pass_markers
        confidence = (
            DynamicSessionArtifact.Confidence.HIGH
            if pass_markers
            else DynamicSessionArtifact.Confidence.LOW
        )
        return DynamicSessionArtifact.objects.create(
            session=session,
            artifact_type=stage_def.artifact_type,
            category="dynamic_mvp_runner",
            name=f"{stage_def.name} evidence summary",
            summary=summary,
            normalized={
                "stage_name": stage_def.name,
                "script_name": result.script_name,
                "status": status,
                "return_code": result.return_code,
                "duration_seconds": result.duration_seconds,
                "timeout_seconds": result.timeout_seconds,
                "timed_out": result.timed_out,
                "markers": {
                    "pass": pass_markers,
                    "fail": result.fail_markers,
                },
                "stdout_preview": result.stdout_preview,
                "stderr_preview": result.stderr_preview,
                "target_apk_execution": False,
            },
            redaction_state=(
                DynamicSessionArtifact.RedactionState.REDACTED
                if result.redaction_applied
                else DynamicSessionArtifact.RedactionState.NOT_REQUIRED
            ),
            confidence=confidence,
            manual_validation_required=manual_validation_required,
            correlation_keys=["dynamic_mvp_runner", stage_def.name],
            sequence_number=self._next_artifact_sequence(session),
        )

    def _finish_session_success(self, session: DynamicSession) -> None:
        summary = session.summary if isinstance(session.summary, dict) else {}
        summary.update(
            {
                "runner": "dynamic_mvp",
                "result": "passed",
                "target_apk_execution": False,
                "artifact_count": session.artifacts.count(),
                "stage_count": session.stages.count(),
            }
        )
        mark_session_completed(session, summary=summary)

    def _finish_session_failed(
        self,
        session: DynamicSession,
        *,
        failure_category: str,
        failure_message: str,
    ) -> None:
        mark_session_failed(
            session,
            category=failure_category,
            message=failure_message,
        )

    def _mark_job_failed_without_session(
        self,
        job: DynamicAnalysisJob,
        category: str,
        message: str,
    ) -> dict:
        job.status = DynamicAnalysisJob.Status.FAILED
        job.failure_category = category
        job.failure_message = message
        job.finished_at = timezone.now()
        job.save(
            update_fields=[
                "status",
                "failure_category",
                "failure_message",
                "finished_at",
                "updated_at",
            ]
        )
        return self._result(job.id, None)

    def _result(self, job_id: int, session_id: int | None) -> dict:
        job = DynamicAnalysisJob.objects.get(pk=job_id)
        session = DynamicSession.objects.filter(pk=session_id).first()
        return {
            "job_id": job.id,
            "session_id": session.id if session is not None else None,
            "job_status": job.status,
            "session_state": session.state if session is not None else None,
            "artifacts_count": (
                session.artifacts.count() if session is not None else 0
            ),
            "stages_count": session.stages.count() if session is not None else 0,
            "failure_category": job.failure_category,
            "failure_message": job.failure_message,
            "cleanup_status": session.cleanup_status if session is not None else None,
        }

    def _finish_with_result(self, result: dict) -> dict:
        self._emit("runner_finished", **result)
        return result

    def _emit(self, event: str, **payload) -> None:
        if self.progress_callback is not None:
            self.progress_callback(event, payload)

    def _emit_stage_result(
        self,
        event: str,
        *,
        session: DynamicSession,
        stage: DynamicSessionStage,
        stage_def: StageDefinition,
        result: DynamicScriptResult,
        message: str,
        status: str,
    ) -> None:
        self._emit(
            event,
            job_id=session.job_id,
            session_id=session.id,
            stage_id=stage.id,
            stage=stage_def.name,
            script_name=stage_def.script_name,
            timeout_seconds=(
                result.timeout_seconds
                or (stage.metadata if isinstance(stage.metadata, dict) else {}).get(
                    "timeout_seconds"
                )
            ),
            status=status,
            return_code=result.return_code,
            duration_seconds=result.duration_seconds,
            pass_markers=result.pass_markers,
            fail_markers=result.fail_markers,
            timed_out=result.timed_out,
            stdout_preview=result.stdout_preview,
            stderr_preview=result.stderr_preview,
            message=message,
        )

    def _script_env(
        self,
        session: DynamicSession,
        stage_def: StageDefinition,
    ) -> dict[str, str]:
        return {
            "MSAP_DYNAMIC_RUNNER_ENABLED": "true",
            "MSAP_ANDROID_SERIAL": session.device.serial,
            "MSAP_DYNAMIC_JOB_ID": str(session.job_id),
            "MSAP_DYNAMIC_SESSION_ID": str(session.id),
            "MSAP_DYNAMIC_STAGE_NAME": stage_def.name,
        }

    def _create_session_event(
        self,
        session: DynamicSession,
        event_type: str,
        message: str,
        *,
        severity: str = DynamicSessionEvent.Severity.INFO,
        metadata: dict | None = None,
    ) -> DynamicSessionEvent:
        return DynamicSessionEvent.objects.create(
            session=session,
            event_type=event_type,
            severity=severity,
            message=message,
            sequence_number=self._next_event_sequence(session),
            metadata=metadata or {},
        )

    def _next_event_sequence(self, session: DynamicSession) -> int:
        return (
            DynamicSessionEvent.objects.filter(session=session).aggregate(
                value=Max("sequence_number")
            )["value"]
            or 0
        ) + 1

    def _next_artifact_sequence(self, session: DynamicSession) -> int:
        return (
            DynamicSessionArtifact.objects.filter(session=session).aggregate(
                value=Max("sequence_number")
            )["value"]
            or 0
        ) + 1


def _stage_plan_item(stage: StageDefinition) -> dict:
    return {
        "stage": stage.name,
        "script_name": stage.script_name,
        "state": stage.state,
        "required": stage.required,
        "skipped": False,
        "timeout_seconds": get_dynamic_stage_timeout(stage.name),
    }


def _upsert_capabilities(device: DynamicDevice) -> None:
    capabilities = (
        (DynamicDeviceCapability.CapabilityType.ADB, "adb", ""),
        (DynamicDeviceCapability.CapabilityType.ROOT, "root", ""),
        (DynamicDeviceCapability.CapabilityType.FRIDA, "frida", "17.16.4"),
        (
            DynamicDeviceCapability.CapabilityType.MITMPROXY_ROUTE,
            "mitmproxy",
            "12.2.3",
        ),
        (DynamicDeviceCapability.CapabilityType.RUNTIME_CA, "runtime-ca", ""),
        (
            DynamicDeviceCapability.CapabilityType.SNAPSHOT,
            "msap-instrumented-base",
            "",
        ),
        (
            DynamicDeviceCapability.CapabilityType.NETWORK_CAPTURE,
            "network-capture",
            "",
        ),
    )
    for capability_type, name, version in capabilities:
        DynamicDeviceCapability.objects.update_or_create(
            device=device,
            capability_type=capability_type,
            name=name,
            defaults={
                "version": version,
                "is_available": True,
                "details": {"managed_by": "dynamic_mvp_runner"},
                "checked_at": timezone.now(),
            },
        )


def _upsert_snapshots(device: DynamicDevice) -> None:
    snapshots = (
        (
            "msap-clean-base",
            DynamicEmulatorSnapshot.SnapshotType.CLEAN_BASE,
            False,
            False,
        ),
        (
            "msap-instrumented-base",
            DynamicEmulatorSnapshot.SnapshotType.INSTRUMENTED_BASE,
            True,
            True,
        ),
    )
    for name, snapshot_type, contains_frida, contains_public_ca in snapshots:
        DynamicEmulatorSnapshot.objects.update_or_create(
            device=device,
            name=name,
            defaults={
                "snapshot_type": snapshot_type,
                "description": f"Local dynamic MVP {name} snapshot.",
                "api_level": 35,
                "abi": "x86_64",
                "contains_frida_binary": contains_frida,
                "contains_public_ca": contains_public_ca,
                "contains_target_apk": False,
                "validation_status": DynamicEmulatorSnapshot.ValidationStatus.VALID,
                "validated_at": timezone.now(),
                "metadata": {"managed_by": "dynamic_mvp_runner"},
            },
        )


def _empty_failed_result(
    stage_def: StageDefinition,
    error_message: str,
) -> DynamicScriptResult:
    now = timezone.now()
    return DynamicScriptResult(
        stage_name=stage_def.name,
        script_name=stage_def.script_name,
        return_code=-1,
        stdout_preview="",
        stderr_preview=error_message,
        stdout_path=None,
        stderr_path=None,
        started_at=now,
        finished_at=now,
        duration_seconds=0.0,
        pass_markers=[],
        fail_markers=[],
        redaction_applied=False,
    )


def _empty_skipped_result(stage_def: StageDefinition) -> DynamicScriptResult:
    now = timezone.now()
    return DynamicScriptResult(
        stage_name=stage_def.name,
        script_name=stage_def.script_name,
        return_code=0,
        stdout_preview="",
        stderr_preview="",
        stdout_path=None,
        stderr_path=None,
        started_at=now,
        finished_at=now,
        duration_seconds=0.0,
        pass_markers=[],
        fail_markers=[],
        redaction_applied=False,
    )

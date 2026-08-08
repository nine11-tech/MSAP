from __future__ import annotations

from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from apps.dynamic_analysis.models import (
    DynamicAnalysisJob,
    DynamicDeviceLease,
    DynamicSession,
    DynamicSessionStage,
)
from apps.dynamic_analysis.services.leases import quarantine_device, release_lease
from apps.dynamic_analysis.services.state_machine import mark_session_failed


TERMINAL_JOB_STATUSES = {
    DynamicAnalysisJob.Status.COMPLETED,
    DynamicAnalysisJob.Status.FAILED,
    DynamicAnalysisJob.Status.CANCELLED,
}


class DynamicJobControlError(ValueError):
    pass


def cancel_queued_job(job: DynamicAnalysisJob, *, requested_by=None) -> DynamicAnalysisJob:
    with transaction.atomic():
        job = DynamicAnalysisJob.objects.select_for_update().get(pk=job.pk)
        if job.status in TERMINAL_JOB_STATUSES:
            return job
        if job.status != DynamicAnalysisJob.Status.QUEUED:
            raise DynamicJobControlError(
                "Only queued jobs can be cancelled directly. Use stale-job recovery "
                "for an abandoned running job."
            )
        now = timezone.now()
        summary = job.summary if isinstance(job.summary, dict) else {}
        summary = {
            **summary,
            "cancellation": {
                "at": now.isoformat(),
                "source": "operator",
                "requested_by_user_id": getattr(requested_by, "pk", None),
            },
        }
        job.status = DynamicAnalysisJob.Status.CANCELLED
        job.failure_category = DynamicAnalysisJob.FailureCategory.OPERATOR_CANCELLED
        job.failure_message = "Dynamic analysis job cancelled before worker execution."
        job.finished_at = now
        job.summary = summary
        job.save(
            update_fields=[
                "status",
                "failure_category",
                "failure_message",
                "finished_at",
                "summary",
                "updated_at",
            ]
        )
        return job


def recover_stale_dynamic_jobs(*, older_than_minutes: int, limit: int = 100) -> dict:
    if older_than_minutes < 1 or older_than_minutes > 1440:
        raise DynamicJobControlError(
            "older_than_minutes must be between 1 and 1440."
        )
    if limit < 1 or limit > 500:
        raise DynamicJobControlError("limit must be between 1 and 500.")

    now = timezone.now()
    cutoff = now - timedelta(minutes=older_than_minutes)
    candidate_ids = list(
        DynamicAnalysisJob.objects.filter(
            status__in=[
                DynamicAnalysisJob.Status.QUEUED,
                DynamicAnalysisJob.Status.RUNNING,
            ],
            updated_at__lt=cutoff,
        )
        .order_by("updated_at", "id")
        .values_list("id", flat=True)[:limit]
    )
    recovered: list[int] = []
    skipped_active_window: list[int] = []

    for job_id in candidate_ids:
        job = DynamicAnalysisJob.objects.get(pk=job_id)
        if job.status == DynamicAnalysisJob.Status.QUEUED:
            cancel_queued_job(job)
            recovered.append(job.id)
            continue

        started_at = job.started_at or job.updated_at
        safe_running_age = max(
            timedelta(minutes=older_than_minutes),
            timedelta(seconds=job.timeout_seconds),
        )
        if now - started_at < safe_running_age:
            skipped_active_window.append(job.id)
            continue
        _recover_abandoned_running_job(job, now=now)
        recovered.append(job.id)

    return {
        "older_than_minutes": older_than_minutes,
        "candidate_count": len(candidate_ids),
        "recovered_count": len(recovered),
        "recovered_job_ids": recovered,
        "skipped_running_within_timeout_job_ids": skipped_active_window,
    }


def _recover_abandoned_running_job(job: DynamicAnalysisJob, *, now) -> None:
    reason = (
        "Dynamic job exceeded its worker heartbeat/timeout recovery window. "
        "Runtime cleanup could not be proven, so any leased device was quarantined."
    )
    session = (
        DynamicSession.objects.filter(job=job)
        .exclude(
            state__in=[
                DynamicSession.State.COMPLETED,
                DynamicSession.State.FAILED,
                DynamicSession.State.CANCELLED,
                DynamicSession.State.QUARANTINED,
            ]
        )
        .select_related("device", "lease")
        .order_by("-created_at", "-id")
        .first()
    )
    if session is None:
        DynamicAnalysisJob.objects.filter(
            pk=job.pk,
            status=DynamicAnalysisJob.Status.RUNNING,
        ).update(
            status=DynamicAnalysisJob.Status.FAILED,
            failure_category=DynamicAnalysisJob.FailureCategory.TIMEOUT,
            failure_message=reason,
            finished_at=now,
            updated_at=now,
        )
        return

    DynamicSessionStage.objects.filter(
        session=session,
        status=DynamicSessionStage.StageStatus.RUNNING,
    ).update(
        status=DynamicSessionStage.StageStatus.FAILED,
        finished_at=now,
        message="Stage abandoned because the worker stopped responding.",
        updated_at=now,
    )
    DynamicSessionStage.objects.filter(
        session=session,
        status=DynamicSessionStage.StageStatus.PENDING,
    ).update(
        status=DynamicSessionStage.StageStatus.CANCELLED,
        finished_at=now,
        message="Stage cancelled during stale-job recovery.",
        updated_at=now,
    )
    session.cleanup_status = DynamicSession.CleanupStatus.PARTIAL
    session.quarantine_required = True
    session.save(
        update_fields=["cleanup_status", "quarantine_required", "updated_at"]
    )

    quarantine_device(
        session.device,
        reason=reason,
        created_by=job.requested_by,
        lease=session.lease,
    )
    if session.lease.lease_status == DynamicDeviceLease.LeaseStatus.ACTIVE:
        release_lease(
            session.lease,
            reason="QUARANTINED",
            released_by=job.requested_by,
        )
    mark_session_failed(
        session,
        category=DynamicAnalysisJob.FailureCategory.TIMEOUT,
        message=reason,
    )

from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from apps.dynamic_analysis.models import (
    DynamicAnalysisJob,
    DynamicSession,
    DynamicSessionEvent,
)


class DynamicStateTransitionError(ValueError):
    pass


TERMINAL_STATES = {
    DynamicSession.State.COMPLETED,
    DynamicSession.State.FAILED,
    DynamicSession.State.CANCELLED,
    DynamicSession.State.QUARANTINED,
}

VALID_TRANSITIONS = {
    DynamicSession.State.QUEUED: {
        DynamicSession.State.WAITING_FOR_DEVICE,
        DynamicSession.State.CANCELLED,
        DynamicSession.State.FAILED,
    },
    DynamicSession.State.WAITING_FOR_DEVICE: {
        DynamicSession.State.LEASING_DEVICE,
        DynamicSession.State.CANCELLED,
        DynamicSession.State.FAILED,
    },
    DynamicSession.State.LEASING_DEVICE: {
        DynamicSession.State.RESTORING_BASELINE,
        DynamicSession.State.WAITING_FOR_DEVICE,
        DynamicSession.State.CANCELLED,
        DynamicSession.State.FAILED,
        DynamicSession.State.CLEANING_UP,
    },
    DynamicSession.State.RESTORING_BASELINE: {
        DynamicSession.State.PREPARING_DEVICE,
        DynamicSession.State.CLEANING_UP,
    },
    DynamicSession.State.PREPARING_DEVICE: {
        DynamicSession.State.INSTALLING_APK,
        DynamicSession.State.STARTING_CAPTURE,
        DynamicSession.State.STARTING_INSTRUMENTATION,
        DynamicSession.State.CLEANING_UP,
    },
    DynamicSession.State.INSTALLING_APK: {
        DynamicSession.State.STARTING_CAPTURE,
        DynamicSession.State.STARTING_INSTRUMENTATION,
        DynamicSession.State.LAUNCHING_APP,
        DynamicSession.State.CLEANING_UP,
    },
    DynamicSession.State.STARTING_CAPTURE: {
        DynamicSession.State.STARTING_INSTRUMENTATION,
        DynamicSession.State.LAUNCHING_APP,
        DynamicSession.State.COLLECTING_EVIDENCE,
        DynamicSession.State.CLEANING_UP,
    },
    DynamicSession.State.STARTING_INSTRUMENTATION: {
        DynamicSession.State.STARTING_CAPTURE,
        DynamicSession.State.LAUNCHING_APP,
        DynamicSession.State.COLLECTING_EVIDENCE,
        DynamicSession.State.CLEANING_UP,
    },
    DynamicSession.State.LAUNCHING_APP: {
        DynamicSession.State.EXERCISING_APP,
        DynamicSession.State.COLLECTING_EVIDENCE,
        DynamicSession.State.CLEANING_UP,
    },
    DynamicSession.State.EXERCISING_APP: {
        DynamicSession.State.COLLECTING_EVIDENCE,
        DynamicSession.State.CLEANING_UP,
    },
    DynamicSession.State.COLLECTING_EVIDENCE: {
        DynamicSession.State.EVALUATING,
        DynamicSession.State.CLEANING_UP,
    },
    DynamicSession.State.EVALUATING: {
        DynamicSession.State.REPORTING,
        DynamicSession.State.CLEANING_UP,
    },
    DynamicSession.State.REPORTING: {
        DynamicSession.State.CLEANING_UP,
    },
    DynamicSession.State.CLEANING_UP: {
        DynamicSession.State.COMPLETED,
        DynamicSession.State.FAILED,
        DynamicSession.State.CANCELLED,
        DynamicSession.State.QUARANTINED,
    },
    DynamicSession.State.COMPLETED: set(),
    DynamicSession.State.FAILED: set(),
    DynamicSession.State.CANCELLED: set(),
    DynamicSession.State.QUARANTINED: set(),
}


def can_transition(current_state: str, new_state: str) -> bool:
    return new_state in VALID_TRANSITIONS.get(current_state, set())


def transition_session(
    session: DynamicSession,
    new_state: str,
    *,
    reason: str | None = None,
) -> DynamicSession:
    if new_state not in DynamicSession.State.values:
        raise DynamicStateTransitionError(f"Unknown dynamic session state: {new_state}")

    invalid_event = None
    with transaction.atomic():
        session = DynamicSession.objects.select_for_update().get(pk=session.pk)
        current_state = session.state
        validation_error = _transition_validation_error(
            session,
            new_state,
            reason=reason,
        )
        if validation_error:
            invalid_event = (
                session,
                validation_error,
                {"from_state": current_state, "to_state": new_state},
            )
        else:
            session.state = new_state
            session.state_reason = reason or ""
            update_fields = ["state", "state_reason", "updated_at"]
            if new_state in TERMINAL_STATES:
                session.finished_at = timezone.now()
                update_fields.append("finished_at")
                if session.started_at is not None:
                    duration = session.finished_at - session.started_at
                    session.duration_seconds = max(0, int(duration.total_seconds()))
                    update_fields.append("duration_seconds")
            session.save(update_fields=update_fields)
            _record_session_event(
                session,
                DynamicSessionEvent.EventType.STATE_TRANSITION,
                reason or f"Transitioned from {current_state} to {new_state}.",
                metadata={"from_state": current_state, "to_state": new_state},
            )

    if invalid_event is not None:
        invalid_session, validation_error, metadata = invalid_event
        _record_session_event(
            invalid_session,
            DynamicSessionEvent.EventType.INVALID_TRANSITION,
            validation_error,
            severity=DynamicSessionEvent.Severity.ERROR,
            metadata=metadata,
        )
        raise DynamicStateTransitionError(validation_error)
    return session


def mark_session_failed(
    session: DynamicSession,
    *,
    category: str,
    message: str,
) -> DynamicSession:
    if category not in DynamicAnalysisJob.FailureCategory.values:
        raise DynamicStateTransitionError(f"Unknown failure category: {category}")

    terminal_state = _terminal_failure_state(session)
    with transaction.atomic():
        session = DynamicSession.objects.select_for_update().select_related("job").get(
            pk=session.pk
        )
        session.job.status = DynamicAnalysisJob.Status.FAILED
        session.job.failure_category = category
        session.job.failure_message = message
        session.job.finished_at = timezone.now()
        session.job.save(
            update_fields=[
                "status",
                "failure_category",
                "failure_message",
                "finished_at",
                "updated_at",
            ]
        )
        session.summary = _summary_with_failure(session.summary, category, message)
        session.save(update_fields=["summary", "updated_at"])

    transitioned = transition_session(session, terminal_state, reason=message)
    _record_session_event(
        transitioned,
        DynamicSessionEvent.EventType.SESSION_FAILED,
        message,
        severity=DynamicSessionEvent.Severity.ERROR,
        metadata={"failure_category": category},
    )
    return transitioned


def mark_session_cancelled(
    session: DynamicSession,
    *,
    reason: str,
) -> DynamicSession:
    terminal_state = _terminal_cancel_state(session)
    with transaction.atomic():
        session = DynamicSession.objects.select_for_update().select_related("job").get(
            pk=session.pk
        )
        session.job.status = DynamicAnalysisJob.Status.CANCELLED
        session.job.failure_category = DynamicAnalysisJob.FailureCategory.OPERATOR_CANCELLED
        session.job.failure_message = reason
        session.job.finished_at = timezone.now()
        session.job.save(
            update_fields=[
                "status",
                "failure_category",
                "failure_message",
                "finished_at",
                "updated_at",
            ]
        )
        summary = session.summary if isinstance(session.summary, dict) else {}
        summary["cancellation_reason"] = reason
        session.summary = summary
        session.save(update_fields=["summary", "updated_at"])

    transitioned = transition_session(session, terminal_state, reason=reason)
    _record_session_event(
        transitioned,
        DynamicSessionEvent.EventType.SESSION_CANCELLED,
        reason,
        severity=DynamicSessionEvent.Severity.WARNING,
    )
    return transitioned


def mark_session_completed(
    session: DynamicSession,
    *,
    summary: dict | None = None,
) -> DynamicSession:
    if summary is not None and not isinstance(summary, dict):
        raise DynamicStateTransitionError("Session summary must be an object.")
    with transaction.atomic():
        session = DynamicSession.objects.select_for_update().select_related("job").get(
            pk=session.pk
        )
        if summary is not None:
            session.summary = summary
            session.save(update_fields=["summary", "updated_at"])
        session.job.status = DynamicAnalysisJob.Status.COMPLETED
        session.job.finished_at = timezone.now()
        session.job.save(update_fields=["status", "finished_at", "updated_at"])

    transitioned = transition_session(
        session,
        DynamicSession.State.COMPLETED,
        reason="Dynamic session completed.",
    )
    _record_session_event(
        transitioned,
        DynamicSessionEvent.EventType.SESSION_COMPLETED,
        "Dynamic session completed.",
        metadata={"summary": summary or {}},
    )
    return transitioned


def _transition_validation_error(
    session: DynamicSession,
    new_state: str,
    *,
    reason: str | None = None,
) -> str:
    if session.state in TERMINAL_STATES:
        return f"Terminal state {session.state} cannot transition to {new_state}."
    if not can_transition(session.state, new_state):
        return f"Invalid transition from {session.state} to {new_state}."
    if (
        new_state == DynamicSession.State.COMPLETED
        and session.cleanup_status != DynamicSession.CleanupStatus.SUCCEEDED
    ):
        return "COMPLETED requires cleanup_status SUCCEEDED."
    if new_state in {DynamicSession.State.FAILED, DynamicSession.State.CANCELLED}:
        if session.cleanup_status != DynamicSession.CleanupStatus.SUCCEEDED:
            return f"{new_state} requires cleanup_status SUCCEEDED."
    if new_state == DynamicSession.State.QUARANTINED:
        if not (
            session.cleanup_status
            in {
                DynamicSession.CleanupStatus.FAILED,
                DynamicSession.CleanupStatus.PARTIAL,
            }
            or session.quarantine_required
            or session.state_reason
            or reason
        ):
            return "QUARANTINED requires failed cleanup or explicit quarantine context."
    return ""


def _terminal_failure_state(session: DynamicSession) -> str:
    session.refresh_from_db(fields=["cleanup_status", "quarantine_required"])
    if session.cleanup_status in {
        DynamicSession.CleanupStatus.FAILED,
        DynamicSession.CleanupStatus.PARTIAL,
    } or session.quarantine_required:
        return DynamicSession.State.QUARANTINED
    if session.cleanup_status != DynamicSession.CleanupStatus.SUCCEEDED:
        raise DynamicStateTransitionError(
            "Failed sessions require cleanup success or quarantine."
        )
    return DynamicSession.State.FAILED


def _terminal_cancel_state(session: DynamicSession) -> str:
    session.refresh_from_db(fields=["cleanup_status", "quarantine_required"])
    if session.cleanup_status in {
        DynamicSession.CleanupStatus.FAILED,
        DynamicSession.CleanupStatus.PARTIAL,
    } or session.quarantine_required:
        return DynamicSession.State.QUARANTINED
    if session.cleanup_status != DynamicSession.CleanupStatus.SUCCEEDED:
        raise DynamicStateTransitionError(
            "Cancelled sessions require cleanup success or quarantine."
        )
    return DynamicSession.State.CANCELLED


def _summary_with_failure(summary: dict, category: str, message: str) -> dict:
    safe_summary = summary if isinstance(summary, dict) else {}
    safe_summary["failure"] = {
        "category": category,
        "message": message,
    }
    return safe_summary


def _record_session_event(
    session: DynamicSession,
    event_type: str,
    message: str,
    *,
    severity: str = DynamicSessionEvent.Severity.INFO,
    metadata: dict | None = None,
) -> DynamicSessionEvent:
    next_sequence = (
        DynamicSessionEvent.objects.filter(session=session).aggregate(
            max_sequence=Max("sequence_number")
        )["max_sequence"]
        or 0
    ) + 1
    return DynamicSessionEvent.objects.create(
        session=session,
        event_type=event_type,
        severity=severity,
        message=message,
        sequence_number=next_sequence,
        metadata=metadata or {},
    )

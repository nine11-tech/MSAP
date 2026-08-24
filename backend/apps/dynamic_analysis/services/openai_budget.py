"""Hard, backend-enforced OpenAI call budget for the finding-validation demo.

This service is the single authority for counting real OpenAI requests across
mission generation, adaptive decision calls, provider retries, and retry runs.
A call counts once a request is actually sent (or attempted) to OpenAI; a local
schema-preflight failure that never opens a connection does not count.

Concurrency safety relies on ``select_for_update`` inside a transaction: every
reservation locks the singleton budget row before deciding, so two workers
cannot both slip past the cap.
"""
from __future__ import annotations

import re
from typing import Any

from django.conf import settings
from django.db import transaction

from apps.dynamic_analysis.models import OpenAICallBudget


GLOBAL_SCOPE = "global"
RESPONSE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

KIND_GENERATION = "generation"
KIND_DECISION = "decision"
KIND_CORRELATION = "correlation"
KIND_POC_PLANNING = "poc_planning"
KIND_EVIDENCE_EXPLANATION = "evidence_explanation"
VALID_KINDS = {
    KIND_GENERATION,
    KIND_DECISION,
    KIND_CORRELATION,
    KIND_POC_PLANNING,
    KIND_EVIDENCE_EXPLANATION,
}


class OpenAIBudgetExhausted(RuntimeError):
    def __init__(self, message: str, *, reason: str = "OPENAI_BUDGET_EXHAUSTED"):
        super().__init__(message)
        self.reason = reason


def _settings_defaults() -> dict[str, int]:
    return {
        "max_mission_generation_calls": int(
            settings.MSAP_OPENAI_MAX_MISSION_GENERATION_CALLS
        ),
        "max_adaptive_decision_calls": int(
            settings.MSAP_OPENAI_MAX_ADAPTIVE_DECISION_CALLS
        ),
        "max_correlation_calls": int(
            settings.MSAP_OPENAI_MAX_CORRELATION_CALLS
        ),
        "max_poc_planning_calls": int(
            settings.MSAP_OPENAI_MAX_POC_PLANNING_CALLS
        ),
        "max_evidence_explanation_calls": int(
            settings.MSAP_OPENAI_MAX_EVIDENCE_EXPLANATION_CALLS
        ),
        "max_total_openai_calls": int(settings.MSAP_OPENAI_MAX_TOTAL_CALLS),
    }


def get_budget(scope: str = GLOBAL_SCOPE) -> OpenAICallBudget:
    """Return the budget row, creating it with settings-backed defaults."""
    budget = OpenAICallBudget.objects.filter(scope=scope).first()
    if budget is not None:
        return budget
    try:
        with transaction.atomic():
            return OpenAICallBudget.objects.get_or_create(
                scope=scope,
                defaults=_settings_defaults(),
            )[0]
    except Exception:
        # Fall back to a plain read if a concurrent create raced; get_or_create
        # is already atomic, this path only guards unusual DB quirks.
        return OpenAICallBudget.objects.filter(scope=scope).first()


def budget_status(scope: str = GLOBAL_SCOPE) -> dict[str, Any]:
    """Serializable snapshot for the UI and health checks."""
    budget = get_budget(scope)
    return {
        "scope": budget.scope,
        "max_mission_generation_calls": budget.max_mission_generation_calls,
        "max_adaptive_decision_calls": budget.max_adaptive_decision_calls,
        "max_evidence_explanation_calls": budget.max_evidence_explanation_calls,
        "max_total_openai_calls": budget.max_total_openai_calls,
        "mission_generation_call_count": budget.mission_generation_call_count,
        "adaptive_decision_call_count": budget.adaptive_decision_call_count,
        "correlation_call_count": budget.correlation_call_count,
        "poc_planning_call_count": budget.poc_planning_call_count,
        "evidence_explanation_call_count": budget.evidence_explanation_call_count,
        "current_openai_call_count": budget.current_openai_call_count,
        "remaining_total_calls": max(
            0, budget.max_total_openai_calls - budget.current_openai_call_count
        ),
        "provider_response_ids": list(budget.provider_response_ids or []),
        "budget_exhausted_reason": budget.budget_exhausted_reason,
        "exhausted": _is_exhausted(budget),
    }


def reserve_call(
    kind: str,
    *,
    scope: str = GLOBAL_SCOPE,
) -> OpenAICallBudget:
    """Reserve one OpenAI call of ``kind`` or raise OpenAIBudgetExhausted.

    This increments the counter before the request is sent. If the caller later
    discovers the request was never sent (local schema preflight), it must call
    ``release_call`` to roll the reservation back.
    """
    if kind not in VALID_KINDS:
        raise ValueError(f"Unsupported OpenAI budget kind: {kind}")
    with transaction.atomic():
        budget = (
            OpenAICallBudget.objects.select_for_update()
            .filter(scope=scope)
            .first()
        )
        if budget is None:
            budget = OpenAICallBudget.objects.create(
                scope=scope,
                **_settings_defaults(),
            )
        try:
            _assert_not_exhausted(budget, kind)
        except OpenAIBudgetExhausted as exc:
            budget.budget_exhausted_reason = exc.reason[:128]
            budget.save(update_fields=["budget_exhausted_reason", "updated_at"])
            raise
        budget.current_openai_call_count += 1
        if kind == KIND_GENERATION:
            budget.mission_generation_call_count += 1
        elif kind == KIND_CORRELATION:
            budget.correlation_call_count += 1
        elif kind == KIND_POC_PLANNING:
            budget.poc_planning_call_count += 1
        elif kind == KIND_EVIDENCE_EXPLANATION:
            budget.evidence_explanation_call_count += 1
        else:
            budget.adaptive_decision_call_count += 1
        budget.budget_exhausted_reason = ""
        budget.save(
            update_fields=[
                "current_openai_call_count",
                "mission_generation_call_count",
                "adaptive_decision_call_count",
                "correlation_call_count",
                "poc_planning_call_count",
                "evidence_explanation_call_count",
                "budget_exhausted_reason",
                "updated_at",
            ]
        )
        return budget


def record_response_id(
    response_id: str | None,
    *,
    scope: str = GLOBAL_SCOPE,
) -> None:
    """Append a provider response id (when available) to the budget row."""
    if not isinstance(response_id, str) or RESPONSE_ID_RE.fullmatch(response_id) is None:
        return
    with transaction.atomic():
        budget = (
            OpenAICallBudget.objects.select_for_update()
            .filter(scope=scope)
            .first()
        )
        if budget is None:
            return
        ids = list(budget.provider_response_ids or [])
        if response_id not in ids:
            ids.append(response_id)
            budget.provider_response_ids = ids
            budget.save(update_fields=["provider_response_ids", "updated_at"])


def release_call(
    kind: str,
    *,
    scope: str = GLOBAL_SCOPE,
) -> None:
    """Roll back a reservation for a request that was never sent."""
    if kind not in VALID_KINDS:
        return
    with transaction.atomic():
        budget = (
            OpenAICallBudget.objects.select_for_update()
            .filter(scope=scope)
            .first()
        )
        if budget is None:
            return
        if kind == KIND_GENERATION and budget.mission_generation_call_count > 0:
            budget.mission_generation_call_count -= 1
        if kind == KIND_DECISION and budget.adaptive_decision_call_count > 0:
            budget.adaptive_decision_call_count -= 1
        if kind == KIND_CORRELATION and budget.correlation_call_count > 0:
            budget.correlation_call_count -= 1
        if kind == KIND_POC_PLANNING and budget.poc_planning_call_count > 0:
            budget.poc_planning_call_count -= 1
        if (
            kind == KIND_EVIDENCE_EXPLANATION
            and budget.evidence_explanation_call_count > 0
        ):
            budget.evidence_explanation_call_count -= 1
        if budget.current_openai_call_count > 0:
            budget.current_openai_call_count -= 1
        budget.save(
            update_fields=[
                "current_openai_call_count",
                "mission_generation_call_count",
                "adaptive_decision_call_count",
                "correlation_call_count",
                "poc_planning_call_count",
                "evidence_explanation_call_count",
                "updated_at",
            ]
        )


def mark_exhausted(
    reason: str,
    *,
    scope: str = GLOBAL_SCOPE,
) -> None:
    budget = get_budget(scope)
    budget.budget_exhausted_reason = reason[:128]
    budget.save(update_fields=["budget_exhausted_reason", "updated_at"])


def reset_budget(scope: str = GLOBAL_SCOPE) -> OpenAICallBudget:
    """Reset the budget counters for a fresh demo run."""
    with transaction.atomic():
        budget = (
            OpenAICallBudget.objects.select_for_update()
            .filter(scope=scope)
            .first()
        )
        if budget is None:
            return OpenAICallBudget.objects.create(scope=scope, **_settings_defaults())
        defaults = _settings_defaults()
        budget.max_mission_generation_calls = defaults["max_mission_generation_calls"]
        budget.max_adaptive_decision_calls = defaults["max_adaptive_decision_calls"]
        budget.max_correlation_calls = defaults["max_correlation_calls"]
        budget.max_poc_planning_calls = defaults["max_poc_planning_calls"]
        budget.max_evidence_explanation_calls = defaults[
            "max_evidence_explanation_calls"
        ]
        budget.max_total_openai_calls = defaults["max_total_openai_calls"]

        budget.mission_generation_call_count = 0
        budget.adaptive_decision_call_count = 0
        budget.correlation_call_count = 0
        budget.poc_planning_call_count = 0
        budget.evidence_explanation_call_count = 0
        budget.current_openai_call_count = 0
        budget.provider_response_ids = []
        budget.budget_exhausted_reason = ""
        budget.save(
            update_fields=[
                "max_mission_generation_calls",
                "max_adaptive_decision_calls",
                "max_correlation_calls",
                "max_poc_planning_calls",
                "max_evidence_explanation_calls",
                "max_total_openai_calls",
                "mission_generation_call_count",
                "adaptive_decision_call_count",
                "correlation_call_count",
                "poc_planning_call_count",
                "evidence_explanation_call_count",
                "current_openai_call_count",
                "provider_response_ids",
                "budget_exhausted_reason",
                "updated_at",
            ]
        )
        return budget


def _is_exhausted(budget: OpenAICallBudget) -> bool:
    return (
        budget.current_openai_call_count >= budget.max_total_openai_calls
        or budget.mission_generation_call_count >= budget.max_mission_generation_calls
        or budget.adaptive_decision_call_count >= budget.max_adaptive_decision_calls
        or budget.correlation_call_count >= budget.max_correlation_calls
        or budget.poc_planning_call_count >= budget.max_poc_planning_calls
        or budget.evidence_explanation_call_count
        >= budget.max_evidence_explanation_calls
    )


def _assert_not_exhausted(budget: OpenAICallBudget, kind: str) -> None:
    if kind == KIND_GENERATION and (
        budget.mission_generation_call_count
        >= budget.max_mission_generation_calls
    ):
        raise OpenAIBudgetExhausted(
            "AI call budget reached. Evidence collected so far was preserved.",
            reason="OPENAI_BUDGET_EXHAUSTED",
        )
    if kind == KIND_DECISION and (
        budget.adaptive_decision_call_count >= budget.max_adaptive_decision_calls
    ):
        raise OpenAIBudgetExhausted(
            "AI call budget reached. Evidence collected so far was preserved.",
            reason="OPENAI_BUDGET_EXHAUSTED",
        )
    if kind == KIND_CORRELATION and (
        budget.correlation_call_count >= budget.max_correlation_calls
    ):
        raise OpenAIBudgetExhausted(
            "AI call budget reached. Evidence collected so far was preserved.",
            reason="OPENAI_BUDGET_EXHAUSTED",
        )
    if kind == KIND_POC_PLANNING and (
        budget.poc_planning_call_count >= budget.max_poc_planning_calls
    ):
        raise OpenAIBudgetExhausted(
            "AI call budget reached. Evidence collected so far was preserved.",
            reason="OPENAI_BUDGET_EXHAUSTED",
        )
    if kind == KIND_EVIDENCE_EXPLANATION and (
        budget.evidence_explanation_call_count
        >= budget.max_evidence_explanation_calls
    ):
        raise OpenAIBudgetExhausted(
            "AI evidence explanation budget reached. Evidence was preserved without AI explanation.",
            reason="OPENAI_EVIDENCE_EXPLANATION_BUDGET_EXHAUSTED",
        )
    if budget.current_openai_call_count >= budget.max_total_openai_calls:
        raise OpenAIBudgetExhausted(
            "AI call budget reached. Evidence collected so far was preserved.",
            reason="OPENAI_BUDGET_EXHAUSTED",
        )

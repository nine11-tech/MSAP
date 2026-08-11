from __future__ import annotations

from datetime import timedelta
from hashlib import sha256
import hmac
import secrets

from django.conf import settings
from django.utils import timezone

from apps.dynamic_analysis.models import AgentRun, AgentRuntime


MAX_RUN_TOKEN_LENGTH = 256


def issue_agent_run_token(run: AgentRun) -> str:
    """Issue one opaque run credential while persisting only its digest."""

    if (
        run.runtime is None
        or run.runtime.runtime_type != AgentRuntime.RuntimeType.CONTAINER_SANDBOX
    ):
        raise ValueError("Run credentials are restricted to container sandbox runs.")
    token = secrets.token_urlsafe(32)
    ttl_seconds = max(
        1,
        min(3600, int(settings.MSAP_AGENT_RUN_TOKEN_TTL_SECONDS)),
    )
    run.run_token_hash = _token_digest(token)
    run.run_token_expires_at = timezone.now() + timedelta(seconds=ttl_seconds)
    run.save(
        update_fields=[
            "run_token_hash",
            "run_token_expires_at",
            "updated_at",
        ]
    )
    return token


def is_valid_agent_run_token(run: AgentRun, token: str) -> bool:
    if not isinstance(token, str) or not token or len(token) > MAX_RUN_TOKEN_LENGTH:
        return False
    if not run.run_token_hash or run.run_token_expires_at is None:
        return False
    if run.run_token_expires_at <= timezone.now():
        return False
    return hmac.compare_digest(run.run_token_hash, _token_digest(token))


def _token_digest(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()

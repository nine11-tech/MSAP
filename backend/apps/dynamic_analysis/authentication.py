from __future__ import annotations

from dataclasses import dataclass
import logging

from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission

from apps.dynamic_analysis.models import AgentRun, AgentRuntime
from apps.dynamic_analysis.services.agent_run_tokens import (
    MAX_RUN_TOKEN_LENGTH,
    is_valid_agent_run_token,
)


security_logger = logging.getLogger("msap.security")


@dataclass(frozen=True)
class AgentRunPrincipal:
    run_id: int
    is_authenticated: bool = True
    is_active: bool = True
    is_anonymous: bool = False
    pk: None = None


class AgentRunTokenAuthentication(BaseAuthentication):
    """Authenticate only a Bearer credential scoped to the route's run ID."""

    def authenticate(self, request):
        header = get_authorization_header(request).split()
        if not header:
            return None
        if len(header) != 2 or header[0].lower() != b"bearer":
            raise AuthenticationFailed("Invalid agent run credential.")
        if len(header[1]) > MAX_RUN_TOKEN_LENGTH:
            raise AuthenticationFailed("Invalid agent run credential.")
        try:
            token = header[1].decode("ascii")
            run_id = int(request.parser_context["kwargs"]["pk"])
            run = AgentRun.objects.select_related("requested_by", "runtime").get(
                pk=run_id
            )
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, AgentRun.DoesNotExist):
            raise AuthenticationFailed("Invalid agent run credential.") from None
        if (
            run.runtime is None
            or run.runtime.runtime_type != AgentRuntime.RuntimeType.CONTAINER_SANDBOX
            or not is_valid_agent_run_token(run, token)
        ):
            security_logger.warning(
                "agent_gateway_auth_rejected run_id=%s",
                run_id,
            )
            raise AuthenticationFailed("Invalid or expired agent run credential.")
        return AgentRunPrincipal(run_id=run_id), run


class IsAgentRunToken(BasePermission):
    message = "A valid agent run credential is required."

    def has_permission(self, request, view):
        run = request.auth
        if not isinstance(run, AgentRun):
            return False
        try:
            route_run_id = int(view.kwargs.get("pk"))
        except (TypeError, ValueError):
            return False
        return run.pk == route_run_id

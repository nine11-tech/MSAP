import logging

from rest_framework.permissions import BasePermission, SAFE_METHODS

from apps.api.roles import user_role


security_logger = logging.getLogger("msap.security")


class _RolePermission(BasePermission):
    allowed_roles: set[str] = set()
    message = "You do not have permission to perform this action."

    def has_permission(self, request, view):
        role = user_role(request.user)
        allowed = role in self.allowed_roles
        if not allowed and getattr(request.user, "is_authenticated", False):
            security_logger.warning(
                "permission_denied user_id=%s role=%s method=%s path=%s",
                request.user.pk,
                role or "NONE",
                request.method,
                request.path,
            )
        return allowed


class IsMSAPAdmin(_RolePermission):
    allowed_roles = {"ADMIN"}


class IsMSAPAnalystOrAdmin(_RolePermission):
    allowed_roles = {"ADMIN", "ANALYST"}


class IsMSAPViewerOrAbove(_RolePermission):
    allowed_roles = {"ADMIN", "ANALYST", "VIEWER"}


class IsReadOnlyViewerOrAbove(BasePermission):
    message = "Your role does not permit this operation."

    def has_permission(self, request, view):
        role = user_role(request.user)
        if request.method in SAFE_METHODS:
            allowed = role in {"ADMIN", "ANALYST", "VIEWER"}
        elif request.method == "DELETE":
            allowed = role == "ADMIN"
        else:
            allowed = role in {"ADMIN", "ANALYST"}
        if not allowed and getattr(request.user, "is_authenticated", False):
            security_logger.warning(
                "permission_denied user_id=%s role=%s method=%s path=%s",
                request.user.pk,
                role or "NONE",
                request.method,
                request.path,
            )
        return allowed

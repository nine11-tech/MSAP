from django.contrib.auth.models import AbstractBaseUser


ADMIN_GROUP = "MSAP_ADMIN"
ANALYST_GROUP = "MSAP_ANALYST"
VIEWER_GROUP = "MSAP_VIEWER"
ROLE_GROUPS = (ADMIN_GROUP, ANALYST_GROUP, VIEWER_GROUP)


def user_role(user: AbstractBaseUser) -> str | None:
    if not getattr(user, "is_authenticated", False):
        return None
    if getattr(user, "is_superuser", False):
        return "ADMIN"
    names = set(user.groups.values_list("name", flat=True))
    if ADMIN_GROUP in names:
        return "ADMIN"
    if ANALYST_GROUP in names:
        return "ANALYST"
    if VIEWER_GROUP in names:
        return "VIEWER"
    return None


def safe_user_permissions(user: AbstractBaseUser) -> list[str]:
    if not getattr(user, "is_authenticated", False):
        return []
    return sorted(user.get_all_permissions())

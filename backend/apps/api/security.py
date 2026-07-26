import logging

from django.http import JsonResponse


security_logger = logging.getLogger("msap.security")


def axes_lockout_response(request, credentials=None, *args, **kwargs):
    username = (credentials or {}).get("username", "")
    security_logger.warning(
        "login_lockout username=%s path=%s",
        username,
        request.path,
    )
    return JsonResponse(
        {
            "detail": (
                "Too many login attempts. Please wait before trying again."
            ),
            "code": "LOGIN_LOCKED",
        },
        status=429,
    )

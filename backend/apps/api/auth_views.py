import logging

from django.contrib.auth import (
    authenticate,
    login,
    logout,
    update_session_auth_hash,
)
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.middleware.csrf import get_token
from rest_framework import serializers, status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from axes.handlers.proxy import AxesProxyHandler

from apps.api.roles import safe_user_permissions, user_role
from apps.api.security import axes_lockout_response


security_logger = logging.getLogger("msap.security")


def serialize_user(user):
    return {
        "id": user.pk,
        "username": user.get_username(),
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "role": user_role(user),
        "is_staff": user.is_staff,
        "permissions": safe_user_permissions(user),
    }


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150, trim_whitespace=False)
    password = serializers.CharField(
        write_only=True,
        trim_whitespace=False,
        style={"input_type": "password"},
    )


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(
        write_only=True,
        trim_whitespace=False,
    )
    new_password = serializers.CharField(
        write_only=True,
        trim_whitespace=False,
    )


class CSRFView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({"csrfToken": get_token(request)})


class LoginView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        # APIView is wrapped as csrf_exempt by DRF, so enforce CSRF explicitly
        # for the anonymous session-establishing request.
        SessionAuthentication().enforce_csrf(request)
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data["username"]
        user = authenticate(
            request=request,
            username=username,
            password=serializer.validated_data["password"],
        )
        if user is None:
            credentials = {"username": username}
            if AxesProxyHandler.is_locked(request, credentials):
                return axes_lockout_response(request, credentials)
            security_logger.warning(
                "login_failure username=%s path=%s",
                username,
                request.path,
            )
            return Response(
                {"detail": "Invalid username or password."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if user_role(user) is None:
            security_logger.warning(
                "login_denied_unassigned_role user_id=%s path=%s",
                user.pk,
                request.path,
            )
            return Response(
                {"detail": "Invalid username or password."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        login(request, user)
        security_logger.info("login_success user_id=%s", user.pk)
        return Response({"user": serialize_user(user)})


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_id = request.user.pk
        logout(request)
        security_logger.info("logout user_id=%s", user_id)
        return Response(status=status.HTTP_204_NO_CONTENT)


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        role = user_role(request.user)
        if role is None:
            return Response(
                {"detail": "No MSAP role is assigned."},
                status=status.HTTP_403_FORBIDDEN,
            )
        return Response(serialize_user(request.user))


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user
        if not user.check_password(serializer.validated_data["current_password"]):
            return Response(
                {"detail": "Current password is invalid."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            validate_password(
                serializer.validated_data["new_password"],
                user=user,
            )
        except DjangoValidationError as exc:
            return Response(
                {"new_password": list(exc.messages)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user.set_password(serializer.validated_data["new_password"])
        user.save(update_fields=["password"])
        update_session_auth_hash(request, user)
        security_logger.info("password_change user_id=%s", user.pk)
        return Response(status=status.HTTP_204_NO_CONTENT)

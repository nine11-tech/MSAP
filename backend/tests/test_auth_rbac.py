from datetime import timedelta

import pytest
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.test import override_settings
from rest_framework.test import APIClient

from apps.api.roles import ANALYST_GROUP, VIEWER_GROUP
from apps.projects.models import Project


PASSWORD = "Correct-Horse-Battery-Staple-42!"


def csrf_client():
    client = APIClient(enforce_csrf_checks=True)
    response = client.get("/api/auth/csrf/")
    assert response.status_code == 200
    return client, response.json()["csrfToken"]


@pytest.fixture
def role_groups(db):
    call_command("bootstrap_roles", verbosity=0)


@pytest.mark.django_db
def test_unauthenticated_api_access_is_denied():
    response = APIClient().get("/api/projects/")
    assert response.status_code in {401, 403}


@pytest.mark.django_db
def test_login_me_and_logout(django_user_model, role_groups):
    user = django_user_model.objects.create_user(
        username="analyst",
        email="analyst@example.test",
        password=PASSWORD,
    )
    user.groups.add(Group.objects.get(name=ANALYST_GROUP))
    client, csrf_token = csrf_client()

    login_response = client.post(
        "/api/auth/login/",
        {"username": "analyst", "password": PASSWORD},
        format="json",
        HTTP_X_CSRFTOKEN=csrf_token,
    )
    assert login_response.status_code == 200
    assert login_response.json()["user"]["role"] == "ANALYST"
    assert "password" not in login_response.json()["user"]

    me_response = client.get("/api/auth/me/")
    assert me_response.status_code == 200
    assert me_response.json()["username"] == "analyst"

    csrf_token = client.get("/api/auth/csrf/").json()["csrfToken"]
    logout_response = client.post(
        "/api/auth/logout/",
        format="json",
        HTTP_X_CSRFTOKEN=csrf_token,
    )
    assert logout_response.status_code == 204
    assert client.get("/api/auth/me/").status_code in {401, 403}


@pytest.mark.django_db
def test_invalid_login_response_is_generic(django_user_model, role_groups):
    django_user_model.objects.create_user(
        username="known-user",
        password=PASSWORD,
    )
    client, csrf_token = csrf_client()
    known = client.post(
        "/api/auth/login/",
        {"username": "known-user", "password": "wrong"},
        format="json",
        HTTP_X_CSRFTOKEN=csrf_token,
    )
    unknown = client.post(
        "/api/auth/login/",
        {"username": "unknown-user", "password": "wrong"},
        format="json",
        HTTP_X_CSRFTOKEN=csrf_token,
    )
    assert known.status_code == unknown.status_code == 400
    assert known.json() == unknown.json() == {
        "detail": "Invalid username or password."
    }


@pytest.mark.django_db
def test_login_requires_csrf(django_user_model, role_groups):
    user = django_user_model.objects.create_user(
        username="csrf-user",
        password=PASSWORD,
    )
    user.groups.add(Group.objects.get(name=ANALYST_GROUP))
    response = APIClient(enforce_csrf_checks=True).post(
        "/api/auth/login/",
        {"username": "csrf-user", "password": PASSWORD},
        format="json",
    )
    assert response.status_code == 403


@pytest.mark.django_db
def test_viewer_can_read_but_cannot_mutate(django_user_model, role_groups):
    project = Project.objects.create(name="Viewer project")
    user = django_user_model.objects.create_user(
        username="viewer",
        password=PASSWORD,
    )
    user.groups.add(Group.objects.get(name=VIEWER_GROUP))
    client = APIClient()
    client.force_authenticate(user)

    assert client.get("/api/projects/").status_code == 200
    assert (
        client.patch(
            f"/api/projects/{project.pk}/",
            {"name": "Changed"},
            format="json",
        ).status_code
        == 403
    )


@pytest.mark.django_db
@override_settings(
    AXES_ENABLED=True,
    AXES_FAILURE_LIMIT=5,
    AXES_COOLOFF_TIME=timedelta(minutes=15),
)
def test_login_lockout_returns_429(django_user_model, role_groups):
    user = django_user_model.objects.create_user(
        username="locked-user",
        password=PASSWORD,
    )
    user.groups.add(Group.objects.get(name=ANALYST_GROUP))
    client, csrf_token = csrf_client()

    responses = [
        client.post(
            "/api/auth/login/",
            {"username": "locked-user", "password": "wrong"},
            format="json",
            HTTP_X_CSRFTOKEN=csrf_token,
            REMOTE_ADDR="198.51.100.10",
        )
        for _ in range(5)
    ]
    assert responses[-1].status_code == 429
    assert responses[-1].json()["code"] == "LOGIN_LOCKED"

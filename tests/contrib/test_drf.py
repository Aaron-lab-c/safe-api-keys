import pytest

pytest.importorskip("rest_framework")
pytest.importorskip("pytest_django")

from rest_framework.test import APIRequestFactory  # noqa: E402

from safe_api_keys.contrib.django import get_manager, reset_manager  # noqa: E402
from safe_api_keys.contrib.django.drf import (  # noqa: E402
    APIKeyAuthentication,
    HasAnyAPIKeyScope,
    HasAPIKey,
    HasAPIKeyScope,
)

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def fresh():
    reset_manager()
    yield
    reset_manager()


def test_authenticate_returns_user_and_record(django_user_model):
    from rest_framework.request import Request

    django_user_model.objects.create(username="alice")
    km = get_manager()
    i = km.issue("alice", scopes=["a"])
    req = Request(APIRequestFactory().get("/", HTTP_AUTHORIZATION=f"Bearer {i.raw_key}"))
    user, record = APIKeyAuthentication().authenticate(req)
    assert user.username == "alice" and record.key_id == i.key_id
    anon = Request(APIRequestFactory().get("/"))
    assert APIKeyAuthentication().authenticate(anon) is None
    assert APIKeyAuthentication().authenticate_header(anon).startswith("Bearer")


def test_permission_factories():
    assert issubclass(HasAPIKeyScope("a"), HasAPIKey) and HasAPIKeyScope("a", "b").required == ("a", "b")
    assert HasAnyAPIKeyScope("x").any_required == ("x",)
    composed = HasAPIKeyScope("a") | HasAnyAPIKeyScope("b")
    assert composed is not None

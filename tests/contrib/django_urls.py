from django.contrib import admin
from django.http import JsonResponse
from django.urls import path
from rest_framework.response import Response
from rest_framework.views import APIView

from safe_api_keys.contrib.django import require_api_key
from safe_api_keys.contrib.django.drf import APIKeyAuthentication, HasAnyAPIKeyScope, HasAPIKey, HasAPIKeyScope


def user_from_owner(owner):
    from django.contrib.auth import get_user_model

    return get_user_model().objects.filter(username=owner).first()


@require_api_key
def plain(request):
    return JsonResponse({"owner": request.api_key.owner})


@require_api_key(scopes=["orders:read"])
def orders(request):
    return JsonResponse({"owner": request.api_key.owner})


@require_api_key(any_scopes=["reports:*", "admin"])
def reports(request):
    return JsonResponse({"ok": True})


@require_api_key(scopes=["orders:read"])
async def async_orders(request):
    return JsonResponse({"owner": request.api_key.owner})


def mw_view(request):
    return JsonResponse({"owner": request.api_key.owner})


def whoami(request):
    return JsonResponse({"owner": request.api_key.owner, "user": str(request.user),
                         "authenticated": request.user.is_authenticated})


@require_api_key
async def async_whoami(request):
    au = await request.auser()
    return JsonResponse({"request_user": str(request.user), "auser": str(au)})


def mw_health(request):
    return JsonResponse({"ok": True, "has_key": hasattr(request, "api_key")})


class DRFOrders(APIView):
    authentication_classes = [APIKeyAuthentication]
    permission_classes = [HasAPIKeyScope("orders:read")]

    def get(self, request):
        return Response({"owner": request.auth.owner, "user": str(request.user)})


class DRFAny(APIView):
    authentication_classes = [APIKeyAuthentication]
    permission_classes = [HasAnyAPIKeyScope("reports:*", "admin")]

    def get(self, request):
        return Response({"ok": True})


class DRFComposed(APIView):
    authentication_classes = [APIKeyAuthentication]
    permission_classes = [HasAPIKeyScope("orders:read") | HasAnyAPIKeyScope("admin")]

    def get(self, request):
        return Response({"ok": True})


class DRFPlain(APIView):
    authentication_classes = [APIKeyAuthentication]
    permission_classes = [HasAPIKey]

    def get(self, request):
        return Response({"owner": request.auth.owner})


urlpatterns = [
    path("admin/", admin.site.urls),
    path("plain/", plain),
    path("orders/", orders),
    path("reports/", reports),
    path("async-orders/", async_orders),
    path("mw/orders/", require_api_key(scopes=["orders:read"])(mw_view)),
    path("mw/any/", mw_view),
    path("mw/health/", mw_health),
    path("mw/whoami/", whoami),
    path("whoami/", require_api_key(whoami)),
    path("async-whoami/", async_whoami),
    path("drf/orders/", DRFOrders.as_view()),
    path("drf/any/", DRFAny.as_view()),
    path("drf/plain/", DRFPlain.as_view()),
    path("drf/composed/", DRFComposed.as_view()),
]

# shop/views_api.py — 受 API key 保護的對外 API（純 Django view，用裝飾器）
import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from safe_api_keys.contrib.django import require_api_key

from .models import Order


@require_api_key(scopes=["orders:read"])
def orders(request):
    owner = request.api_key.owner           # 以 owner 做資料隔離
    return JsonResponse(list(Order.objects.filter(owner_id=owner).values("id", "item", "qty")), safe=False)


@csrf_exempt                                # API key 請求不帶 session cookie，不需 CSRF
@require_http_methods(["POST"])
@require_api_key(scopes=["orders:write"])
def create_order(request):
    body = json.loads(request.body or "{}")
    order = Order.objects.create(owner_id=request.api_key.owner, item=body.get("item", "?"), qty=body.get("qty", 1))
    return JsonResponse({"id": order.id, "item": order.item, "qty": order.qty}, status=201)


@require_api_key(any_scopes=["reports:*", "admin"])
def report(request, name):
    return JsonResponse({"report": name, "orders": Order.objects.filter(owner_id=request.api_key.owner).count()})


def health(request):
    return JsonResponse({"ok": True})

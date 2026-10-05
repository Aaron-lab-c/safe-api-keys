# shop/views_account.py — 登入使用者管理自己的 key（用 Django session 登入保護）
#
# CSRF：這些端點靠 session cookie 認證，所以 Django 的 CsrfViewMiddleware 會檢查 POST/DELETE。
# 前端先 GET /account/csrf/ 取得 csrftoken cookie，之後每個 POST/DELETE 帶 header
#   X-CSRFToken: <csrftoken cookie 的值>
# 沒帶會得到 403（Django 測試客戶端預設不檢查 CSRF，真實伺服器會）。
# 只給 API key 呼叫的端點（views_api.py）不靠 cookie，用 @csrf_exempt 即可。
import json
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpResponse, JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_http_methods

from safe_api_keys import AlreadyRotated, ExpiredKey, PolicyViolation, RevokedKey
from safe_api_keys.contrib.django import get_manager


def km():
    return get_manager()                    # 由 settings.SAFE_API_KEYS 建好的單例


@ensure_csrf_cookie
def csrf(request):
    """讓 SPA／前端取得 csrftoken cookie。"""
    return HttpResponse(status=204)


@login_required
@require_http_methods(["POST"])
def create_key(request):
    body = json.loads(request.body or "{}")
    try:
        issued = km().issue(
            owner=str(request.user.pk),
            name=body.get("name", ""),
            scopes=body.get("scopes", ["orders:read"]),
            expires_in=timedelta(days=body.get("days", 90)),
        )
    except (PolicyViolation, ValueError) as exc:
        return JsonResponse({"error": "bad_request", "message": str(exc)}, status=400)
    return JsonResponse(
        {"api_key": issued.raw_key, "key_id": issued.record.key_id, "masked": issued.record.masked,
         "expires_at": issued.record.expires_at.isoformat()},
        status=201,
    )


@login_required
def list_keys(request):
    rows = km().list(owner=str(request.user.pk))
    return JsonResponse([{"key_id": r.key_id, "masked": r.masked, "name": r.name,
                          "scopes": list(r.scopes), "state": r.state()} for r in rows], safe=False)


def _own_key_or_404(request, key_id):
    rec = km().get(key_id)
    if rec is None or rec.owner != str(request.user.pk):
        raise Http404
    return rec


@login_required
@require_http_methods(["POST", "DELETE"])
def revoke_key(request, key_id):
    _own_key_or_404(request, key_id)
    km().revoke(key_id, reason="user_request")
    return HttpResponse(status=204)


@login_required
@require_http_methods(["POST"])
def rotate_key(request, key_id):
    _own_key_or_404(request, key_id)
    try:
        issued = km().rotate(key_id, grace=timedelta(hours=24))
    except (RevokedKey, ExpiredKey, AlreadyRotated) as exc:        # 已撤銷／已過期／已輪替過：狀態衝突
        return JsonResponse({"error": "conflict", "message": str(exc)}, status=409)
    return JsonResponse({"api_key": issued.raw_key, "key_id": issued.record.key_id}, status=201)

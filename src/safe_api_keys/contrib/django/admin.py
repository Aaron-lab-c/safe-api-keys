"""Django admin for API keys.

* list: masked key, owner, name, scopes, state, expiry, last use; search by owner/key_id
* "Add" issues a key through the KeyManager and shows the raw key **once** on a result page
* actions: revoke, rotate (new raw key shown once on a result page)
* ``hash`` is never displayed; ``hash_alg``/``secret_last4`` and all lifecycle fields are read-only
* no delete: deleting a row leaves no audit trail, revoke instead (``purge`` removes old rows later)

Raw keys are rendered straight into the response (``safe_api_keys/admin/show_keys.html``), never put in
``django.contrib.messages``: its default storage is a signed-but-unencrypted cookie that would carry the key
back and forth on following requests.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict, List, Optional

from django import forms
from django.contrib import admin, messages
from django.template.response import TemplateResponse
from django.urls import reverse

from ..._logic import build_new_key
from ...exceptions import SafeAPIKeysError
from .conf import get_manager, get_settings
from .models import APIKey

ONCE = "This key will not be shown again — copy it now. (不會再顯示，請立即複製)"
SHOW_KEYS_TEMPLATE = "safe_api_keys/admin/show_keys.html"
_ISSUED_ATTR = "_safe_api_keys_issued"
_READONLY = ["key_id", "masked", "prefix", "hash_alg", "secret_last4", "owner", "scopes", "state", "created_at",
             "expires_at", "revoked_at", "revoke_reason", "last_used_at", "use_count", "rotated_from",
             "rotated_to", "ip_allowlist", "metadata"]


def _split(value: str) -> List[str]:
    return [p for p in (value or "").replace(",", " ").split() if p]


class IssueKeyForm(forms.ModelForm):
    scopes_text = forms.CharField(label="Scopes", required=False, help_text="space or comma separated")
    expires_in_days = forms.IntegerField(label="Expires in (days)", required=False, min_value=1)
    ip_allowlist_text = forms.CharField(label="IP allowlist", required=False, help_text="IPs/CIDRs, optional")

    class Meta:
        model = APIKey
        fields = ["owner", "name"]

    def clean(self) -> Any:
        data = super().clean()
        km = get_manager()
        days = data.get("expires_in_days")
        try:  # dry run: validation + policy, no I/O
            build_new_key(key_format=km.key_format, hasher=km.registry.current, policy=km.policy, now=km.now(),
                          owner=data.get("owner") or "", name=data.get("name") or "",
                          scopes=_split(data.get("scopes_text", "")),
                          expires_in=timedelta(days=days) if days else None,
                          ip_allowlist=_split(data.get("ip_allowlist_text", "")))
        except (SafeAPIKeysError, ValueError) as exc:
            raise forms.ValidationError(str(exc)) from None
        return data


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ["masked", "owner", "name", "scopes_display", "state", "expires_at", "last_used_at"]
    list_filter = ["revoked_at"]
    search_fields = ["owner", "key_id", "name"]
    ordering = ["-created_at"]
    actions = ["revoke_selected", "rotate_selected"]
    exclude = ["hash"]

    def has_delete_permission(self, request: Any, obj: Optional[APIKey] = None) -> bool:
        return False  # no audit trail for a delete; revoke instead (purge() cleans up later)

    def _show_keys(self, request: Any, issued: List[Dict[str, str]], title: str) -> TemplateResponse:
        opts = self.model._meta
        context = {
            **self.admin_site.each_context(request), "opts": opts, "title": title, "issued": issued, "once": ONCE,
            "changelist_url": reverse(f"admin:{opts.app_label}_{opts.model_name}_changelist"),
        }
        return TemplateResponse(request, SHOW_KEYS_TEMPLATE, context)

    def _uses_this_model(self) -> bool:
        cfg = get_settings()
        return cfg["STORE"] is None and cfg["MODEL"].lower() == "safe_api_keys.apikey"

    @admin.display(description="Scopes")
    def scopes_display(self, obj: APIKey) -> str:
        return ", ".join(obj.scopes or []) or "—"

    @admin.display(description="Key")
    def masked(self, obj: APIKey) -> str:
        return obj.masked

    def get_form(self, request: Any, obj: Optional[APIKey] = None, change: bool = False, **kwargs: Any) -> Any:
        if obj is None:
            kwargs["form"] = IssueKeyForm
        return super().get_form(request, obj, change=change, **kwargs)

    def get_fields(self, request: Any, obj: Optional[APIKey] = None) -> Any:
        if obj is None:
            return ["owner", "name", "scopes_text", "expires_in_days", "ip_allowlist_text"]
        return ["name"] + _READONLY

    def get_readonly_fields(self, request: Any, obj: Optional[APIKey] = None) -> Any:
        return [] if obj is None else _READONLY

    def has_add_permission(self, request: Any) -> bool:
        return super().has_add_permission(request) and self._uses_this_model()

    def save_model(self, request: Any, obj: APIKey, form: Any, change: bool) -> None:
        if change:  # only "name" is editable
            APIKey._default_manager.filter(pk=obj.pk).update(name=obj.name)
            return
        km = get_manager()
        days = form.cleaned_data.get("expires_in_days")
        issued = km.issue(owner=form.cleaned_data["owner"], name=form.cleaned_data.get("name") or "",
                          scopes=_split(form.cleaned_data.get("scopes_text", "")),
                          expires_in=timedelta(days=days) if days else None,
                          ip_allowlist=_split(form.cleaned_data.get("ip_allowlist_text", "")))
        saved = APIKey._default_manager.get(pk=issued.record.key_id)
        for f in APIKey._meta.concrete_fields:
            setattr(obj, f.attname, getattr(saved, f.attname))
        obj._state.adding = False
        obj._state.db = saved._state.db
        setattr(request, _ISSUED_ATTR, {"masked": issued.record.masked, "raw_key": issued.raw_key})

    def response_add(self, request: Any, obj: APIKey, post_url_continue: Optional[str] = None) -> Any:
        issued = getattr(request, _ISSUED_ATTR, None)
        if issued is None:  # pragma: no cover - defensive: save_model always records the issued key
            return super().response_add(request, obj, post_url_continue)
        return self._show_keys(request, [issued], "New API key")

    @admin.action(description="Revoke selected API keys")
    def revoke_selected(self, request: Any, queryset: Any) -> None:
        km = get_manager()
        n = 0
        for obj in queryset:
            if obj.revoked_at is None:
                km.revoke(obj.pk, reason="admin")
                n += 1
        self.message_user(request, f"Revoked {n} key(s).", messages.SUCCESS)

    @admin.action(description="Rotate selected API keys (24h grace)")
    def rotate_selected(self, request: Any, queryset: Any) -> Any:
        km = get_manager()
        issued: List[Dict[str, str]] = []
        for obj in queryset:
            try:
                new = km.rotate(obj.pk, grace=timedelta(hours=24))
            except SafeAPIKeysError as exc:
                self.message_user(request, f"{obj.masked}: {exc}", messages.ERROR)
                continue
            issued.append({"masked": obj.masked, "raw_key": new.raw_key, "new_masked": new.record.masked})
        if not issued:
            return None
        return self._show_keys(request, issued, "Rotated API keys")

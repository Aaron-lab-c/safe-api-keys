"""Django admin for API keys.

* list: masked key, owner, name, scopes, state, expiry, last use; search by owner/key_id
* "Add" issues a key through the KeyManager and shows the raw key **once** in a message
* actions: revoke, rotate (new raw key shown once)
* ``hash`` is never displayed; ``hash_alg``/``secret_last4`` and all lifecycle fields are read-only
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, List, Optional

from django import forms
from django.contrib import admin, messages
from django.utils.html import format_html

from ..._logic import build_new_key
from ...exceptions import SafeAPIKeysError
from .conf import get_manager, get_settings
from .models import APIKey

ONCE = "This key will not be shown again — copy it now. (不會再顯示，請立即複製)"
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
        messages.warning(request, format_html("New API key <code>{}</code> — {}", issued.raw_key, ONCE))

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
    def rotate_selected(self, request: Any, queryset: Any) -> None:
        km = get_manager()
        for obj in queryset:
            try:
                issued = km.rotate(obj.pk, grace=timedelta(hours=24))
            except SafeAPIKeysError as exc:
                self.message_user(request, f"{obj.masked}: {exc}", messages.ERROR)
                continue
            messages.warning(request, format_html("{} → new key <code>{}</code> — {}", obj.masked,
                                                  issued.raw_key, ONCE))

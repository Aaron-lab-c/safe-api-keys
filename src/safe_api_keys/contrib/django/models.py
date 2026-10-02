"""Django models. Table: ``safe_api_keys_apikey`` (created by ``python manage.py migrate``)."""

from __future__ import annotations

from typing import Any

from django.db import models

from ...models import mask_parts

__all__ = ["AbstractAPIKey", "APIKey"]


class AbstractAPIKey(models.Model):
    """All §12.4 columns. Subclass it for a custom model and point ``SAFE_API_KEYS['MODEL']`` at it."""

    key_id = models.CharField(max_length=16, primary_key=True, editable=False)
    prefix = models.CharField(max_length=32, editable=False)
    # 255 (not 64) so an Argon2Hasher's encoded output fits too.
    hash = models.CharField(max_length=255, editable=False)
    hash_alg = models.CharField(max_length=32, editable=False)
    secret_last4 = models.CharField(max_length=4, editable=False)
    owner = models.CharField(max_length=255, db_index=True)
    name = models.CharField(max_length=255, blank=True, default="")
    scopes = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField()
    expires_at = models.DateTimeField(null=True, blank=True, db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoke_reason = models.CharField(max_length=255, null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    use_count = models.BigIntegerField(default=0)
    rotated_from = models.CharField(max_length=16, null=True, blank=True)
    rotated_to = models.CharField(max_length=16, null=True, blank=True)
    ip_allowlist = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        abstract = True
        ordering = ["-created_at"]
        verbose_name = "API key"
        verbose_name_plural = "API keys"

    @property
    def masked(self) -> str:
        return mask_parts(self.prefix, self.key_id, self.secret_last4)

    def to_record(self) -> Any:
        from ...stores.django import DjangoStore

        return DjangoStore(type(self))._to_record(self)

    @property
    def state(self) -> str:
        return str(self.to_record().state())

    def __str__(self) -> str:
        return self.masked


class APIKey(AbstractAPIKey):
    class Meta(AbstractAPIKey.Meta):
        abstract = False
        app_label = "safe_api_keys"

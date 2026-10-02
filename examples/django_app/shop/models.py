from django.db import models


class Order(models.Model):
    owner_id = models.CharField(max_length=255, db_index=True)   # = api_key.owner (user.pk as string)
    item = models.CharField(max_length=255)
    qty = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["id"]

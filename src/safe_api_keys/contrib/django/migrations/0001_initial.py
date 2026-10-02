from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="APIKey",
            fields=[
                ("key_id", models.CharField(editable=False, max_length=16, primary_key=True, serialize=False)),
                ("prefix", models.CharField(editable=False, max_length=32)),
                ("hash", models.CharField(editable=False, max_length=255)),
                ("hash_alg", models.CharField(editable=False, max_length=32)),
                ("secret_last4", models.CharField(editable=False, max_length=4)),
                ("owner", models.CharField(db_index=True, max_length=255)),
                ("name", models.CharField(blank=True, default="", max_length=255)),
                ("scopes", models.JSONField(blank=True, default=list)),
                ("created_at", models.DateTimeField()),
                ("expires_at", models.DateTimeField(blank=True, db_index=True, null=True)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("revoke_reason", models.CharField(blank=True, max_length=255, null=True)),
                ("last_used_at", models.DateTimeField(blank=True, null=True)),
                ("use_count", models.BigIntegerField(default=0)),
                ("rotated_from", models.CharField(blank=True, max_length=16, null=True)),
                ("rotated_to", models.CharField(blank=True, max_length=16, null=True)),
                ("ip_allowlist", models.JSONField(blank=True, default=list)),
                ("metadata", models.JSONField(blank=True, default=dict)),
            ],
            options={
                "verbose_name": "API key",
                "verbose_name_plural": "API keys",
                "ordering": ["-created_at"],
                "abstract": False,
            },
        ),
    ]

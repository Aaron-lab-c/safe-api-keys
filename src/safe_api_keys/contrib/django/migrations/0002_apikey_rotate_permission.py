from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("safe_api_keys", "0001_initial")]

    operations = [
        migrations.AlterModelOptions(
            name="apikey",
            options={
                "ordering": ["-created_at"],
                "permissions": [("rotate_apikey", "Can rotate API key")],
                "verbose_name": "API key",
                "verbose_name_plural": "API keys",
            },
        ),
    ]

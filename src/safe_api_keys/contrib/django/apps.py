from django.apps import AppConfig


class SafeAPIKeysConfig(AppConfig):
    name = "safe_api_keys.contrib.django"
    label = "safe_api_keys"
    verbose_name = "API keys"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        from . import checks, conf  # noqa: F401 - importing registers the system checks

        conf.validate_settings()  # raises ImproperlyConfigured on bad SAFE_API_KEYS
        conf.connect_signals()

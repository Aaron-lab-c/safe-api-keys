# examples/django_app/settings_test.py
from .settings import *  # noqa: F401,F403
from .settings import SAFE_API_KEYS

SAFE_API_KEYS = {**SAFE_API_KEYS, "STORE": "memory", "PEPPERS": {"v1": b"test-pepper-32-bytes-xxxxxxxxxxxxx"},
                 "CURRENT_PEPPER": "v1"}
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}

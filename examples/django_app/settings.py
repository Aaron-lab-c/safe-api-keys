# examples/django_app/settings.py
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-only-change-me")
DEBUG = True
ALLOWED_HOSTS = ["*"]
USE_TZ = True
ROOT_URLCONF = "shop.urls"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}}

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",                       # 選用
    "safe_api_keys.contrib.django",         # 提供 APIKey model、admin、管理指令
    "shop",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "safe_api_keys.contrib.django.middleware.APIKeyMiddleware",   # 選用：用 PROTECT/EXEMPT 一次保護路徑
]

TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
}]
STATIC_URL = "static/"

SAFE_API_KEYS = {
    "PREFIX": "acme_live",
    "PEPPER_ENV": "SAFE_API_KEYS_PEPPER",   # 從環境變數讀；絕不寫死在 settings
    "EXTRACT": {"bearer": True, "header": "X-API-Key"},
    "POLICY": {"max_ttl": "365d", "allowed_scopes": ["orders:read", "orders:write", "reports:*"],
               "max_active_keys_per_owner": 10},
    "PROTECT": ["/api/"],
    "EXEMPT": ["/api/health/"],
    "USER_RESOLVER": "shop.auth.user_from_owner",   # DRF：把 owner 還原成 User
}

# DRF 錯誤回應也帶 Cache-Control: no-store 與 §13.2 的 JSON 格式
REST_FRAMEWORK = {"EXCEPTION_HANDLER": "safe_api_keys.contrib.django.drf.exception_handler"}

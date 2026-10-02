"""Minimal Django settings for the test-suite."""

SECRET_KEY = "tests-only-not-secret"  # noqa: S105
DEBUG = True
USE_TZ = True
ALLOWED_HOSTS = ["*"]
ROOT_URLCONF = "tests.contrib.django_urls"
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "rest_framework",
    "safe_api_keys.contrib.django",
]
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "safe_api_keys.contrib.django.middleware.APIKeyMiddleware",
]
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
}]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
SAFE_API_KEYS = {
    "PREFIX": "sk_test",
    "PEPPERS": {"v1": "test-pepper-32-bytes-xxxxxxxxxxxxx"},
    "CURRENT_PEPPER": "v1",
    "PROTECT": ["/mw/"],
    "EXEMPT": ["/mw/health/"],
    "USER_RESOLVER": "tests.contrib.django_urls.user_from_owner",
}
REST_FRAMEWORK = {"EXCEPTION_HANDLER": "safe_api_keys.contrib.django.drf.exception_handler"}

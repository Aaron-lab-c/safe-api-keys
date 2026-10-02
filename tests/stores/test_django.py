import pytest

pytest.importorskip("django")
pytest.importorskip("pytest_django")

from safe_api_keys.stores import DjangoStore  # noqa: E402

from .conformance import StoreContract, make_record  # noqa: E402


@pytest.mark.django_db(transaction=True)
class TestDjangoStore(StoreContract):
    # The sqlite test DB is per-connection; thread concurrency is covered by the SQL backends.
    supports_concurrency = False

    @pytest.fixture
    def store(self):
        return DjangoStore()


@pytest.mark.django_db
def test_model_string_and_use_tz_false(settings):
    from safe_api_keys.contrib.django.models import APIKey

    s = DjangoStore("safe_api_keys.APIKey")
    rec = make_record()
    s.save(rec)
    assert APIKey.objects.get(pk=rec.key_id).masked == rec.masked
    settings.USE_TZ = False
    s2 = DjangoStore(APIKey)
    rec2 = make_record("BBBBBBBBBBBB")
    s2.save(rec2)
    assert s2.get(rec2.key_id) == rec2

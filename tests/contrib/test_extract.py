import pytest

from safe_api_keys import ExtractConfig, extract_key


@pytest.mark.parametrize("headers,expected", [
    ({"Authorization": "Bearer abc"}, "abc"),
    ({"authorization": "bearer abc"}, "abc"),
    ({"AUTHORIZATION": "BEARER   abc  "}, "abc"),
    ({"x-api-key": "hdr"}, "hdr"),
    ({"X-API-KEY": " hdr "}, "hdr"),
    ({"Authorization": "Basic Zm9v"}, None),
    ({"Authorization": "Bearer"}, None),
    ({"Authorization": "Bearer a b"}, None),
    ({"X-API-Key": "   "}, None),
    ({}, None),
])
def test_sources(headers, expected):
    assert extract_key(headers, {}) == expected


def test_order_first_wins_no_merge():
    h = {"Authorization": "Bearer from-bearer", "X-API-Key": "from-header"}
    assert extract_key(h, {}) == "from-bearer"
    assert extract_key(h, {}, ExtractConfig(order=("header", "bearer"))) == "from-header"
    assert extract_key({"Authorization": "Basic x", "X-API-Key": "h"}, {}) == "h"


def test_query_param_off_by_default():
    assert extract_key({}, {"api_key": "q"}) is None
    cfg = ExtractConfig(query_param="api_key")
    assert extract_key({}, {"api_key": "q"}, cfg) == "q"
    assert extract_key({}, {"api_key": ["q1", "q2"]}, cfg) == "q1"
    assert extract_key({"X-API-Key": "h"}, {"api_key": "q"}, cfg) == "h"


def test_disabled_sources_and_custom_header():
    cfg = ExtractConfig(bearer=False, header="X-Token")
    assert extract_key({"Authorization": "Bearer b"}, {}, cfg) is None
    assert extract_key({"x-token": "t"}, {}, cfg) == "t"
    with pytest.raises(ValueError):
        ExtractConfig(order=("cookie",))


def test_list_of_tuples_headers():
    assert extract_key([(b"authorization", b"Bearer raw")], {}) == "raw"

import pytest
from hypothesis import given
from hypothesis import strategies as st

from safe_api_keys.scopes import has_scope, missing_scopes, normalize_scopes, scope_covers, validate_scope


@pytest.mark.parametrize("s", ["orders:read", "orders:*", "*", "a", "reports.v2:export-csv", "x_y", "a:b:c:*"])
def test_valid(s):
    assert validate_scope(s) == s


@pytest.mark.parametrize("s", ["", "Orders:read", ":x", "orders:**", "orders*", "a b", "-x", "a" * 64 + "b", 3])
def test_invalid(s):
    with pytest.raises(ValueError):
        validate_scope(s)


def test_normalize_sorts_and_dedups():
    assert normalize_scopes(["b", "a", "b"]) == ("a", "b")
    assert normalize_scopes(None) == ()
    assert normalize_scopes("x") == ("x",)


@pytest.mark.parametrize("granted,required,ok", [
    ("orders:read", "orders:read", True),
    ("orders:*", "orders:read", True),
    ("orders:*", "orders:items:write", True),
    ("orders:*", "orders", False),
    ("orders:*", "ordersx:read", False),
    ("*", "anything", True),
    ("orders:read", "orders:write", False),
])
def test_covers(granted, required, ok):
    assert scope_covers(granted, required) is ok
    assert has_scope([granted], required) is ok


def test_missing():
    assert missing_scopes(["orders:*"], ["orders:read", "users:read"]) == ["users:read"]
    assert missing_scopes([], []) == []


scope_text = st.from_regex(r"[a-z0-9][a-z0-9_.:-]{0,10}", fullmatch=True)


@given(scope_text)
def test_reflexive(s):
    assert scope_covers(s, s) and has_scope(["*"], s)


@given(scope_text, scope_text)
def test_exact_scopes_symmetric(a, b):
    # Without wildcards coverage is plain equality, hence symmetric.
    assert scope_covers(a, b) == scope_covers(b, a) == (a == b)

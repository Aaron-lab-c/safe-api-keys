import re

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from safe_api_keys.exceptions import ConfigurationError, MalformedKey
from safe_api_keys.format import (
    BASE62_ALPHABET,
    KeyFormat,
    base62_encode,
    compute_checksum,
    generate_key,
    mask_key,
    parse_key,
    validate_prefix,
)

FMT = KeyFormat("sk_live")


def test_default_length_and_shape():
    raw, parsed = generate_key(FMT)
    assert len(raw) == 59 == FMT.length
    assert re.fullmatch(r"sk_live_[0-9A-Za-z]{12}_[0-9A-Za-z]{38}", raw)
    assert parsed.body == raw[:-6] and parsed.checksum == raw[-6:]
    assert compute_checksum(parsed.body) == parsed.checksum


def test_round_trip():
    raw, parsed = generate_key(FMT)
    again = parse_key(raw, FMT)
    assert again == parsed and again.checksum_ok


def test_prefix_with_underscores_round_trips():
    fmt = KeyFormat("myapp_ci_v2")
    raw, parsed = generate_key(fmt)
    assert parse_key(raw, fmt).prefix == "myapp_ci_v2"


@pytest.mark.parametrize("prefix", ["", "_sk", "sk_", "sk__live", "SK", "sk-live", "a" * 33, "sk live", "ü"])
def test_invalid_prefix(prefix):
    with pytest.raises(ConfigurationError):
        validate_prefix(prefix)


def test_custom_lengths():
    fmt = KeyFormat("p", key_id_len=16, secret_len=48)
    raw, parsed = generate_key(fmt)
    assert len(parsed.key_id) == 16 and len(parsed.secret) == 48
    assert parse_key(raw, fmt) == parsed


@pytest.mark.parametrize("kw", [{"key_id_len": 7}, {"secret_len": 23}, {"secret_len": 65}])
def test_minimum_lengths_rejected(kw):
    with pytest.raises(ConfigurationError):
        KeyFormat("sk", **kw)


def test_no_checksum_format():
    fmt = KeyFormat("sk", checksum=False)
    raw, parsed = generate_key(fmt)
    assert parsed.checksum == "" and parse_key(raw, fmt) == parsed


def test_exhaustive_single_char_checksum():
    """Every single-character change at every position must be rejected by parse()."""
    raw, _ = generate_key(FMT)
    replacements = "0Az9_x"
    for i in range(len(raw)):
        for ch in replacements:
            if raw[i] == ch:
                continue
            mutated = raw[:i] + ch + raw[i + 1:]
            try:
                p = parse_key(mutated, FMT)
            except MalformedKey:
                continue
            # A prefix-only change can still parse with a valid checksum only if the checksum
            # also matches, which CRC32 rules out for single-byte changes.
            pytest.fail(f"mutation at {i} -> {ch!r} accepted: {p!r}")


def test_checksum_reason():
    raw, _ = generate_key(FMT)
    bad = raw[:-1] + ("0" if raw[-1] != "0" else "1")
    with pytest.raises(MalformedKey) as ei:
        parse_key(bad, FMT)
    assert ei.value.reason == "checksum"
    assert parse_key(bad, FMT, strict_checksum=False).checksum_ok is False


def test_length_limits_and_ascii():
    with pytest.raises(MalformedKey):
        parse_key("a" * 513)
    with pytest.raises(MalformedKey):
        parse_key("sk_live_ÄÄÄÄÄÄÄÄÄÄÄÄ_" + "a" * 38)
    with pytest.raises(MalformedKey):
        parse_key(None)  # type: ignore[arg-type]


def test_strip_whitespace():
    raw, parsed = generate_key(FMT)
    assert parse_key(f"  {raw}\n", FMT) == parsed


@pytest.mark.parametrize("bad", ["", "sk_live", "sk_live_abc", "sk_live__" + "a" * 38, "nounderscores" * 5])
def test_garbage_rejected(bad):
    with pytest.raises(MalformedKey):
        parse_key(bad, FMT)


def test_wrong_lengths_for_format():
    raw, _ = generate_key(KeyFormat("sk_live", key_id_len=10))
    with pytest.raises(MalformedKey):
        parse_key(raw, FMT)


def test_generic_parse_without_format():
    raw, parsed = generate_key(KeyFormat("x", key_id_len=9, secret_len=30))
    assert parse_key(raw) == parsed


def test_mask():
    raw, parsed = generate_key(FMT)
    assert mask_key(raw) == f"sk_live_{parsed.key_id}_…{parsed.secret[-4:]}"
    assert parsed.secret not in repr(parsed)


def test_base62():
    assert base62_encode(0) == "0"
    assert base62_encode(61) == "z"
    assert base62_encode(62) == "10"
    assert base62_encode(5, 6) == "000005"
    assert base62_encode(b"\x00\x01") == "1"
    assert set(BASE62_ALPHABET) == set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    with pytest.raises(ValueError):
        base62_encode(-1)


def test_injected_key_id_validated():
    with pytest.raises(ValueError):
        generate_key(FMT, key_id="short")
    raw, p = generate_key(FMT, key_id="AAAAAAAAAAAA")
    assert p.key_id == "AAAAAAAAAAAA"


prefix_strategy = st.from_regex(r"[a-z0-9]{1,6}(_[a-z0-9]{1,6}){0,3}", fullmatch=True)


@settings(max_examples=150, deadline=None)
@given(prefix=prefix_strategy, kid=st.integers(8, 20), sec=st.integers(24, 64), chk=st.booleans())
def test_property_round_trip(prefix, kid, sec, chk):
    fmt = KeyFormat(prefix, key_id_len=kid, secret_len=sec, checksum=chk)
    raw, parsed = generate_key(fmt)
    assert parse_key(raw, fmt) == parsed

import logging
from datetime import timedelta

import pytest

from safe_api_keys import CallbackAuditSink, LoggingAuditSink, MalformedKey, NullAuditSink
from safe_api_keys.audit import AuditEvent, safe_emit

from .conftest import START, make_km


@pytest.fixture
def events():
    return []


@pytest.fixture
def akm(clock, events):
    return make_km(clock=clock, audit=CallbackAuditSink(events.append))


def types(events):
    return [e.type for e in events]


def test_lifecycle_events(akm, events, clock):
    a = akm.issue("o", scopes=["x"])
    akm.verify(a.raw_key, scopes=["x"], client_ip="1.2.3.4")
    b = akm.rotate(a.key_id)
    akm.verify(a.raw_key)
    akm.revoke(b.key_id, reason="done")
    clock.advance(days=10)
    akm.purge(older_than=timedelta(days=1))
    assert types(events) == ["key.issued", "key.verified", "key.rotated", "key.verified", "key.revoked",
                             "key.purged"]
    verified = events[1]
    assert verified.key_id == a.key_id and verified.owner == "o" and verified.client_ip == "1.2.3.4"
    assert verified.scopes_required == ("x",) and verified.at == START
    assert events[3].extra["rotated_to"] == b.key_id  # old key used during grace
    assert events[4].reason == "done" and events[5].extra["count"] == 2


@pytest.mark.parametrize("make_raw,reason", [
    (lambda km, i: "garbage", "malformed"),
    (lambda km, i: i.raw_key[:-1] + ("0" if i.raw_key[-1] != "0" else "1"), "checksum"),
    (lambda km, i: i.raw_key.replace("sk_test", "sk_live", 1), "checksum"),
    (lambda km, i: km.key_format.build("ZZZZZZZZZZZZ", "y" * 32)[0], "unknown"),
    (lambda km, i: km.key_format.build(i.key_id, "y" * 32)[0], "bad_secret"),
])
def test_rejected_reasons(akm, events, make_raw, reason):
    i = akm.issue("o")
    with pytest.raises(Exception):
        akm.verify(make_raw(akm, i))
    ev = events[-1]
    assert ev.type == "key.rejected" and ev.reason == reason


def test_rejected_prefix_and_state_reasons(clock, events):
    from safe_api_keys.format import KeyFormat

    live = make_km(clock=clock, prefix="sk_live")
    akm = make_km(live.store, clock=clock, audit=CallbackAuditSink(events.append))
    with pytest.raises(MalformedKey):
        akm.verify(live.issue("o").raw_key)
    assert events[-1].reason == "prefix"
    i = akm.issue("o", scopes=["a"], ip_allowlist=["10.0.0.1"], expires_in=timedelta(hours=1))
    for kwargs, reason in [({"scopes": ["b"], "client_ip": "10.0.0.1"}, "scope"), ({"client_ip": "9.9.9.9"}, "ip")]:
        with pytest.raises(Exception):
            akm.verify(i.raw_key, **kwargs)
        assert events[-1].reason == reason and events[-1].key_id == i.key_id
    clock.advance(hours=1)
    with pytest.raises(Exception):
        akm.verify(i.raw_key, client_ip="10.0.0.1")
    assert events[-1].reason == "expired"
    akm.revoke(i.key_id)
    with pytest.raises(Exception):
        akm.verify(i.raw_key, client_ip="10.0.0.1")
    assert events[-1].reason == "revoked"
    assert KeyFormat


def test_audit_success_off(clock, events):
    km = make_km(clock=clock, audit=CallbackAuditSink(events.append), audit_success=False)
    km.verify(km.issue("o").raw_key)
    assert types(events) == ["key.issued"]


def test_sinks_never_raise(caplog, clock):
    def boom(event):
        raise RuntimeError("sink down")

    km = make_km(clock=clock, audit=CallbackAuditSink(boom))
    km.verify(km.issue("o").raw_key)

    class Rude:
        def emit(self, event):
            raise RuntimeError("rude")

    safe_emit(Rude(), AuditEvent(type="key.issued", at=START))
    NullAuditSink().emit(AuditEvent(type="key.issued", at=START))


def test_logging_sink_structured(caplog, clock):
    km = make_km(clock=clock, audit=LoggingAuditSink("test.audit"))
    with caplog.at_level(logging.INFO, logger="test.audit"):
        i = km.issue("o")
    rec = caplog.records[-1]
    assert rec.audit["type"] == "key.issued" and rec.audit_key_id == i.key_id

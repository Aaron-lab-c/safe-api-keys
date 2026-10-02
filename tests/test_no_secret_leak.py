"""S16: no 32-char base62 run (i.e. a secret) may appear in logs, reprs, exceptions or audit events."""

import logging
import re
from datetime import timedelta

import pytest

from safe_api_keys import LoggingAuditSink
from safe_api_keys.audit import CallbackAuditSink

from .conftest import make_km

SECRET_RE = re.compile(r"[0-9A-Za-z]{32}")


def assert_clean(text: str, secrets) -> None:
    for s in secrets:
        assert s not in text, "secret leaked"
    assert not SECRET_RE.search(text), f"32-char base62 run found in: {text[:200]!r}"


def test_nothing_leaks(caplog, capsys, clock):
    events = []
    sinks = CallbackAuditSink(events.append)
    km = make_km(clock=clock, audit=sinks)
    log_km = make_km(km.store, clock=clock, audit=LoggingAuditSink("leak.audit", level=logging.WARNING))
    texts, secrets = [], []
    with caplog.at_level(logging.DEBUG):
        issued = km.issue("owner-1", scopes=["a"], expires_in=timedelta(days=1))
        secrets.append(km.parse(issued.raw_key).secret)
        texts += [repr(issued), str(issued), repr(issued.record), str(issued.record), repr(km.parse(issued.raw_key)),
                  repr(km), repr(km.store), km.mask(issued.raw_key)]
        rec = log_km.verify(issued.raw_key, scopes=["a"])
        texts += [repr(rec), str(rec.to_dict())]
        bad_secret = km.key_format.build(issued.key_id, "Q" * 32)[0]
        for raw in (bad_secret, issued.raw_key[:-1] + "0", "sk_test_" + "x" * 60):
            for m in (km, log_km):
                try:
                    m.verify(raw, scopes=["zzz"])
                except Exception as exc:
                    texts += [str(exc), repr(exc), str(exc.__dict__)]
        try:
            km.verify(issued.raw_key, scopes=["zzz"])
        except Exception as exc:
            texts += [str(exc), repr(exc)]
        rotated = km.rotate(issued.key_id)
        secrets.append(km.parse(rotated.raw_key).secret)
        texts += [repr(rotated), repr(km.lineage(rotated.key_id))]
        km.revoke(rotated.key_id)
    texts += [r.getMessage() + str(getattr(r, "audit", "")) for r in caplog.records]
    texts += [repr(e) + str(e.as_dict()) for e in events]
    out = capsys.readouterr()
    texts += [out.out, out.err]
    # the deliberately forged "Q"*32 secret is a test artefact, not a real secret
    for t in texts:
        assert_clean(t.replace("Q" * 32, "<forged>"), secrets)


@pytest.mark.parametrize("obj", ["record", "issued", "parsed"])
def test_reprs_masked(km, obj):
    issued = km.issue("o")
    target = {"record": issued.record, "issued": issued, "parsed": km.parse(issued.raw_key)}[obj]
    assert issued.raw_key not in repr(target)
    assert "…" in repr(target)
    assert repr(issued) == f"IssuedKey(masked={issued.record.masked!r})"

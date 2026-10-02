"""CLI tests (§20.5): every sub-command via subprocess; only issue/rotate may print a secret."""

import json
import os
import re
import subprocess
import sys

import pytest

SECRET_RE = re.compile(r"[0-9A-Za-z]{32}")
PEPPER = "cli-test-pepper-xxxxxxxxxxxxxxxxxx"


@pytest.fixture
def run(tmp_path):
    db = tmp_path / "cli.db"
    env = {**os.environ, "SAFE_API_KEYS_PEPPER": PEPPER, "SAFE_API_KEYS_STORE": f"sqlite:///{db}"}
    env.pop("SAFE_API_KEYS_PEPPERS", None)

    def _run(*args, env_over=None, check_clean=True):
        e = {**env, **(env_over or {})}
        p = subprocess.run([sys.executable, "-m", "safe_api_keys.cli", *args], capture_output=True, env=e,
                           timeout=60)
        out, err = p.stdout.decode("utf-8"), p.stderr.decode("utf-8")
        assert "\r\n" not in out  # LF on non-tty
        if check_clean:
            assert not SECRET_RE.search(out) and not SECRET_RE.search(err), out + err
        return p.returncode, out, err

    return _run


def test_full_lifecycle(run):
    rc, out, err = run("issue", "--prefix", "sk_cli", "--owner", "svc", "--scopes", "reports:*", "orders:read",
                       "--expires", "90d", "--name", "batch", "--ip", "10.0.0.0/8", "--meta", "team=billing",
                       check_clean=False)
    assert rc == 0 and "not be shown again" in err
    raw = out.strip()
    assert raw.startswith("sk_cli_") and len(raw) == 58

    rc, out, _ = run("verify", "--prefix", "sk_cli", raw, "--scopes", "reports:daily", "--ip", "10.1.1.1")
    assert rc == 0 and out.startswith("valid:") and "owner=svc" in out
    rc, out, _ = run("verify", "--prefix", "sk_cli", raw, "--scopes", "admin", "--ip", "10.1.1.1")
    assert rc == 1 and "insufficient_scope" in out
    rc, out, _ = run("verify", "--prefix", "sk_cli", raw, "--ip", "8.8.8.8", "--json")
    assert rc == 1 and json.loads(out)["error"] == "ip_not_allowed"

    key_id = raw.split("_")[2]
    rc, out, _ = run("list", "--owner", "svc")
    assert rc == 0 and key_id in out and "batch" in out
    rc, out, _ = run("list", "--json")
    rows = json.loads(out)
    assert rows[0]["key_id"] == key_id and "hash" not in rows[0] and rows[0]["metadata"] == {"team": "billing"}

    rc, out, err = run("rotate", "--prefix", "sk_cli", key_id, "--grace", "1h", "--json", check_clean=False)
    assert rc == 0
    rotated = json.loads(out)
    assert rotated["rotated_from"] == key_id and rotated["raw_key"].startswith("sk_cli_")

    rc, out, _ = run("revoke", key_id, "--reason", "compromised")
    assert rc == 0 and "revoked" in out
    rc, out, _ = run("verify", "--prefix", "sk_cli", raw, "--ip", "10.1.1.1")
    assert rc == 1 and "revoked" in out
    rc, out, _ = run("list", "--all", "--json")
    assert {r["state"] for r in json.loads(out)} == {"revoked", "active"}
    rc, out, _ = run("purge", "--older-than", "90d")
    assert rc == 0 and "purged 0" in out


def test_issue_json_contains_raw_key(run):
    rc, out, _ = run("issue", "--prefix", "sk_cli", "--owner", "o", "--json", check_clean=False)
    data = json.loads(out)
    assert rc == 0 and data["raw_key"].startswith("sk_cli_") and data["key"]["owner"] == "o"
    assert data["key"]["masked"].endswith(data["raw_key"].split("_")[-1][-10:-6])


def test_parse_does_not_need_store(run):
    rc, out, _ = run("issue", "--prefix", "sk_cli", "--owner", "o", check_clean=False)
    raw = out.strip()
    rc, out, _ = run("parse", raw, env_over={"SAFE_API_KEYS_STORE": "", "SAFE_API_KEYS_PEPPER": ""})
    assert rc == 0 and "checksum_ok: True" in out and "masked: sk_cli_" in out
    rc, out, _ = run("parse", raw[:-1] + ("0" if raw[-1] != "0" else "1"))
    assert rc == 1 and "checksum_ok: False" in out
    rc, _, err = run("parse", "garbage")
    assert rc == 1


def test_exit_codes(run, tmp_path):
    rc, _, err = run("issue", "--prefix", "sk_cli", "--owner", "o", env_over={"SAFE_API_KEYS_PEPPER": ""})
    assert rc == 2 and "pepper" in err
    rc, _, err = run("issue", "--owner", "o")  # missing --prefix
    assert rc == 2
    rc, _, err = run("issue", "--prefix", "BAD", "--owner", "o")
    assert rc == 2
    rc, _, err = run("issue", "--prefix", "sk_cli", "--owner", "o", "--expires", "whenever")
    assert rc == 2
    rc, _, err = run("revoke", "NOSUCHKEY123")
    assert rc == 1
    rc, _, err = run("list", env_over={"SAFE_API_KEYS_STORE": "bogus://x"})
    assert rc == 2
    bad_dir = tmp_path / "missing-dir" / "x.db"
    rc, _, err = run("list", env_over={"SAFE_API_KEYS_STORE": f"sqlite:///{bad_dir}"})
    assert rc == 3
    rc, _, _ = run("nonsense")
    assert rc == 2


def test_multi_pepper_env(run):
    env = {"SAFE_API_KEYS_PEPPER": "", "SAFE_API_KEYS_PEPPERS": "v2:" + "b" * 32 + ",v1:" + PEPPER,
           "SAFE_API_KEYS_CURRENT_PEPPER": "v2"}
    rc, out, _ = run("issue", "--prefix", "sk_cli", "--owner", "o", "--json", env_over=env, check_clean=False)
    assert json.loads(out)["key"]["hash_alg"] == "hmac-sha256$v2"

"""Tests for the authorization-gated ACTIVE mode.

CRITICAL: these tests inject an in-memory provider and a fake clock. They never
read real firmware and never touch a network. Active mode must be OFF by
default and refuse out-of-scope hosts.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from bootwarden import active
from bootwarden.active import (
    ActiveConfig, RateLimiter, active_audit, enforce_scope,
    NotAuthorizedError, ScopeError, local_hostname, AUTHORIZED_USE_BANNER,
)
from bootwarden.cli import main


HOST = local_hostname()


def _provider(pk=True, kek=True, db=True, dbx=True):
    def p():
        return {"PK": pk, "KEK": kek, "db": db, "dbx": dbx}
    return p


# --- default-off / authorization ------------------------------------------ #
def test_active_off_by_default():
    cfg = ActiveConfig()  # authorized defaults to False
    assert cfg.authorized is False
    with pytest.raises(NotAuthorizedError):
        enforce_scope(cfg)


def test_active_requires_authorized_flag():
    cfg = ActiveConfig(authorized=False, allowlist=[HOST])
    with pytest.raises(NotAuthorizedError):
        active_audit(cfg, provider=_provider())


def test_active_requires_allowlist():
    cfg = ActiveConfig(authorized=True, allowlist=[])
    with pytest.raises(ScopeError):
        enforce_scope(cfg)


def test_active_refuses_out_of_scope_host():
    cfg = ActiveConfig(authorized=True, allowlist=["some-other-host"])
    with pytest.raises(ScopeError):
        enforce_scope(cfg)


def test_active_accepts_in_scope_host():
    cfg = ActiveConfig(authorized=True, allowlist=[HOST])
    assert enforce_scope(cfg) == HOST


def test_active_scope_is_case_insensitive():
    cfg = ActiveConfig(authorized=True, allowlist=[HOST.upper()])
    assert enforce_scope(cfg) == HOST


def test_active_explicit_host_override():
    cfg = ActiveConfig(authorized=True, allowlist=["box-1"], host="box-1")
    assert enforce_scope(cfg) == "box-1"


# --- audit result shape (mock provider) ----------------------------------- #
def test_active_audit_clean(monkeypatch):
    cfg = ActiveConfig(authorized=True, allowlist=[HOST], rate_limit=1000.0)
    res = active_audit(cfg, provider=_provider())
    assert res.verdict == "PASS"
    assert res.secureboot_vars["dbx"] is True
    assert res.path.startswith("live://")
    assert any(f.code == "active-mode" for f in res.findings)


def test_active_audit_missing_keys_fails():
    cfg = ActiveConfig(authorized=True, allowlist=[HOST], rate_limit=1000.0)
    res = active_audit(cfg, provider=_provider(pk=False))
    assert res.verdict == "FAIL"
    assert any(f.code == "missing-secureboot-keys" for f in res.findings)


def test_active_audit_no_dbx_warns():
    cfg = ActiveConfig(authorized=True, allowlist=[HOST], rate_limit=1000.0)
    res = active_audit(cfg, provider=_provider(dbx=False))
    codes = {f.code for f in res.findings}
    assert "no-dbx" in codes
    # missing dbx is only a warning, not an error
    assert res.verdict == "PASS"


def test_active_audit_normalises_partial_provider():
    cfg = ActiveConfig(authorized=True, allowlist=[HOST], rate_limit=1000.0)
    res = active_audit(cfg, provider=lambda: {"PK": True})
    assert set(res.secureboot_vars) == {"PK", "KEK", "db", "dbx"}
    assert res.secureboot_vars["KEK"] is False


# --- rate limiter ---------------------------------------------------------- #
def test_rate_limiter_rejects_nonpositive():
    with pytest.raises(ValueError):
        RateLimiter(0)
    with pytest.raises(ValueError):
        RateLimiter(-1)


def test_rate_limiter_spaces_calls():
    slept = []
    t = {"now": 0.0}
    rl = RateLimiter(2.0, clock=lambda: t["now"], sleep=lambda s: slept.append(s))
    rl.wait()  # first call: no sleep
    assert slept == []
    rl.wait()  # immediate second call -> must sleep ~0.5s
    assert slept and abs(slept[0] - 0.5) < 1e-9


def test_active_audit_uses_rate_limiter():
    waited = {"n": 0}

    class Counter(RateLimiter):
        def wait(self):
            waited["n"] += 1

    cfg = ActiveConfig(authorized=True, allowlist=[HOST])
    active_audit(cfg, provider=_provider(), rate_limiter=Counter(1.0))
    assert waited["n"] >= 1


# --- CLI gating ------------------------------------------------------------ #
def test_cli_active_without_authorized_refused(capsys):
    rc = main(["active", "--target-allowlist", HOST])
    assert rc == 3
    err = capsys.readouterr().err
    assert "AUTHORIZED USE ONLY" in err
    assert "refused" in err


def test_cli_active_without_allowlist_refused(capsys):
    rc = main(["active", "--authorized"])
    assert rc == 3
    assert "allowlist" in capsys.readouterr().err


def test_cli_active_out_of_scope_refused(capsys):
    rc = main(["active", "--authorized", "--target-allowlist", "not-this-host"])
    assert rc == 3
    assert "not in the authorized scope" in capsys.readouterr().err


def test_cli_active_bad_rate_limit(capsys):
    rc = main(["active", "--authorized", "--target-allowlist", HOST,
               "--rate-limit", "0"])
    assert rc == 2
    assert "rate-limit" in capsys.readouterr().err


def test_cli_active_scope_file(tmp_path, capsys):
    sf = tmp_path / "scope.txt"
    sf.write_text("# scope\nnot-this-host\n", encoding="utf-8")
    rc = main(["active", "--authorized", "--scope-file", str(sf)])
    # host not in file -> refused
    assert rc == 3


def test_cli_active_banner_always_printed(capsys):
    main(["active", "--authorized", "--target-allowlist", "x"])
    assert "AUTHORIZED USE ONLY" in capsys.readouterr().err


def test_banner_text_mentions_defensive_and_local():
    assert "AUTHORIZED USE ONLY" in AUTHORIZED_USE_BANNER
    assert "LOCAL" in AUTHORIZED_USE_BANNER
    assert "remote" in AUTHORIZED_USE_BANNER.lower()


def test_default_provider_is_callable():
    p = active.default_provider()
    assert callable(p)

"""Offline tests for the CISA KEV data-feed enrichment.

These NEVER touch the network: a tiny trimmed real-data KEV fixture is committed
under tests/fixtures/feeds-cache, COGNIS_FEEDS_CACHE is pointed at it, and every
call uses offline=True so datafeeds serves the cache only.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

_FIXTURE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "fixtures", "feeds-cache")
)

# Must be set before importing datafeeds/feeds so cache_dir() resolves to it.
os.environ["COGNIS_FEEDS_CACHE"] = _FIXTURE

from bootwarden import feeds, datafeeds, core  # noqa: E402
from bootwarden.cli import main  # noqa: E402

# Real CVE ids present in the committed fixture.
KEV_IN_FIXTURE = "CVE-2025-47827"   # IGEL OS Secure Boot bypass
KEV_ALSO = "CVE-2022-0492"          # Linux kernel cgroups priv-esc
NOT_IN_KEV = "CVE-2099-00000"       # synthetic


def setup_function(_):
    # Defensive: keep the cache pointed at the fixture for every test.
    os.environ["COGNIS_FEEDS_CACHE"] = _FIXTURE


def test_fixture_present_and_offline_loadable():
    assert os.path.isfile(os.path.join(_FIXTURE, "cisa-kev.data"))
    assert os.path.isfile(os.path.join(_FIXTURE, "cisa-kev.meta.json"))
    cat = feeds.load_kev(offline=True)
    assert cat["vulnerabilities"], "fixture has KEV entries"
    assert datafeeds.cache_dir() == __import__("pathlib").Path(_FIXTURE)


def test_kev_index_keys_are_cves():
    idx = feeds.kev_index(offline=True)
    assert KEV_IN_FIXTURE in idx
    assert KEV_ALSO in idx
    assert all(k.startswith("CVE-") for k in idx)


def test_only_relevant_feed_allowed():
    import pytest

    with pytest.raises(KeyError):
        feeds._check_relevant("opensky-states")
    assert feeds.RELEVANT_FEEDS == ("cisa-kev",)


def test_enrich_cves_flags_known_exploited():
    report = feeds.enrich_cves(
        [KEV_IN_FIXTURE, KEV_ALSO, NOT_IN_KEV], offline=True
    )
    assert report["total"] == 3
    assert report["known_exploited"] == 2
    by_cve = {i["cve"]: i for i in report["items"]}
    assert by_cve[KEV_IN_FIXTURE]["known_exploited"] is True
    assert by_cve[KEV_IN_FIXTURE]["vendor"]  # real record carried through
    assert by_cve[KEV_IN_FIXTURE]["due_date"]
    assert by_cve[NOT_IN_KEV]["known_exploited"] is False
    assert KEV_IN_FIXTURE in report["patch_now"]
    assert NOT_IN_KEV not in report["patch_now"]


def test_enrich_cves_dedupes_and_normalises_case():
    report = feeds.enrich_cves(
        [KEV_IN_FIXTURE.lower(), KEV_IN_FIXTURE], offline=True
    )
    assert report["total"] == 1  # case-insensitive dedupe


def test_enrich_audit_result_relevels_finding_with_kev_cve():
    # A finding that references a KEV CVE should be escalated to error + annotated.
    result = core.AuditResult(path="fw.bin", size=1024)
    result.findings.append(
        core.Finding("warn", "smm-cve",
                     "SMM driver vulnerable to {}".format(KEV_IN_FIXTURE))
    )
    result.findings.append(
        core.Finding("warn", "other-cve",
                     "component references {}".format(NOT_IN_KEV))
    )
    summary = feeds.enrich_audit_result(result, offline=True)
    assert summary["flagged"] == [KEV_IN_FIXTURE]
    kev_finding = result.findings[0]
    assert kev_finding.level == "error"
    assert "[KEV:" in kev_finding.message
    # non-KEV finding untouched
    assert result.findings[1].level == "warn"


def test_enrich_audit_result_idempotent():
    result = core.AuditResult(path="fw.bin", size=1024)
    result.findings.append(
        core.Finding("warn", "smm-cve", "vuln {}".format(KEV_IN_FIXTURE))
    )
    feeds.enrich_audit_result(result, offline=True)
    msg_once = result.findings[0].message
    feeds.enrich_audit_result(result, offline=True)
    assert result.findings[0].message == msg_once  # no double annotation


def test_offline_missing_cache_raises(tmp_path):
    os.environ["COGNIS_FEEDS_CACHE"] = str(tmp_path)  # empty -> nothing cached
    try:
        import pytest
        with pytest.raises(FileNotFoundError):
            feeds.load_kev(offline=True)
    finally:
        os.environ["COGNIS_FEEDS_CACHE"] = _FIXTURE


def test_cli_feeds_list(capsys):
    rc = main(["feeds", "list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "cisa-kev" in out
    assert "cisa.gov" in out


def test_cli_feeds_get_cve_offline_table(capsys):
    rc = main(["feeds", "get", "--offline", "--cve", KEV_IN_FIXTURE, "--cve", NOT_IN_KEV])
    assert rc == 0
    out = capsys.readouterr().out
    assert "[KEV]" in out
    assert KEV_IN_FIXTURE in out
    assert "PATCH NOW" in out


def test_cli_feeds_get_cve_offline_json(capsys):
    rc = main(["feeds", "get", "--offline", "--cve", KEV_IN_FIXTURE, "--format", "json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["known_exploited"] == 1
    assert doc["patch_now"] == [KEV_IN_FIXTURE]


def test_cli_feeds_get_catalog_offline(capsys):
    rc = main(["feeds", "get", "--offline"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "KEV catalog" in out


def test_cli_feeds_rejects_unknown_feed(capsys):
    rc = main(["feeds", "get", "opensky-states", "--offline"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "only consumes" in err


def test_demo_runs_offline():
    path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "demos", "11-kev-enrichment", "run.py")
    )
    spec = importlib.util.spec_from_file_location("kev_demo", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    report = mod.run(offline=True)
    assert report["known_exploited"] == 2
    assert report["total"] == 3

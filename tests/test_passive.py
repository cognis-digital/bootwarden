"""Tests for passive (offline) analysis: SBOM/CVE extraction + batch scanning."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from bootwarden import passive
from bootwarden.cli import main
from _fwfix import sample_failing, sample_clean


# --- CVE text extraction --------------------------------------------------- #
def test_extract_cves_from_text():
    out = passive.extract_cves_from_text("see CVE-2023-1234 and cve-2024-99999")
    assert out == ["CVE-2023-1234", "CVE-2024-99999"]


def test_extract_cves_dedup_preserves_order():
    out = passive.extract_cves_from_text("CVE-2020-0001 CVE-2020-0002 CVE-2020-0001")
    assert out == ["CVE-2020-0001", "CVE-2020-0002"]


def test_extract_cves_empty():
    assert passive.extract_cves_from_text("") == []
    assert passive.extract_cves_from_text("no cves here") == []


def test_parse_cve_list_ignores_comments_and_blanks():
    text = "# header\nCVE-2021-1111\n\n  CVE-2021-2222  # trailing\n"
    assert passive.parse_cve_list(text) == ["CVE-2021-1111", "CVE-2021-2222"]


def test_parse_cve_list_dedup():
    assert passive.parse_cve_list("CVE-2021-1\nCVE-2021-1") == []  # 1 too short
    assert passive.parse_cve_list("CVE-2021-1234\ncve-2021-1234") == ["CVE-2021-1234"]


# --- SBOM extraction ------------------------------------------------------- #
def test_sbom_cyclonedx_vulnerabilities():
    sbom = {
        "bomFormat": "CycloneDX",
        "vulnerabilities": [
            {"id": "CVE-2022-0001"},
            {"id": "GHSA-xxxx", "references": [{"id": "CVE-2022-0002"}]},
        ],
    }
    out = passive.extract_cves_from_sbom(sbom)
    assert "CVE-2022-0001" in out
    assert "CVE-2022-0002" in out


def test_sbom_cyclonedx_json_string():
    sbom = json.dumps({"components": [{"name": "x", "description": "fixes CVE-2019-5555"}]})
    out = passive.extract_cves_from_sbom(sbom)
    assert out == ["CVE-2019-5555"]


def test_sbom_spdx_tag_value_text():
    spdx = "SPDXID: SPDXRef-DOCUMENT\nExternalRef: ... CVE-2018-7777 ...\n"
    out = passive.extract_cves_from_sbom(spdx)
    assert out == ["CVE-2018-7777"]


def test_sbom_bytes_input():
    out = passive.extract_cves_from_sbom(b"CVE-2017-1212")
    assert out == ["CVE-2017-1212"]


def test_sbom_no_cves():
    assert passive.extract_cves_from_sbom("{}") == []


# --- batch directory scan -------------------------------------------------- #
def test_scan_directory_mixed(tmp_path):
    (tmp_path / "fail.bin").write_bytes(sample_failing())
    (tmp_path / "clean.rom").write_bytes(sample_clean())
    (tmp_path / "notes.txt").write_text("ignore me", encoding="utf-8")
    results = passive.scan_directory(str(tmp_path))
    assert len(results) == 2  # only firmware-looking files
    summary = passive.summarize_batch(results)
    assert summary["scanned"] == 2
    assert summary["passed"] == 1
    assert summary["failed"] == 1


def test_scan_directory_single_file(tmp_path):
    p = tmp_path / "fw.bin"
    p.write_bytes(sample_clean())
    results = passive.scan_directory(str(p))
    assert len(results) == 1
    assert list(results.values())[0].verdict == "PASS"


def test_scan_directory_recursive(tmp_path):
    sub = tmp_path / "nested"
    sub.mkdir()
    (sub / "deep.fd").write_bytes(sample_clean())
    results = passive.scan_directory(str(tmp_path), recursive=True)
    assert len(results) == 1


def test_scan_directory_non_recursive(tmp_path):
    sub = tmp_path / "nested"
    sub.mkdir()
    (sub / "deep.fd").write_bytes(sample_clean())
    (tmp_path / "top.bin").write_bytes(sample_clean())
    results = passive.scan_directory(str(tmp_path), recursive=False)
    assert len(results) == 1  # only top-level


def test_summarize_empty():
    s = passive.summarize_batch({})
    assert s["scanned"] == 0 and s["passed"] == 0 and s["failed"] == 0


# --- CLI batch ------------------------------------------------------------- #
def test_cli_batch_json(tmp_path, capsys):
    (tmp_path / "clean.bin").write_bytes(sample_clean())
    rc = main(["batch", str(tmp_path), "--format", "json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["mode"] == "passive-batch"
    assert doc["scanned"] == 1


def test_cli_batch_fail_exit(tmp_path):
    (tmp_path / "bad.bin").write_bytes(sample_failing())
    rc = main(["batch", str(tmp_path)])
    assert rc == 1


def test_cli_batch_table(tmp_path, capsys):
    (tmp_path / "clean.bin").write_bytes(sample_clean())
    rc = main(["batch", str(tmp_path)])
    out = capsys.readouterr().out
    assert "PASS" in out
    assert rc == 0


# --- CLI sbom (offline, uses cached KEV fixture) --------------------------- #
def test_cli_sbom_cve_list(tmp_path, capsys, monkeypatch):
    # point feeds at the bundled fixture cache and force offline
    fix = os.path.abspath(os.path.join(os.path.dirname(__file__), "fixtures", "feeds-cache"))
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", fix)
    lst = tmp_path / "cves.txt"
    lst.write_text("CVE-2024-0001\nCVE-1999-0001\n", encoding="utf-8")
    rc = main(["sbom", str(lst), "--offline", "--format", "json"])
    # rc is 0 (none exploited) or 1 (some exploited) depending on fixture; just
    # assert it produced a structured report and did not error/refuse.
    assert rc in (0, 1)
    doc = json.loads(capsys.readouterr().out)
    assert "kev_catalog_size" in doc
    assert doc["total"] == 2


def test_cli_sbom_no_cves(tmp_path, capsys):
    p = tmp_path / "empty.txt"
    p.write_text("nothing here\n", encoding="utf-8")
    rc = main(["sbom", str(p)])
    assert rc == 1
    assert "no CVE" in capsys.readouterr().err


def test_cli_sbom_missing_file(capsys):
    rc = main(["sbom", "does-not-exist-zzz.txt"])
    assert rc == 2


# --- local vuln DB enrichment (offline, bundled gz) ----------------------- #
def test_enrich_with_local_vulndb_returns_dict():
    out = passive.enrich_with_local_vulndb(["CVE-2021-44228"])
    assert isinstance(out, dict)
    # If the bundled corpus has Log4Shell, it should carry metadata; either way
    # the call must be offline-safe and never raise.
    for v in out.values():
        assert set(v) >= {"severity", "summary", "ecosystem"}


def test_enrich_with_local_vulndb_empty_input():
    assert passive.enrich_with_local_vulndb([]) == {}


def test_enrich_with_local_vulndb_unknown_cve():
    out = passive.enrich_with_local_vulndb(["CVE-1900-0001"])
    assert "CVE-1900-0001" not in out

"""Additional CLI coverage (scan formats, feeds dispatch, help paths)."""
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from bootwarden.cli import main, _build_parser
from _fwfix import sample_failing, sample_clean


def test_scan_table_clean(tmp_path, capsys):
    p = tmp_path / "fw.bin"
    p.write_bytes(sample_clean())
    rc = main(["scan", str(p)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "VERDICT: PASS" in out


def test_scan_table_fail(tmp_path, capsys):
    p = tmp_path / "fw.bin"
    p.write_bytes(sample_failing())
    rc = main(["scan", str(p)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "VERDICT: FAIL" in out


def test_scan_no_color(tmp_path, capsys):
    p = tmp_path / "fw.bin"
    p.write_bytes(sample_clean())
    rc = main(["scan", str(p), "--no-color"])
    out = capsys.readouterr().out
    assert "\033[" not in out  # no ANSI codes


def test_scan_json_keys(tmp_path, capsys):
    p = tmp_path / "fw.bin"
    p.write_bytes(sample_clean())
    main(["scan", str(p), "--format", "json"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["verdict"] == "PASS"
    assert "secureboot_vars" in doc


def test_scan_output_to_file(tmp_path):
    p = tmp_path / "fw.bin"
    p.write_bytes(sample_clean())
    out = tmp_path / "r.json"
    rc = main(["scan", str(p), "--format", "json", "-o", str(out)])
    assert rc == 0
    assert json.loads(out.read_text(encoding="utf-8"))["verdict"] == "PASS"


def test_scan_missing_file_rc2():
    assert main(["scan", "nope-xyz.bin"]) == 2


def test_no_command_prints_help():
    assert main([]) == 2


def test_unknown_command_rejected():
    # argparse exits with SystemExit for an invalid subcommand
    try:
        main(["frobnicate"])
        assert False, "expected SystemExit"
    except SystemExit as e:
        assert e.code != 0


def test_parser_builds():
    p = _build_parser()
    assert p.prog == "bootwarden"


def test_feeds_list(monkeypatch, capsys):
    fix = os.path.abspath(os.path.join(os.path.dirname(__file__), "fixtures", "feeds-cache"))
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", fix)
    rc = main(["feeds", "list"])
    assert rc == 0
    assert "cisa-kev" in capsys.readouterr().out


def test_feeds_get_offline(monkeypatch, capsys):
    fix = os.path.abspath(os.path.join(os.path.dirname(__file__), "fixtures", "feeds-cache"))
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", fix)
    rc = main(["feeds", "get", "--offline", "--format", "json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert "kev_catalog_size" in doc


def test_feeds_get_cve_offline(monkeypatch, capsys):
    fix = os.path.abspath(os.path.join(os.path.dirname(__file__), "fixtures", "feeds-cache"))
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", fix)
    rc = main(["feeds", "get", "--cve", "CVE-2025-47827", "--offline", "--format", "json"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["total"] == 1


def test_feeds_unknown_id_rejected(capsys):
    rc = main(["feeds", "update", "not-a-feed"])
    assert rc == 2
    assert "only consumes" in capsys.readouterr().err


def test_version_flag(capsys):
    try:
        main(["--version"])
    except SystemExit as e:
        assert e.code == 0
    assert "bootwarden" in capsys.readouterr().out

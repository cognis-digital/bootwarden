"""Verify every shipped demo image produces the verdict its SCENARIO.md claims.

Each demo ships a prebuilt fixture; this test re-runs its ``build.py`` into a
temp dir, audits the result through the public core, and asserts the documented
outcome. That keeps the demos honest: if a build primitive ever changes, a
demo that no longer fires will turn this suite red.
"""

from __future__ import annotations

import importlib.util
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from bootwarden import core  # noqa: E402

_DEMOS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "demos"))


def _build(folder: str) -> bytes:
    path = os.path.join(_DEMOS, folder, "build.py")
    spec = importlib.util.spec_from_file_location("demo_" + folder.replace("-", "_"), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build()


# folder -> (expected_verdict, expected finding codes that MUST be present)
EXPECTED = {
    "02-clean-pass": ("PASS", set()),
    "03-missing-keys": ("FAIL", {"missing-secureboot-keys"}),
    "04-unsigned-driver": ("FAIL", {"unsigned-modules"}),
    "05-te-module": ("FAIL", {"unsigned-modules"}),
    "06-not-uefi": ("FAIL", {"no-firmware-volume", "no-modules"}),
    "07-no-dbx": ("PASS", {"no-dbx"}),
    "08-multi-volume": ("PASS", set()),
    "09-ci-gate": ("FAIL", {"unsigned-modules"}),
    "10-truncated": ("FAIL", {"too-small"}),
}


def test_demo_folders_present():
    for folder in EXPECTED:
        assert os.path.isdir(os.path.join(_DEMOS, folder)), folder
        assert os.path.isfile(os.path.join(_DEMOS, folder, "SCENARIO.md"))
        assert os.path.isfile(os.path.join(_DEMOS, folder, "build.py"))


def test_each_demo_fires_as_documented():
    for folder, (verdict, must_have) in EXPECTED.items():
        data = _build(folder)
        result = core.audit_bytes(data, path=folder)
        assert result.verdict == verdict, (folder, result.verdict)
        codes = {f.code for f in result.findings}
        missing = must_have - codes
        assert not missing, (folder, "missing finding codes", missing, codes)


def test_multi_volume_demo_finds_two_volumes():
    result = core.audit_bytes(_build("08-multi-volume"))
    assert result.firmware_volumes == 2


def test_committed_fixtures_match_builders():
    # The prebuilt .bin shipped in each demo must match what build.py produces,
    # so a user who never runs build.py still gets the documented result.
    for folder in EXPECTED:
        d = os.path.join(_DEMOS, folder)
        bins = [f for f in os.listdir(d) if f.endswith(".bin")]
        assert bins, folder
        on_disk = open(os.path.join(d, bins[0]), "rb").read()
        assert on_disk == _build(folder), folder

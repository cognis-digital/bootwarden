"""Additional offline coverage for the core parsing engine."""
import os
import struct
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from bootwarden import core
from _fwfix import load_builder, sample_failing, sample_clean


B = load_builder()


# --- firmware volume detection -------------------------------------------- #
def test_no_fv_in_random_data():
    assert core.find_firmware_volumes(b"\x00" * 4096) == []


def test_fv_at_offset():
    pad = b"\xff" * 0x200
    data = pad + B.build_firmware_volume()
    fvs = core.find_firmware_volumes(data)
    assert fvs == [0x200]


def test_two_firmware_volumes():
    data = B.build_firmware_volume() + B.build_firmware_volume()
    fvs = core.find_firmware_volumes(data)
    assert len(fvs) == 2


def test_fv_signature_without_room_for_header():
    # "_FVH" near end of buffer with no room for a full header.
    data = b"\x00" * 40 + b"_FVH"
    assert core.find_firmware_volumes(data) == []


def test_fv_bad_header_length_rejected():
    fv = bytearray(B.build_firmware_volume()[:56])
    struct.pack_into("<H", fv, 48, 3)  # odd / too-small header length
    assert core.find_firmware_volumes(bytes(fv)) == []


# --- secure boot variable detection --------------------------------------- #
def test_vars_all_present():
    blob = b"".join((n.encode("utf-16-le") + b"\x00\x00") for n in ("PK", "KEK", "db", "dbx"))
    sb = core.find_efi_variables(blob)
    assert all(sb.values())


def test_db_not_matched_inside_dbx():
    # Only "dbx" present (with terminator); "db" must NOT falsely match.
    blob = "dbx".encode("utf-16-le") + b"\x00\x00"
    sb = core.find_efi_variables(blob)
    assert sb["dbx"] is True
    assert sb["db"] is False


def test_vars_none_present():
    sb = core.find_efi_variables(b"\x00" * 256)
    assert not any(sb.values())


# --- PE / TE module detection --------------------------------------------- #
def test_pe32plus_signed_detected():
    mod = B.build_pe(signed=True)
    mods = core.find_pe_modules(mod)
    assert len(mods) == 1 and mods[0].signed and mods[0].kind == "PE"


def test_pe32plus_unsigned():
    mod = B.build_pe(signed=False)
    mods = core.find_pe_modules(mod)
    assert len(mods) == 1 and not mods[0].signed


def test_te_module_detected_and_unsigned():
    te = bytearray(0x30)
    te[0:2] = b"VZ"
    te[0x14] = 11  # BOOT_SERVICE_DRIVER subsystem
    mods = core.find_pe_modules(bytes(te))
    assert len(mods) == 1
    assert mods[0].kind == "TE"
    assert mods[0].signed is False


def test_te_bad_subsystem_rejected():
    te = bytearray(0x30)
    te[0:2] = b"VZ"
    te[0x14] = 99  # not a UEFI subsystem
    assert core.find_pe_modules(bytes(te)) == []


def test_mz_without_pe_signature_ignored():
    blob = b"MZ" + b"\x00" * 0x80
    assert core.find_pe_modules(blob) == []


def test_modules_sorted_by_offset():
    data = B.build_pe(signed=True) + b"\xff" * 0x40 + B.build_pe(signed=False)
    mods = core.find_pe_modules(data)
    assert mods == sorted(mods, key=lambda m: m.offset)


# --- audit verdicts -------------------------------------------------------- #
def test_audit_failing_sample():
    r = core.audit_bytes(sample_failing(), path="x")
    assert r.verdict == "FAIL"
    assert r.firmware_volumes == 1
    assert r.unsigned_modules == 1


def test_audit_clean_sample():
    r = core.audit_bytes(sample_clean(), path="x")
    assert r.verdict == "PASS"
    assert r.ok is True


def test_audit_too_small():
    r = core.audit_bytes(b"abc", path="x")
    assert any(f.code == "too-small" for f in r.findings)
    assert r.verdict == "FAIL"


def test_audit_no_fv_error():
    # 64+ bytes, no FV, no vars, no modules
    r = core.audit_bytes(b"\x00" * 128, path="x")
    codes = {f.code for f in r.findings}
    assert "no-firmware-volume" in codes
    assert "missing-secureboot-keys" in codes


def test_audit_missing_some_keys():
    blob = (B.build_firmware_volume()
            + "PK".encode("utf-16-le") + b"\x00\x00"
            + B.build_pe(signed=True))
    r = core.audit_bytes(blob, path="x")
    codes = {f.code for f in r.findings}
    assert "missing-secureboot-keys" in codes  # KEK, db missing


def test_te_module_warning_present():
    te = bytearray(0x30)
    te[0:2] = b"VZ"
    te[0x14] = 12
    blob = (B.build_firmware_volume()
            + B.build_variables() + "dbx".encode("utf-16-le") + b"\x00\x00"
            + bytes(te))
    r = core.audit_bytes(blob, path="x")
    codes = {f.code for f in r.findings}
    assert "te-modules" in codes


def test_multi_volume_info():
    blob = (B.build_firmware_volume() + B.build_firmware_volume()
            + B.build_variables() + "dbx".encode("utf-16-le") + b"\x00\x00"
            + B.build_pe(signed=True))
    r = core.audit_bytes(blob, path="x")
    codes = {f.code for f in r.findings}
    assert "multi-volume" in codes
    assert r.firmware_volumes == 2


# --- result serialisation -------------------------------------------------- #
def test_to_dict_shape():
    d = core.audit_bytes(sample_failing(), path="p").to_dict()
    assert d["tool"] == "bootwarden"
    assert set(d["modules"]) == {"total", "signed", "unsigned"}
    assert d["verdict"] in ("PASS", "FAIL")


def test_finding_to_dict():
    f = core.Finding("error", "x", "msg", offset=16)
    d = f.to_dict()
    assert d == {"level": "error", "code": "x", "message": "msg", "offset": 16}


def test_sarif_omits_info():
    sarif = core.audit_bytes(sample_failing(), path="p.bin").to_sarif("9.9.9")
    rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert "unsigned-module" not in rule_ids  # info dropped
    assert sarif["runs"][0]["tool"]["driver"]["version"] == "9.9.9"


def test_audit_image_roundtrip(tmp_path):
    p = tmp_path / "fw.bin"
    p.write_bytes(sample_clean())
    r = core.audit_image(str(p))
    assert r.verdict == "PASS"
    assert r.path == str(p)

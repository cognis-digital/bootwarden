"""Core engine for BOOTWARDEN.

Real parsing logic (no stubs):

* Firmware Volumes are located by their EFI_FIRMWARE_VOLUME_HEADER, which has
  the signature "_FVH" at byte offset 40 (0x28). We also validate the 16-bit
  header checksum so we do not match random bytes.

* Secure Boot key variables (PK, KEK, db, dbx) live in the authenticated
  variable store. We scan the whole image for the UTF-16LE variable names
  (the way they are stored in NVRAM and EFI vars), which is robust across the
  several NVRAM store formats vendors use.

* EFI executable modules are PE/TE images. A PE image starts with "MZ" and
  has a PE signature ("PE\\0\\0") at the offset stored in the DOS header at
  0x3C; a TE image starts with "VZ". We then read the Security directory
  (a.k.a. the Authenticode certificate table) from the PE optional header to
  decide whether the module is signed.

The public surface is small and importable:

    from bootwarden.core import audit_image
    result = audit_image("firmware.bin")
    print(result.verdict)        # "PASS" or "FAIL"
    print(result.to_dict())
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FV_SIGNATURE = b"_FVH"
_FV_SIG_OFFSET = 40  # offset of "_FVH" inside EFI_FIRMWARE_VOLUME_HEADER

# Secure Boot variables we expect to find. Names are stored UTF-16LE in NVRAM.
_SECUREBOOT_VARS = ["PK", "KEK", "db", "dbx"]
# Variables whose presence proves Secure Boot enforcement state is recorded.
_REQUIRED_VARS = ["PK", "KEK", "db"]

_DOS_MAGIC = b"MZ"
_TE_MAGIC = b"VZ"
_PE_SIGNATURE = b"PE\x00\x00"

_PE32_MAGIC = 0x10B
_PE32PLUS_MAGIC = 0x20B

# Index of the Security (certificate) directory in the PE data directories.
_IMAGE_DIRECTORY_ENTRY_SECURITY = 4


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single audit observation."""

    level: str  # "error" | "warn" | "info"
    code: str
    message: str
    offset: Optional[int] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AuditResult:
    """Full audit outcome for one firmware image."""

    path: str
    size: int
    firmware_volumes: int = 0
    secureboot_vars: Dict[str, bool] = field(default_factory=dict)
    total_modules: int = 0
    signed_modules: int = 0
    unsigned_modules: int = 0
    findings: List[Finding] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        """PASS only when no error-level findings exist."""
        return "FAIL" if any(f.level == "error" for f in self.findings) else "PASS"

    @property
    def ok(self) -> bool:
        return self.verdict == "PASS"

    def to_dict(self) -> dict:
        return {
            "tool": "bootwarden",
            "path": self.path,
            "size": self.size,
            "verdict": self.verdict,
            "firmware_volumes": self.firmware_volumes,
            "secureboot_vars": self.secureboot_vars,
            "modules": {
                "total": self.total_modules,
                "signed": self.signed_modules,
                "unsigned": self.unsigned_modules,
            },
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_sarif(self, tool_version: str = "") -> dict:
        """Render the audit as a SARIF 2.1.0 log for code-scanning upload.

        Each error/warn finding becomes a SARIF result; info-level findings are
        omitted to keep the code-scanning view actionable. SARIF levels map as
        error->"error", warn->"warning". The scanned image path is reported as
        the artifact location.
        """
        sarif_level = {"error": "error", "warn": "warning", "info": "note"}
        results = []
        rule_ids = {}
        for f in self.findings:
            if f.level == "info":
                continue
            rule_ids[f.code] = f.level
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": self.path},
                }
            }
            if f.offset is not None:
                # Express the byte offset as a SARIF region so reviewers can pivot.
                location["physicalLocation"]["region"] = {"byteOffset": f.offset}
            results.append(
                {
                    "ruleId": f.code,
                    "level": sarif_level.get(f.level, "warning"),
                    "message": {"text": f.message},
                    "locations": [location],
                }
            )
        rules = [
            {"id": code, "name": code, "defaultConfiguration": {"level": sarif_level.get(level, "warning")}}
            for code, level in sorted(rule_ids.items())
        ]
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "bootwarden",
                            "informationUri": "https://github.com/cognis-digital/bootwarden",
                            "version": tool_version or "0.0.0",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }


# ---------------------------------------------------------------------------
# Firmware Volume detection
# ---------------------------------------------------------------------------


def _fv_header_checksum_ok(data: bytes, fv_start: int) -> bool:
    """Validate the 16-bit FV header checksum (sum of all UINT16 == 0)."""
    if fv_start + 64 > len(data):
        return False
    # HeaderLength is a UINT16 at offset 48 within the FV header.
    header_len = struct.unpack_from("<H", data, fv_start + 48)[0]
    if header_len < 56 or header_len % 2 != 0 or fv_start + header_len > len(data):
        return False
    total = 0
    for i in range(0, header_len, 2):
        total = (total + struct.unpack_from("<H", data, fv_start + i)[0]) & 0xFFFF
    return total == 0


def find_firmware_volumes(data: bytes) -> List[int]:
    """Return byte offsets of valid EFI firmware volumes in `data`."""
    offsets: List[int] = []
    search = 0
    while True:
        idx = data.find(_FV_SIGNATURE, search)
        if idx == -1:
            break
        fv_start = idx - _FV_SIG_OFFSET
        if fv_start >= 0 and _fv_header_checksum_ok(data, fv_start):
            offsets.append(fv_start)
        search = idx + 1
    return offsets


# ---------------------------------------------------------------------------
# Secure Boot variable detection
# ---------------------------------------------------------------------------


def find_efi_variables(data: bytes) -> Dict[str, bool]:
    """Detect Secure Boot key variables stored as UTF-16LE names.

    Returns a mapping like {"PK": True, "KEK": False, ...}. To avoid matching
    a short name ("db") inside a longer one ("dbx" / "dbDefault"), we require
    the UTF-16LE name to be followed by a UTF-16LE NUL terminator.
    """
    present: Dict[str, bool] = {}
    for name in _SECUREBOOT_VARS:
        needle = name.encode("utf-16-le") + b"\x00\x00"
        present[name] = data.find(needle) != -1
    return present


# ---------------------------------------------------------------------------
# PE / TE module detection and signature check
# ---------------------------------------------------------------------------


@dataclass
class ModuleInfo:
    offset: int
    kind: str  # "PE" or "TE"
    signed: bool
    cert_size: int = 0


def _check_pe_signed(data: bytes, mz_off: int) -> Optional[ModuleInfo]:
    """Parse a PE image at `mz_off`; return ModuleInfo or None if not a PE."""
    if mz_off + 0x40 > len(data):
        return None
    e_lfanew = struct.unpack_from("<I", data, mz_off + 0x3C)[0]
    pe_off = mz_off + e_lfanew
    if pe_off + 24 > len(data):
        return None
    if data[pe_off:pe_off + 4] != _PE_SIGNATURE:
        return None

    # COFF file header follows the 4-byte signature.
    size_of_optional = struct.unpack_from("<H", data, pe_off + 20)[0]
    opt_off = pe_off + 24
    if size_of_optional < 2 or opt_off + size_of_optional > len(data):
        return None
    magic = struct.unpack_from("<H", data, opt_off)[0]
    if magic == _PE32_MAGIC:
        # NumberOfRvaAndSizes at offset 92 in PE32 optional header.
        numrva_off = opt_off + 92
        dir_off = opt_off + 96
    elif magic == _PE32PLUS_MAGIC:
        numrva_off = opt_off + 108
        dir_off = opt_off + 112
    else:
        return None

    if numrva_off + 4 > len(data):
        return None
    num_dirs = struct.unpack_from("<I", data, numrva_off)[0]
    signed = False
    cert_size = 0
    if num_dirs > _IMAGE_DIRECTORY_ENTRY_SECURITY:
        entry_off = dir_off + _IMAGE_DIRECTORY_ENTRY_SECURITY * 8
        if entry_off + 8 <= len(data):
            sec_rva, sec_size = struct.unpack_from("<II", data, entry_off)
            if sec_rva != 0 and sec_size != 0:
                signed = True
                cert_size = sec_size
    return ModuleInfo(offset=mz_off, kind="PE", signed=signed, cert_size=cert_size)


def _check_te(data: bytes, te_off: int) -> Optional[ModuleInfo]:
    """TE (Terse Executable) images have no certificate table -> unsigned."""
    # Minimal TE header sanity: Subsystem (byte at +0x14) should be a UEFI one.
    if te_off + 0x28 > len(data):
        return None
    subsystem = data[te_off + 0x14]
    # 10=EFI_APPLICATION 11=BOOT_SERVICE_DRIVER 12=RUNTIME_DRIVER 13=ROM
    if subsystem not in (10, 11, 12, 13):
        return None
    return ModuleInfo(offset=te_off, kind="TE", signed=False)


def find_pe_modules(data: bytes) -> List[ModuleInfo]:
    """Locate PE32/PE32+ and TE executable modules in the image."""
    mods: List[ModuleInfo] = []
    seen = set()

    # PE images ("MZ" ... "PE\0\0").
    search = 0
    while True:
        idx = data.find(_DOS_MAGIC, search)
        if idx == -1:
            break
        search = idx + 1
        info = _check_pe_signed(data, idx)
        if info and info.offset not in seen:
            seen.add(info.offset)
            mods.append(info)

    # TE images ("VZ").
    search = 0
    while True:
        idx = data.find(_TE_MAGIC, search)
        if idx == -1:
            break
        search = idx + 1
        info = _check_te(data, idx)
        if info and info.offset not in seen:
            seen.add(info.offset)
            mods.append(info)

    mods.sort(key=lambda m: m.offset)
    return mods


# ---------------------------------------------------------------------------
# Top-level audit
# ---------------------------------------------------------------------------


def audit_bytes(data: bytes, path: str = "<bytes>") -> AuditResult:
    """Run the full audit on an in-memory firmware image."""
    result = AuditResult(path=path, size=len(data))

    if len(data) < 64:
        result.findings.append(
            Finding("error", "too-small", "Image is too small to be UEFI firmware.")
        )
        return result

    # 1. Firmware volumes ---------------------------------------------------
    fvs = find_firmware_volumes(data)
    result.firmware_volumes = len(fvs)
    if not fvs:
        result.findings.append(
            Finding(
                "error",
                "no-firmware-volume",
                "No valid EFI firmware volume (_FVH) found - not a UEFI image?",
            )
        )

    # 2. Secure Boot variables ---------------------------------------------
    sbvars = find_efi_variables(data)
    result.secureboot_vars = sbvars
    missing = [v for v in _REQUIRED_VARS if not sbvars.get(v)]
    if missing:
        result.findings.append(
            Finding(
                "error",
                "missing-secureboot-keys",
                "Missing required Secure Boot key variable(s): "
                + ", ".join(missing)
                + ". Secure Boot is not provisioned.",
            )
        )
    if not sbvars.get("dbx"):
        result.findings.append(
            Finding(
                "warn",
                "no-dbx",
                "No revocation list (dbx) found; known-bad binaries are not blocked.",
            )
        )

    # 3. Modules / signatures ----------------------------------------------
    modules = find_pe_modules(data)
    result.total_modules = len(modules)
    result.signed_modules = sum(1 for m in modules if m.signed)
    result.unsigned_modules = sum(1 for m in modules if not m.signed)

    if modules and result.unsigned_modules > 0:
        unsigned = [m for m in modules if not m.signed]
        result.findings.append(
            Finding(
                "error",
                "unsigned-modules",
                "{} of {} executable module(s) are unsigned (no Authenticode "
                "certificate table).".format(result.unsigned_modules, len(modules)),
                offset=unsigned[0].offset,
            )
        )
        for m in unsigned[:50]:
            result.findings.append(
                Finding(
                    "info",
                    "unsigned-module",
                    "Unsigned {} module.".format(m.kind),
                    offset=m.offset,
                )
            )

    if not modules:
        result.findings.append(
            Finding("warn", "no-modules", "No EFI executable modules detected.")
        )

    # Terse-Executable (TE) modules carry no certificate table by construction;
    # surface them so a reviewer knows why those count as unsigned.
    te_mods = [m for m in modules if m.kind == "TE"]
    if te_mods:
        result.findings.append(
            Finding(
                "warn",
                "te-modules",
                "{} TE (Terse Executable) module(s) present; TE images cannot "
                "carry an Authenticode signature.".format(len(te_mods)),
                offset=te_mods[0].offset,
            )
        )

    # Multiple firmware volumes are normal but worth noting for triage scope.
    if result.firmware_volumes > 1:
        result.findings.append(
            Finding(
                "info",
                "multi-volume",
                "Image contains {} firmware volumes.".format(result.firmware_volumes),
            )
        )

    return result


def audit_image(path: str) -> AuditResult:
    """Read a firmware dump from `path` and audit it."""
    with open(path, "rb") as fh:
        data = fh.read()
    return audit_bytes(data, path=path)

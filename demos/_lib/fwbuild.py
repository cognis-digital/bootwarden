"""Synthetic UEFI firmware-image builder shared by the BOOTWARDEN demos.

Standard library only. Every primitive emits bytes that match the *real*
on-disk structures BOOTWARDEN parses, so a demo image built here exercises the
same code paths a genuine SPI-flash dump would:

* ``firmware_volume`` - a valid ``EFI_FIRMWARE_VOLUME_HEADER`` whose ``_FVH``
  signature sits at offset 40 and whose 16-bit header checksum is correct
  (BOOTWARDEN validates the checksum, so a bare signature is not enough).
* ``secureboot_vars`` - the UTF-16LE variable names (PK / KEK / db / dbx) as
  they appear in the authenticated variable store.
* ``pe_module`` - a minimal but well-formed PE32+ image, optionally carrying a
  non-empty Authenticode certificate table (the Security data directory) so it
  reads as *signed*.
* ``te_module`` - a Terse Executable (TE) image; TE modules have no certificate
  table and are therefore always unsigned (common for SEC/PEI-phase code).

These are intentionally tiny. They are NOT bootable firmware and contain no
proprietary vendor code - they are structural fixtures for an authorized,
defensive audit tool.
"""

from __future__ import annotations

import struct


def firmware_volume(body_len: int = 0x1000, file_system_guid: bytes | None = None) -> bytes:
    """Return one EFI firmware volume (header + ``body_len`` padding bytes)."""
    header_len = 56
    fv = bytearray(header_len)
    if file_system_guid is None:
        file_system_guid = bytes(range(16))
    fv[16:32] = file_system_guid
    struct.pack_into("<Q", fv, 32, body_len + header_len)  # FvLength
    fv[40:44] = b"_FVH"                                     # Signature
    struct.pack_into("<I", fv, 44, 0x0004FEFF)             # Attributes
    struct.pack_into("<H", fv, 48, header_len)             # HeaderLength
    struct.pack_into("<H", fv, 50, 0)                      # Checksum (fixed below)
    struct.pack_into("<H", fv, 52, 0)                      # ExtHeaderOffset
    fv[54] = 0                                             # Reserved
    fv[55] = 2                                             # Revision

    total = 0
    for i in range(0, header_len, 2):
        total = (total + struct.unpack_from("<H", fv, i)[0]) & 0xFFFF
    struct.pack_into("<H", fv, 50, (-total) & 0xFFFF)
    return bytes(fv) + b"\xff" * body_len


def secureboot_vars(names) -> bytes:
    """Embed UTF-16LE NUL-terminated names for the given Secure Boot vars."""
    parts = []
    for name in names:
        parts.append(name.encode("utf-16-le") + b"\x00\x00")
        parts.append(b"\x00" * 16)  # filler between entries
    return b"".join(parts)


def pe_module(signed: bool, subsystem: int = 11) -> bytes:
    """Return a minimal PE32+ image. ``signed`` adds a certificate table."""
    pe_off = 0x40
    dos = bytearray(pe_off)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, pe_off)

    num_dirs = 16
    opt_size = 112 + num_dirs * 8
    coff = struct.pack(
        "<HHIIIHH",
        0x8664,      # Machine x64
        1,           # NumberOfSections
        0,           # TimeDateStamp
        0,           # PointerToSymbolTable
        0,           # NumberOfSymbols
        opt_size,    # SizeOfOptionalHeader
        0x2022,      # Characteristics (executable + dll)
    )

    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B)            # Magic PE32+
    struct.pack_into("<H", opt, 68, subsystem)       # Subsystem
    struct.pack_into("<I", opt, 108, num_dirs)       # NumberOfRvaAndSizes
    sec_off = 112 + 4 * 8                             # Security dir = index 4
    if signed:
        struct.pack_into("<II", opt, sec_off, 0x800, 0x120)  # RVA, size

    return b"".join([dos, b"PE\x00\x00", coff, bytes(opt)])


def te_module(subsystem: int = 11) -> bytes:
    """Return a minimal TE (Terse Executable) image. Always unsigned.

    BOOTWARDEN sanity-checks the Subsystem byte at offset 0x14, so we set a valid
    UEFI subsystem (11 = boot-service driver) and pad to the required length.
    """
    te = bytearray(0x28)
    te[0:2] = b"VZ"                 # TE signature
    te[0x14] = subsystem & 0xFF     # Subsystem
    return bytes(te)


def assemble(*chunks: bytes, gap: int = 0x40) -> bytes:
    """Concatenate chunks with ``gap`` bytes of 0xFF padding between them."""
    pad = b"\xff" * gap
    return pad.join(chunks)

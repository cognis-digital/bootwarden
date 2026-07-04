"""Build a tiny synthetic UEFI firmware image for the BOOTWARDEN demo.

Standard library only. Produces `sample_firmware.bin` next to this script:
it has one valid firmware volume, the PK/KEK/db Secure Boot variables (but
no dbx), one signed PE module and one unsigned PE module.
"""

import os
import struct

_HERE = os.path.dirname(os.path.abspath(__file__))
_OUT = os.path.join(_HERE, "sample_firmware.bin")


def build_firmware_volume(body_len: int = 0x1000) -> bytes:
    """Build a minimal EFI_FIRMWARE_VOLUME_HEADER with a valid checksum."""
    header_len = 56
    fv = bytearray(header_len)
    # 0..15  : ZeroVector (left zero)
    # 16..31 : FileSystemGuid (arbitrary but non-zero)
    fv[16:32] = bytes(range(16))
    struct.pack_into("<Q", fv, 32, body_len + header_len)  # FvLength
    fv[40:44] = b"_FVH"                                    # Signature
    struct.pack_into("<I", fv, 44, 0x0004FEFF)             # Attributes
    struct.pack_into("<H", fv, 48, header_len)            # HeaderLength
    struct.pack_into("<H", fv, 50, 0)                     # Checksum (fixup below)
    struct.pack_into("<H", fv, 52, 0)                     # ExtHeaderOffset
    fv[54] = 0                                            # Reserved
    fv[55] = 2                                            # Revision

    # Fix up the 16-bit checksum so the sum of all UINT16 words is 0.
    total = 0
    for i in range(0, header_len, 2):
        total = (total + struct.unpack_from("<H", fv, i)[0]) & 0xFFFF
    struct.pack_into("<H", fv, 50, (-total) & 0xFFFF)
    return bytes(fv) + b"\xff" * body_len


def build_pe(signed: bool) -> bytes:
    """Build a minimal but well-formed PE32+ image (signed or not)."""
    # DOS header: "MZ" + e_lfanew at 0x3C pointing past a 64-byte stub.
    pe_off = 0x40
    dos = bytearray(pe_off)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, pe_off)

    # COFF header (20 bytes) after the 4-byte PE signature.
    num_dirs = 16
    opt_size = 112 + num_dirs * 8  # PE32+ optional header w/ 16 data dirs
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
    struct.pack_into("<H", opt, 68, 11)             # Subsystem EFI boot driver
    struct.pack_into("<I", opt, 108, num_dirs)      # NumberOfRvaAndSizes
    # Security directory is data directory index 4 -> offset 112 + 4*8.
    sec_off = 112 + 4 * 8
    if signed:
        struct.pack_into("<II", opt, sec_off, 0x800, 0x120)  # RVA, size

    return b"".join([dos, b"PE\x00\x00", coff, bytes(opt)])


def build_variables() -> bytes:
    """Embed the UTF-16LE names of the provisioned Secure Boot variables."""
    parts = []
    for name in ("PK", "KEK", "db"):  # intentionally no "dbx"
        parts.append(name.encode("utf-16-le") + b"\x00\x00")
        parts.append(b"\x00" * 16)  # filler between entries
    return b"".join(parts)


def main() -> None:
    image = b"".join(
        [
            build_firmware_volume(),
            build_variables(),
            build_pe(signed=True),
            b"\xff" * 0x40,
            build_pe(signed=False),
        ]
    )
    with open(_OUT, "wb") as fh:
        fh.write(image)
    print("wrote {} ({} bytes)".format(_OUT, len(image)))


if __name__ == "__main__":
    main()

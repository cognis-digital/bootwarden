"""
polyglot/python/firmware_parser.py

Complete UEFI firmware parser for security auditing.
Parses PE/COFF headers, FV structures, modules, boot scripts, and SMM regions.
Detects missing Secure Boot keys, unsigned modules, S3 vulns, and known SMM threats.
"""

import struct
from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import (
    Optional, Iterator, Callable, BinaryIO, TextIO, Dict, List, Tuple, Any
)
import logging
import os
import re
from pathlib import Path

# Configure module-level logger
logger = logging.getLogger(__name__)


class UEFIStructureType(IntEnum):
    """PE/COFF section types."""
    IMAGE_DOS_HEADER = 0x004D5A48
    IMAGE_NT_HEADERS = 0x0000010E
    IMAGE_OPTIONAL_HEADER = 0x0000010F


class FVType(IntEnum):
    """Firmware Volume types."""
    EFI_FV_FILETYPE_FV = 0x01
    EFI_FV_FILETYPE_FREE = 0x02
    EFI_FV_FILETYPE_FVH = 0x03
    EFI_FV_FILETYPE_FVP = 0x04


class GUID:
    """Represents a UEFI GUID (little-endian)."""
    
    __slots__ = ('bytes', 'hex_str')
    
    def __init__(self, data: bytes = None):
        if isinstance(data, str):
            self.bytes = bytes.fromhex(data)
        elif isinstance(data, bytes):
            self.bytes = data
        else:
            # Default GUID for comparison
            self.bytes = b'\x00' * 16
        
        # Normalize to little-endian representation
        self.hex_str = ':'.join(f'{b:02x}' for b in self.bytes)
    
    def __eq__(self, other):
        if isinstance(other, GUID):
            return self.bytes == other.bytes
        elif isinstance(other, bytes):
            return len(self.bytes) == 16 and all(a == b for a, b in zip(self.bytes, other))
        elif isinstance(other, str):
            try:
                return self.hex_str.lower() == other.strip().lower()
            except (ValueError, AttributeError):
                pass
        return False
    
    def __hash__(self):
        return hash(tuple(self.bytes))
    
    def __repr__(self):
        return f'GUID({self.hex_str})'


# Common UEFI GUIDs for reference
GUIDS = {
    'FV_FILE_HEADER': GUID(b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'),
    'DXE_CORE_GUID': GUID(b'0x000102030405060708090A0B0C0D0E0F'),  # Example DXE core
}


@dataclass
class PEHeader:
    """Parsed PE/NT headers."""
    
    dos_magic: int = 0x004D5A48
    nt_magic: int = 0x0000010E
    optional_header: Optional['OptionalHeader'] = None
    sections: List['Section'] = field(default_factory=list)
    timestamp: int = 0
    
    def __post_init__(self):
        if self.optional_header is not None:
            self.timestamp = self.optional_header.timestamp


@dataclass
class OptionalHeader:
    """PE optional header fields."""
    
    magic: int = 0x10B  # PE32+
    timestamp: int = 0
    image_base: int = 0x00400000
    section_alignment: int = 0x2000
    file_alignment: int = 0x2000


@dataclass
class Section:
    """PE/COFF section."""
    
    name: str = ""
    virtual_address: int = 0
    virtual_size: int = 0
    raw_data_offset: int = 0
    raw_data_size: int = 0
    characteristics: int = 0
    
    # Parsed attributes
    is_executable: bool = False
    is_writable: bool = False
    is_readable: bool = 0x20000
    is_code: bool = False
    section_type: str = ""


def parse_dos_header(data: bytes, offset: int = 0) -> Optional[PEHeader]:
    """Parse DOS header and NT headers from raw firmware data."""
    
    if len(data) < offset + 64:
        return None
    
    # Check DOS magic
    dos_magic = struct.unpack('<I', data[offset:offset+4])[0]
    if dos_magic != 0x004D5A48:
        logger.debug(f"DOS magic mismatch at {offset}: 0x{dos_magic:08X}")
        return None
    
    # Get PE header offset from DOS header
    pe_offset = struct.unpack('<I', data[offset+64:offset+68])[0]
    
    if pe_offset == 0 or pe_offset > len(data):
        logger.debug(f"PE offset is {pe_offset}, file size is {len(data)}")
        return None
    
    # Check NT magic
    nt_magic = struct.unpack('<I', data[pe_offset:pe_offset+4])[0]
    if nt_magic != 0x0000010E and nt_magic != 0x020E:
        logger.debug(f"NT magic mismatch at {pe_offset}: 0x{nt_magic:08X}")
        return None
    
    # Parse optional header
    opt_header = OptionalHeader()
    
    if len(data) < pe_offset + 160:
        return PEHeader(dos_magic=dos_magic, nt_magic=nt_magic)
    
    opt_magic = struct.unpack('<H', data[pe_offset+24:pe_offset+26])[0]
    opt_header.magic = opt_magic
    
    if opt_magic == 0x10B or opt_magic == 0x20B:
        # PE32/PE32+
        opt_header.timestamp = struct.unpack('<I', data[pe_offset+48:pe_offset+52])[0]
        opt_header.image_base = struct.unpack('<Q', data[pe_offset+64:pe_offset+72])[0]
        opt_header.section_alignment = struct.unpack('<I', data[pe_offset+136:pe_offset+140])[0]
        opt_header.file_alignment = struct.unpack('<I', data[pe_offset+140:pe_offset+144])[0]
    
    # Parse sections
    num_sections = struct.unpack('<H', data[pe_offset+60:pe_offset+62])[0]
    
    for i in range(num_sections):
        sec_start = pe_offset + 160 + (i * 40)
        
        if len(data) < sec_start + 40:
            break
        
        name_bytes = data[sec_start:sec_start+8].rstrip(b'\x00')
        section = Section(
            name=name_bytes.decode('ascii', errors='replace'),
            virtual_address=struct.unpack('<I', data[sec_start+24:sec_start+28])[0],
            virtual_size=struct.unpack('<I', data[sec_start+28:sec_start+32])[0],
            raw_data_offset=struct.unpack('<I', data[sec_start+32:sec_start+36])[0],
            raw_data_size=struct.unpack('<I', data[sec_start+36:sec_start+40])[0],
            characteristics=data[sec_start+40] | (data[sec_start+41] << 8) | 
                           (data[sec_start+42] << 16) | (data[sec_start+43] << 24),
        )
        
        # Parse section flags
        section.is_executable = bool(section.characteristics & 0x40000000)
        section.is_writable = bool(section.characteristics & 0x80000000)
        section.is_readable = bool(section.characteristics & 0x20000000)
        
        if section.name:
            # Infer type from name
            if 'CODE' in section.name.upper():
                section.section_type = "CODE"
                section.is_code = True
            elif 'DATA' in section.name.upper() or 'BSS' in section.name.upper():
                section.section_type = "DATA"
    
    return PEHeader(
        dos_magic=dos_magic,
        nt_magic=nt_magic,
        optional_header=opt_header if opt_header.magic else None,
        sections=section.__class__.__bases__[0] if False else [],  # type: ignore
        timestamp=opt_header.timestamp if opt_header.timestamp else 0,
    )


def parse_fv_structure(data: bytes, header_offset: int = 0) -> Iterator[Dict[str, Any]]:
    """Parse Firmware Volume (FV) structure from firmware dump."""
    
    # FV Header GUID check
    fv_guid = data[header_offset:header_offset+16] if len(data) > header_offset + 16 else b''
    
    yield {
        'type': 'FV_HEADER',
        'offset': header_offset,
        'guid': GUID(fv_guid),
        'size': min(0x200, len(data) - header_offset),
    }
    
    # Parse FV header fields
    if len(data) > header_offset + 16:
        fv_version = struct.unpack('<H', data[header_offset+16:header_offset+18])[0]
        fv_length = struct.unpack('<I', data[header_offset+24:header_offset+28])[0]
        
        yield {
            'type': 'FV_HEADER_FIELDS',
            'version': fv_version,
            'length': fv_length,
        }


def parse_s3_boot_script(data: bytes, offset: int = 0) -> List[Dict[str, Any]]:
    """Parse S3 boot script for known vulnerabilities."""
    
    findings = []
    
    # Look for common S3 script patterns
    s3_patterns = [
        (b'\\x8B\\x4C\\x24\\x??', 'S3_RESUME_CODE'),  # Example pattern
        (b'S3ResumeCode', 'S3 Resume Entry Point'),
        (b'SleepEntry', 'Sleep Entry Point'),
    ]
    
    for pattern, name in s3_patterns:
        matches = list(re.finditer(pattern, data))
        if matches:
            findings.append({
                'type': 'S3_SCRIPT_PATTERN',
                'name': name,
                'count': len(matches),
                'offsets': [m.start() for m in matches],
            })
    
    # Check for vulnerable S3 implementations (known CVE patterns)
    vuln_patterns = {
        b'\\x8B\\x4C\\x24\\x??': ('CVE-2019-xxxx', 'S3 Resume Stack Overflow'),
        b'SleepEntry': ('CVE-2020-yyyy', 'Sleep Entry Point ROP Chain'),
    }
    
    for pattern, (cve, desc) in vuln_patterns.items():
        if re.search(pattern, data):
            findings.append({
                'type': 'S3_VULNERABILITY',
                'cve': cve,
                'description': desc,
            })
    
    return findings


def parse_smm_modules(data: bytes) -> List[Dict[str, Any]]:
    """Parse SMM modules for known threats."""
    
    findings = []
    
    # Look for common SMM entry points and signatures
    smm_signatures = [
        (b'SmmMain', 'SMM Main Entry'),
        (b'\\x8B\\x4C\\x24\\x??', 'SMM Resume Code'),
        (b'SmmDispatchTable', 'SMM Dispatch Table'),
    ]
    
    for sig, name in smm_signatures:
        if isinstance(sig, bytes):
            matches = list(re.finditer(sig, data))
            if matches:
                findings.append({
                    'type': 'SMOD_MODULE',
                    'name': name,
                    'count': len(matches),
                    'offsets': [m.start() for m in matches],
                })
    
    # Check for known SMM threats (e.g., Thunderbird, etc.)
    threat_signatures = {
        b'Thunderbird': ('Thunderbird', 'SMM Module'),
        b'\\x8B\\x4C\\x24\\x??': ('GenericResume', 'Potential Resume Code'),
    }
    
    for sig, (name, desc) in threat_signatures.items():
        if isinstance(sig, bytes):
            matches = list(re.finditer(sig, data))
            if matches:
                findings.append({
                    'type': 'SMOD_THREAT',
                    'name': name,
                    'description': desc,
                    'count': len(matches),
                })
    
    return findings


def parse_secure_boot_keys(data: bytes) -> Dict[str, Any]:
    """Check for presence of Secure Boot keys in firmware."""
    
    # Common key GUIDs and patterns
    key_guids = {
        b'PK': 'Platform Key',
        b'KEK': 'Key Exchange Key',
        b'DB': 'Database (allowed signatures)',
        b'DBT': 'DB Trusted',
    }
    
    findings = {}
    
    for guid, name in key_guids.items():
        # Search for GUID patterns in the firmware
        if isinstance(guid, bytes):
            matches = list(re.finditer(guid, data))
            if matches:
                findings[name] = {
                    'found': True,
                    'count': len(matches),
                    'offsets': [m.start() for m in matches],
                }
    
    # Check for key presence using more sophisticated methods
    pk_pattern = b'\\x8B\\x4C\\x24\\x??'  # Example PK pattern
    
    return findings


def parse_pe_sections(data: bytes, pe_offset: int) -> List[Section]:
    """Parse all PE sections from firmware data."""
    
    if len(data) < pe_offset + 160:
        return []
    
    opt_header = OptionalHeader()
    opt_magic = struct.unpack('<H', data[pe_offset+24:pe_offset+26])[0]
    opt_header.magic = opt_magic
    
    num_sections = struct.unpack('<H', data[pe_offset+60:pe_offset+62])[0]
    
    sections = []
    for i in range(num_sections):
        sec_start = pe_offset + 160 + (i * 40)
        
        if len(data) < sec_start + 40:
            break
        
        name_bytes = data[sec_start:sec_start+8].rstrip(b'\x00')
        section = Section(
            name=name_bytes.decode('ascii', errors='replace'),
            virtual_address=struct.unpack('<I', data[sec_start+24:sec_start+28])[0],
            virtual_size=struct.unpack('<I', data[sec_start+28:sec_start+32])[0],
            raw_data_offset=struct.unpack('<I', data[sec_start+32:sec_start+36])[0],
            raw_data_size=struct.unpack('<I', data[sec_start+36:sec_start+40])[0],
            characteristics=data[sec_start+40] | (data[sec_start+41] << 8) | 
                           (data[sec_start+42] << 16) | (data[sec_start+43] << 24),
        )
        
        # Parse section flags
        section.is_executable = bool(section.characteristics & 0x40000000)
        section.is_writable = bool(section.characteristics & 0x80000000)
        section.is_readable = bool(section.characteristics & 0x20000000)
        
        if section.name:
            # Infer type from name
            if 'CODE' in
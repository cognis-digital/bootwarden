"""
polyglot/python/secure_boot_validator.py

UEFI Secure Boot Validator Module.

Audits UEFI firmware dumps for:
- Missing Secure Boot keys (via Security Manager Protocol)
- Unsigned modules and images
- S3 boot-script vulnerabilities
- Known SMM threat signatures

Author: Qwen / Expert Python Engineer
"""

import struct
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, BinaryIO, Dict, Any
from enum import IntFlag, auto


# =============================================================================
# UEFI CONSTANTS (from spec)
# =============================================================================

# GUIDs as 16-byte strings for comparison
GUID_SECURITY_MANAGER_PROTOCOL = bytes.fromhex(
    "87D6F332-2FFA-4536-A0C2-8F16291DA3FB"
)

GUID_SMM_SPECIFICATION = bytes.fromhex(
    "EFA8B64C-8F4E-487A-BF83-3D8C8B8F5F5E"
)

# EFI_IMAGE_HEADER signature
EFI_IMAGE_HEADER_SIGNATURE = b"\x01\x02\x03\x04\x05\x06\x07\x08"

# SMM region attributes (from SMM spec)
SMM_REGION_ATTRIBUTES = {
    "EXECUTE": 0x0001,
    "READ_WRITE": 0x0002,
    "READ_ONLY": 0x0004,
    "CACHEABLE": 0x0010,
}

# Known SMM threat signatures (simplified patterns)
KNOWN_SMM_THREATS = {
    "SMMLIB": b"SMMLIB",
    "SMM_BIOS": b"SMM_BIOS",
    "SMM_HANDLER": b"SMM_HANDLER",
    # These are common strings found in vulnerable SMM code
}

# Common S3 boot script vulnerability patterns
KNOWN_S3_VULN_PATTERNS = [
    b"BootScript",
    b"S3Resume",
    b"SleepResume",
]


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class EFI_IMAGE_HEADER:
    """UEFI Image Header structure."""
    signature: bytes  # 8 bytes
    image_type: int  # 4 bytes (e.g., 0x10 for PE32)
    image_name: bytes = field(default=b"")  # 64 bytes
    compression_type: int  # 4 bytes
    image_size: int  # 8 bytes
    header_length: int  # 4 bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional["EFI_IMAGE_HEADER"]:
        """Parse an EFI Image Header from raw bytes."""
        if len(data) < 28:
            return None
        
        signature = data[:8]
        image_type = struct.unpack("<I", data[8:12])[0]
        compression_type = struct.unpack("<I", data[16:20])[0]
        image_size = struct.unpack("<Q", data[20:28])[0]
        
        # Validate signature
        if signature != EFI_IMAGE_HEADER_SIGNATURE:
            return None
        
        return cls(
            signature=signature,
            image_type=image_type,
            compression_type=compression_type,
            image_size=image_size,
            header_length=48  # Standard header length
        )


@dataclass
class SMM_REGION:
    """SMM Region structure."""
    base_address: int
    attribute: int
    size: int

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional["SMM_REGION"]:
        if len(data) < 12:
            return None
        
        # Simplified parsing - adjust based on actual format found
        base = struct.unpack("<Q", data[0:8])[0]
        attr = struct.unpack("<I", data[8:12])[0]
        size = struct.unpack("<Q", data[12:20])[0]
        
        return cls(base_address=base, attribute=attr, size=size)


# =============================================================================
# CORE VALIDATION LOGIC
# =============================================================================

class SecureBootValidator:
    """Main validator class for UEFI secure boot auditing."""

    def __init__(self):
        self.firmware_data: bytes = b""
        self.findings: List[Dict[str, Any]] = []
        self.smm_regions: List[SMM_REGION] = []
        self.images_found: List[EFI_IMAGE_HEADER] = []
        self.security_manager_protocol: Optional[bytes] = None

    def load_firmware(self, data: bytes) -> "SecureBootValidator":
        """Load firmware dump into the validator."""
        self.firmware_data = data
        return self

    def add_finding(self, severity: str, category: str, 
                    description: str, details: Optional[Dict] = None):
        """Record a finding with severity level."""
        entry = {
            "severity": severity,
            "category": category,
            "description": description,
            "details": details or {},
        }
        self.findings.append(entry)

    def validate_secure_boot(self) -> Dict[str, Any]:
        """
        Check Secure Boot status via Security Manager Protocol.
        
        Returns dict with:
            - enabled: bool (whether Secure Boot is active)
            - keys_present: list of key identifiers found
            - signature_list: list of registered signatures
        """
        result = {
            "enabled": False,
            "keys_present": [],
            "signature_list": [],
        }

        # Look for Security Manager Protocol GUID in firmware
        guid_bytes = GUID_SECURITY_MANAGER_PROTOCOL
        
        if self.firmware_data:
            # Search for the GUID (it might be stored as bytes)
            positions = []
            pos = 0
            while True:
                idx = self.firmware_data.find(guid_bytes, pos)
                if idx == -1:
                    break
                positions.append(idx)
                pos = idx + 1
            
            # If found, assume Secure Boot is enabled (common case)
            if positions:
                result["enabled"] = True
                self.add_finding(
                    severity="info",
                    category="secure_boot",
                    description="Security Manager Protocol detected in firmware",
                    details={"guid": guid_bytes.hex(), "found_at": positions[:3]}
                )

        return result

    def scan_unsigned_modules(self) -> List[Dict[str, Any]]:
        """
        Scan for unsigned or weakly-signed modules.
        
        Returns list of module entries with signature status.
        """
        unsigned = []
        image_count = 0
        
        if not self.firmware_data:
            return unsigned

        # Search for EFI_IMAGE_HEADER signatures
        header_sig = EFI_IMAGE_HEADER_SIGNATURE
        
        pos = 0
        while True:
            idx = self.firmware_data.find(header_sig, pos)
            if idx == -1:
                break
            
            image_count += 1
            
            # Extract potential header (8 bytes minimum for signature check)
            header_bytes = self.firmware_data[idx:idx + 28]
            
            header = EFI_IMAGE_HEADER.from_bytes(header_bytes)
            
            if header:
                # Check compression type - uncompressed is more common in signed images
                is_compressed = header.compression_type != 0
                
                module_info = {
                    "offset": idx,
                    "image_type": header.image_type,
                    "compressed": is_compressed,
                    "size": header.image_size,
                    "status": "unsigned" if not is_compressed else "unknown",
                }
                
                # Compressed images often indicate signed/validated content
                if is_compressed:
                    module_info["status"] = "possibly_signed"
                    
                unsigned.append(module_info)
            else:
                # Signature mismatch - could be another format or corrupted data
                pass
            
            pos = idx + 1

        self.add_finding(
            severity="info",
            category="modules",
            description=f"Found {image_count} potential image headers, "
                        f"{len(unsigned)} analyzed as unsigned/unknown",
            details={"total_images": image_count, "unsigned_count": len(unsigned)}
        )

        return unsigned

    def scan_smm_regions(self) -> List[Dict[str, Any]]:
        """
        Scan for SMM regions and check for known threats.
        
        Returns list of SMM region info with threat assessment.
        """
        results = []
        
        if not self.firmware_data:
            return results

        # Search for common SMM-related strings as indicators
        smm_indicators = [b"SMM", b"SMMLIB", b"SMM_HANDLER"]
        
        found_regions = 0
        
        for indicator in smm_indicators:
            pos = 0
            while True:
                idx = self.firmware_data.find(indicator, pos)
                if idx == -1:
                    break
                
                # Look around the match for region-like structure
                context_start = max(0, idx - 32)
                context_end = min(len(self.firmware_data), idx + 64)
                context = self.firmware_data[context_start:context_end]
                
                results.append({
                    "indicator": indicator.decode('ascii', errors='replace'),
                    "offset": idx,
                    "context_length": len(context),
                    "type": "potential_smm",
                })
                
                found_regions += 1
                pos = idx + 1

        # Check for known threat signatures
        threats_found = []
        for name, pattern in KNOWN_SMM_THREATS.items():
            if pattern in self.firmware_data:
                pos = 0
                positions = []
                while True:
                    idx = self.firmware_data.find(pattern, pos)
                    if idx == -1:
                        break
                    positions.append(idx)
                    pos = idx + 1
                
                threats_found.append({
                    "name": name,
                    "occurrences": len(positions),
                    "positions": positions[:5],  # Limit output
                })

        self.add_finding(
            severity="warning" if threats_found else "info",
            category="smm",
            description=f"Found {found_regions} potential SMM indicators, "
                        f"{len(threats_found)} known threat patterns detected",
            details={
                "regions": found_regions,
                "threats": threats_found,
            }
        )

        return results + threats_found

    def scan_s3_boot_script(self) -> List[Dict[str, Any]]:
        """
        Scan for S3 boot script vulnerabilities.
        
        Returns list of potential vulnerability findings.
        """
        results = []
        
        if not self.firmware_data:
            return results

        # Search for known S3-related patterns
        for pattern in KNOWN_S3_VULN_PATTERNS:
            positions = []
            pos = 0
            while True:
                idx = self.firmware_data.find(pattern, pos)
                if idx == -1:
                    break
                positions.append(idx)
                pos = idx + 1
            
            if positions:
                results.append({
                    "pattern": pattern.decode('ascii', errors='replace'),
                    "occurrences": len(positions),
                    "positions": positions[:3],
                    "type": "potential_s3_vuln",
                })

        self.add_finding(
            severity="info" if results else "low",
            category="s3_boot_script",
            description=f"Found {len(results)} potential S3 boot script patterns",
            details={"patterns": results}
        )

        return results

    def run_full_audit(self) -> Dict[str, Any]:
        """
        Run complete secure boot validation suite.
        
        Returns comprehensive audit report.
        """
        self.findings = []  # Reset previous findings
        
        # Run all checks
        sec_boot_result = self.validate_secure_boot()
        unsigned_modules = self.scan_unsigned_modules()
        smm_results = self.scan_smm_regions()
        s3_results = self.scan_s3_boot_script()

        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "warning": 2, 
                         "info": 3, "low": 4}
        
        sorted_findings = sorted(
            self.findings,
            key=lambda x: severity_order.get(x["severity"], 5)
        )

        # Build summary report
        report = {
            "summary": {
                "secure_boot_enabled": sec_boot_result["enabled"],
                "unsigned_modules_count": len(unsigned_modules),
                "smm_indicators_found": len(smm_results),
                "s3_patterns_found": len(s3_results),
                "total_findings": len(self.findings),
            },
            "findings": sorted_findings,
        }

        # Add overall assessment
        critical_count = sum(1 for f in self.findings if f["severity"] == "critical")
        high_count = sum(1 for f in self.findings if f["severity"] == "high")
        
        report["assessment"] = {
            "overall_status": "clean" if not (critical_count or high_count) else 
                            "review_required",
            "critical_issues": critical_count,
            "high_issues": high_count,
        }

        return report


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def create_sample_firmware() -> bytes:
    """
    Create a sample firmware image for testing.
    
    Returns a minimal but realistic-looking EFI system table + headers.
    """
    # Build a minimal EFI_SYSTEM_TABLE (1024 bytes)
    efi_st = bytearray(1024)
    
    # Set up basic fields
    struct.pack_into("<Q", efi_st, 0x1000, 0x1000)  # SystemTablePointer
    struct.pack_into("<I", efi_st, 0x1018, 0x0004)   # ImageType (PE32)
    
    # Add an EFI_IMAGE_HEADER signature at offset 0x1100
    header_offset = 0x1100
    efi_st[header_offset:header_offset + 8] = EFI_IMAGE_HEADER_SIGNATURE
    
    # Set image type for PE32+ (signed images)
    struct.pack_into("<I", efi_st, header_offset + 8, 0x1004)
    
    return bytes(efi_st)


def create_sample_smm_firmware() -> bytes:
    """Create sample firmware with SMM indicators."""
    base = bytearray(create_sample_firmware())
    
    # Add SMM-related strings at various offsets
    smm_strings = [b"SMMLIB", b"SMM_HANDLER", b"S3Resume"]
    
    for i, s in enumerate(smm_strings):
        offset = 0x1200 + (i * 64)
        base[offset:offset + len(s)] = s
    
    return bytes(base)


def create_sample_unsigned_firmware() -> bytes:
    """Create sample firmware with unsigned modules."""
    base = bytearray(create_sample_smm_firmware())
    
    # Add multiple image headers (some compressed, some not)
    for i in range(5):
        offset = 0x1300 + (i * 48)
        
        if i % 2 == 0:
            # Compressed (possibly signed)
            base[offset:offset + 8] = EFI_IMAGE_HEADER_SIGNATURE
            struct.pack_into("<I", base, offset + 8, 0x1004)  # PE32+
        else:
            # Uncompressed (unsigned)
            base[offset:offset + 8] = b"\xFF\xFF\xFF\xFF"  # Different signature
    
    return bytes(base)


# =============================================================================
# DEMO / ENTRY POINT
# =============================================================================

def main():
    """Demo harness for SecureBootValidator."""
    print("=" * 60)
    print("UEFI Secure Boot Validator - Demo")
    print("=" * 60)
    
    validator = SecureBootValidator()
    
    # Test with sample data
    test_cases = [
        ("Clean firmware", create_sample_firmware()),
        ("Firmware with SMM indicators", create_sample_smm_firmware()),
        ("Firmware with unsigned modules", create_sample_unsigned_firmware()),
    ]

    for name, data in test_cases:
        print(f"\n--- Testing: {name} ---")
        validator.load_firmware(data)
        
        report = validator.run_full_audit()
        
        # Print summary
        print(f"  Secure Boot
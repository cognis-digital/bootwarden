use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;

/// UEFI Firmware Parser for uefiscan security audit tool.
/// 
/// Parses PE/COFF headers, FV hierarchy, SMM modules, and Secure Boot keys.
pub mod firmware_parser {

    use crate::utils::{read_u32_le, read_u16_le, read_u8};

    // =====================================================================
    // CONSTANTS & MAGIC NUMBERS
    // =====================================================================

    const PE_SIGNATURE: u32 = 0x4550; // "PE\0\0" little-endian
    const IMAGE_NT_HEADERS_SIZE: usize = 64;
    
    // FV (Firmware Volume) Hierarchy
    const EFI_FV_HEADER_SIG: [u8; 16] = b"EFI_FV_00";
    const EFI_FV2_HEADER_SIG: [u8; 16] = b"EFI_FV2_00";
    
    // DXE Core Section (where main boot code lives)
    const IMAGE_SCN_CNT_CODE: u32 = 0x40000000;
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
    
    // SMM Module Section
    const IMAGE_SCN_MEM_2MB_PAGE: u32 = 0x10000000;
    
    // Secure Boot Key Types (FV2)
    const EFI_SECURITY_DATABASE_GUID: [u8; 16] = [0xb9, 0xe7, 0x95, 0xd9, 0xa3, 0x94, 0xc3, 0xf8, 0x1c, 0xf2, 0x6f, 0x4b, 0xfd, 0x4f, 0x75, 0x6d];
    const EFI_CERT_X509_GUID: [u8; 16] = [0xb9, 0xe7, 0x95, 0xd9, 0xa3, 0x94, 0xc3, 0xf8, 0x1c, 0xf2, 0x6f, 0x4b, 0xfd, 0x4f, 0x75, 0x6d];
    
    // Known vulnerable SMM module signatures (partial list)
    const KNOWN_SMM_SIGNATURES: &[&[u8]] = &[
        b"INTEL", b"AMD", b"MSFT", b"IBM ",
    ];

    // =====================================================================
    // DATA STRUCTURES
    // =====================================================================

    /// Represents a parsed PE/COFF header.
    #[derive(Debug, Clone)]
    pub struct PeHeader {
        pub signature: u32,
        pub machine: u16,
        pub num_sections: u16,
        pub timestamp: u32,
        pub optional_header_offset: u32,
        pub sections_start: usize,
    }

    /// Represents a Firmware Volume (FV) structure.
    #[derive(Debug, Clone)]
    pub struct FvHeader {
        pub signature: [u8; 16],
        pub version: u32,
        pub header_size: u32,
        pub crc32: u32,
        pub reserved: u32,
        pub start_offset: u32,
        pub size: u64,
    }

    /// Represents a DXE Core section with security metadata.
    #[derive(Debug, Clone)]
    pub struct DxeCoreSection {
        pub name: String,
        pub offset: u32,
        pub size: u32,
        pub attributes: u64,
        pub is_signed: bool,
        pub signature_offset: Option<u32>,
    }

    /// Represents an SMM module found in the firmware.
    #[derive(Debug, Clone)]
    pub struct SmmModule {
        pub name: String,
        pub offset: u64,
        pub size: u64,
        pub attributes: u64,
        pub vendor_signature: Option<String>,
        pub is_known_vulnerable: bool,
    }

    /// Represents a Secure Boot key found in the firmware.
    #[derive(Debug, Clone)]
    pub struct SecureBootKey {
        pub guid: [u8; 16],
        pub offset: u32,
        pub size: u32,
        pub version: u32,
        pub is_signed: bool,
        pub key_type: KeyType,
    }

    /// Type of Secure Boot key.
    #[derive(Debug, Clone, Copy)]
    pub enum KeyType {
        PK,           // Platform Key - root of trust
        KEK,          // Key Exchange Key - for updates
        AuthenticatedBoot,  // For authenticated boot policy
        Unknown,
    }

    /// Complete firmware analysis result.
    #[derive(Debug, Clone)]
    pub struct FirmwareAnalysis {
        pub pe_header: Option<PeHeader>,
        pub fv_headers: Vec<FvHeader>,
        pub dxe_core_sections: Vec<DxeCoreSection>,
        pub smm_modules: Vec<SmmModule>,
        pub secure_boot_keys: Vec<SecureBootKey>,
        pub issues: Vec<Issue>,
    }

    /// Security issue found during analysis.
    #[derive(Debug, Clone)]
    pub struct Issue {
        pub severity: Severity,
        pub category: Category,
        pub message: String,
        pub offset: Option<u64>,
        pub details: HashMap<String, String>,
    }

    /// Issue severity levels.
    #[derive(Debug, Clone, Copy)]
    pub enum Severity {
        Info,
        Low,
        Medium,
        High,
        Critical,
    }

    /// Issue categories for organization.
    #[derive(Debug, Clone, Copy)]
    pub enum Category {
        SecureBoot,
        Signing,
        SmmSecurity,
        FvStructure,
        General,
    }

    // =====================================================================
    // UTILITY FUNCTIONS
    // =====================================================================

    /// Read a u32 from little-endian bytes.
    fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
        if data.len() >= offset + 4 {
            Some(u32::from_le_bytes([data[offset], data[offset+1], 
                                      data[offset+2], data[offset+3]]))
        } else {
            None
        }
    }

    /// Read a u16 from little-endian bytes.
    fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
        if data.len() >= offset + 2 {
            Some(u16::from_le_bytes([data[offset], data[offset+1]]))
        } else {
            None
        }
    }

    /// Read a single byte.
    fn read_u8(data: &[u8], offset: usize) -> Option<u8> {
        if data.len() > offset {
            Some(data[offset])
        } else {
            None
        }
    }

    /// Convert bytes to ASCII string, trimming nulls.
    pub fn bytes_to_string(bytes: &[u8], max_len: usize) -> String {
        let end = std::cmp::min(max_len, bytes.len());
        unsafe { 
            std::str::from_utf8_unchecked(&bytes[..end])
                .trim_end_matches('\0')
                .to_owned()
        }
    }

    /// Convert GUID bytes to human-readable format.
    pub fn guid_to_string(guid: &[u8; 16]) -> String {
        format!("{:02x}{:02x}-{:02x}-{:02x}-{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            guid[0], guid[1], guid[2], guid[3],
            guid[4], guid[5], guid[6], guid[7],
            guid[8], guid[9], guid[10], guid[11],
            guid[12], guid[13], guid[14], guid[15]
        )
    }

    /// Check if bytes match a GUID (case-insensitive).
    pub fn guid_matches(guid: &[u8; 16], target: &[u8; 16]) -> bool {
        guid.iter().zip(target.iter()).all(|(a, b)| a == *b)
    }

    /// Determine key type from GUID.
    fn identify_key_type(guid: &[u8; 16]) -> KeyType {
        if guid_matches(guid, &EFI_SECURITY_DATABASE_GUID) ||
           guid_matches(guid, &EFI_CERT_X509_GUID) {
            // Check for PK/KEK by examining the first few bytes of data
            KeyType::PK
        } else {
            KeyType::Unknown
        }
    }

    /// Check if a section has execute permissions.
    fn has_execute_attr(attributes: u64) -> bool {
    attributes & IMAGE_SCN_MEM_EXECUTE != 0
}

    /// Check if a section is code (likely signed).
    fn is_code_section(attributes: u64) -> bool {
        attributes & IMAGE_SCN_CNT_CODE != 0 && has_execute_attr(attributes)
    }

    // =====================================================================
    // PE HEADER PARSING
    // =====================================================================

    /// Parse the PE/COFF header from firmware data.
    pub fn parse_pe_header(data: &[u8]) -> Option<PeHeader> {
        let signature = read_u32_le(data, 0)?;
        
        if signature != PE_SIGNATURE {
            return None;
        }

        Some(PeHeader {
            signature,
            machine: read_u16_le(data, 4)?,
            num_sections: read_u16_le(data, 6)?,
            timestamp: read_u32_le(data, 8)?,
            optional_header_offset: read_u32_le(data, 12)?,
            sections_start: IMAGE_NT_HEADERS_SIZE,
        })
    }

    /// Parse a DXE Core section from the PE header.
    pub fn parse_dxe_core_section(
        data: &[u8],
        offset: usize,
        num_sections: u16,
    ) -> Option<DxeCoreSection> {
        if num_sections == 0 || offset >= data.len() {
            return None;
        }

        let name_size = read_u16_le(data, offset)? as usize;
        let name_offset = offset + 2;
        
        // Read section name (max 8 chars)
        let name_bytes: [u8; 8] = data[name_offset..name_offset+std::cmp::min(8, name_size)].try_into().unwrap_or_default();
        let name = bytes_to_string(&name_bytes, 8);

        // Read attributes (at offset 2 within section header)
        let attrs_offset = name_offset + std::cmp::min(8, name_size);
        let attributes = read_u64_le(data, attrs_offset)?;

        Some(DxeCoreSection {
            name: name.clone(),
            offset: offset as u32,
            size: 0, // Will be calculated from next section or end of file
            attributes,
            is_signed: is_code_section(attributes),
            signature_offset: None,
        })
    }

    /// Parse all DXE Core sections.
    pub fn parse_all_dxe_sections(
        data: &[u8],
        pe_header: &PeHeader,
    ) -> Vec<DxeCoreSection> {
        let mut sections = Vec::new();
        
        for i in 0..pe_header.num_sections as usize {
            let section_offset = pe_header.sections_start + (i * 40); // 40 bytes per section header
            
            if section_offset >= data.len() {
                break;
            }

            let name_size = read_u16_le(data, section_offset)? as usize;
            
            // Check for DXE Core indicators
            let attrs_offset = section_offset + 2;
            let attributes = read_u64_le(data, attrs_offset)?;

            if is_code_section(attributes) {
                let name_bytes: [u8; 8] = data[section_offset+2..section_offset+10].try_into().unwrap_or_default();
                let name = bytes_to_string(&name_bytes, 8);

                // Calculate size from next section or EOF
                let next_section = if i + 1 < pe_header.num_sections as usize {
                    (i + 1) * 40
                } else {
                    data.len() - pe_header.sections_start
                };

                sections.push(DxeCoreSection {
                    name: name.clone(),
                    offset: section_offset as u32,
                    size: next_section as u32,
                    attributes,
                    is_signed: is_code_section(attributes),
                    signature_offset: None,
                });
            }
        }

        sections
    }

    // =====================================================================
    // FV (FIRMWARE VOLUME) PARSING
    // =====================================================================

    /// Parse a Firmware Volume header.
    pub fn parse_fv_header(data: &[u8], offset: usize, fv2: bool) -> Option<FvHeader> {
        let sig_offset = if fv2 { 0 } else { 4 };
        
        let signature = &data[offset + sig_offset..offset + sig_offset + 16];

        // Check for valid FV signatures
        let is_valid_sig = if fv2 {
            guid_matches(&signature.try_into().unwrap_or_default(), &EFI_FV2_HEADER_SIG)
        } else {
            guid_matches(&signature.try_into().unwrap_or_default(), &EFI_FV_HEADER_SIG)
        };

        if !is_valid_sig {
            return None;
        }

        let version = read_u32_le(data, offset + 16)?;
        let header_size = read_u32_le(data, offset + 20)?;
        let crc32 = read_u32_le(data, offset + 24)?;
        let reserved = read_u32_le(data, offset + 28)?;
        let start_offset = read_u32_le(data, offset + 32)?;
        let size = read_u64_le(data, offset + 36)?? as u64;

        Some(FvHeader {
            signature: signature.try_into().unwrap_or_default(),
            version,
            header_size,
            crc32,
            reserved,
            start_offset,
            size,
        })
    }

    /// Parse all FV headers from firmware data.
    pub fn parse_all_fv_headers(data: &[u8]) -> Vec<FvHeader> {
        let mut fv_headers = Vec::new();

        // Search for FV signatures throughout the file
        let search_size = std::cmp::min(16, data.len());
        
        for i in 0..=data.len() - 20 {
            if i + 4 <= data.len() && i + 36 <= data.len() {
                let sig_bytes: [u8; 16] = data[i..i+16].try_into().unwrap_or_default();

                if guid_matches(&sig_bytes, &EFI_FV_HEADER_SIG) ||
                   guid_matches(&sig_bytes, &EFI_FV2_HEADER_SIG) {
                    
                    let fv2 = guid_matches(&sig_bytes, &EFI_FV2_HEADER_SIG);
                    if let Some(fv) = parse_fv_header(data, i, fv2) {
                        // Avoid duplicates (same start_offset and size)
                        if !fv_headers.iter().any(|h| h.start_offset == fv.start_offset && 
                                                       h.size == fv.size) {
                            fv_headers.push(fv);
                        }
                    }
                }
            }
        }

        fv_headers
    }

    // =====================================================================
    // SMM MODULE PARSING
    // =====================================================================

    /// Check if a section might be an SMM module.
    fn is_smm_section(attributes: u64) -> bool {
        attributes & IMAGE_SCN_MEM_2MB_PAGE != 0 && has_execute_attr(attributes)
    }

    /// Parse potential SMM modules from firmware.
    pub fn parse_smm_modules(
        data: &[u8],
        pe_header: Option<&PeHeader>,
    ) -> Vec<SmmModule> {
        let mut smm_modules = Vec::new();

        if let Some(pe) = pe_header {
            for i in 0..pe.num_sections as usize {
                let section_offset = pe.sections_start + (i * 40);
                
                if section_offset >= data.len() {
                    break;
                }

                let attrs_offset = section_offset + 2
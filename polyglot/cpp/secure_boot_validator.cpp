#include <cstdint>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <memory>

namespace uefiscan {

// ============================================================================
// Constants and Types
// ============================================================================

constexpr uint32_t PE_SIGNATURE = 0x00004550; // "PE\0\0"
constexpr uint16_t IMAGE_NT_OPTIONAL_HDR_MAGIC_PE32 = 0x10b;
constexpr uint16_t IMAGE_NT_OPTIONAL_HDR_MAGIC_PE32PLUS = 0x20b;

// SMM regions are typically in the first 4MB of memory
constexpr size_t DEFAULT_SMM_SIZE = 4 * 1024 * 1024;

// Known dangerous SMM base addresses (Intel/AMD common)
struct SmmRegion {
    uint64_t base;
    uint32_t size;
    std::string vendor;
};

// ============================================================================
// Utility Functions
// ============================================================================

inline bool is_valid_pointer(uintptr_t ptr, size_t max_size) {
    return ptr > 0 && ptr < max_size;
}

inline void safe_copy(const char* src, size_t len, std::string& dest) {
    if (!src || !len) {
        dest.clear();
        return;
    }
    if (len > 256) len = 256; // Reasonable limit for strings
    dest.assign(src, len);
}

// ============================================================================
// PE/COFF Parsing
// ============================================================================

struct PeHeader {
    uint32_t signature;
    uint16_t machine;
    uint16_t num_sections;
    uint32_t timestamp;
    uint32_t optional_magic;
    uint32_t entry_point_rva;
    uint32_t image_base;
};

struct SectionHeader {
    char name[8];
    uint32_t virtual_size;
    uint32_t raw_size;
    uint32_t vaddr;
    uint32_t raddr;
    uint16_t characteristics;
};

bool parse_pe_header(const void* data, size_t size, PeHeader& header) {
    if (size < 0x40) return false; // Minimum PE header
    
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    
    header.signature = *(uint32_t*)ptr;
    header.machine = *(uint16_t*)(ptr + 4);
    header.num_sections = *(uint16_t*)(ptr + 6);
    header.timestamp = *(uint32_t*)(ptr + 8);
    header.optional_magic = *(uint32_t*)(ptr + 0x18);
    header.entry_point_rva = *(uint32_t*)(ptr + 0x24);
    header.image_base = *(uint32_t*)(ptr + 0x2C);
    
    return header.signature == PE_SIGNATURE;
}

bool parse_sections(const PeHeader& header, const void* data, 
                    size_t size, std::vector<SectionHeader>& sections) {
    if (header.num_sections == 0 || header.optional_magic != IMAGE_NT_OPTIONAL_HDR_MAGIC_PE32 &&
        header.optional_magic != IMAGE_NT_OPTIONAL_HDR_MAGIC_PE32PLUS) {
        return false;
    }
    
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    size_t offset = 0x40 + (header.optional_magic == IMAGE_NT_OPTIONAL_HDR_MAGIC_PE32PLUS ? 0x6C : 0x5C);
    
    sections.reserve(header.num_sections);
    
    for (uint16_t i = 0; i < header.num_sections && offset + sizeof(SectionHeader) <= size; ++i) {
        SectionHeader& sec = sections.emplace_back();
        
        memcpy(sec.name, ptr + offset, 8);
        sec.virtual_size = *(uint32_t*)(ptr + offset + 16);
        sec.raw_size = *(uint32_t*)(ptr + offset + 20);
        sec.vaddr = *(uint32_t*)(ptr + offset + 24);
        sec.raddr = *(uint32_t*)(ptr + offset + 28);
        sec.characteristics = *(uint16_t*)(ptr + offset + 32);
        
        // Check if section is executable (contains code)
        bool is_executable = (sec.characteristics & 0x40000000) || 
                            (sec.characteristics & 0x20000000);
        sec.name[7] = '\0'; // Null-terminate for printing
        
        offset += sizeof(SectionHeader);
    }
    
    return !sections.empty();
}

// ============================================================================
// X509 Certificate Chain Verification
// ============================================================================

struct CertChainResult {
    bool valid;
    std::string issuer;
    std::string subject;
    uint32_t cert_count;
    std::vector<uint8_t> raw_cert_chain;
};

bool find_x509_certificate(const void* data, size_t size, 
                           CertChainResult& result) {
    // Look for X.509 certificate signature (common in PE headers and sections)
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    
    // Search for RSA public key OID: 2A 86 48 86 F7 0D 01 01 01 05
    constexpr size_t RSA_OID_LEN = 11;
    constexpr uint8_t RSA_OID[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 
                                    0x01, 0x01, 0x01, 0x05};
    
    size_t cert_offset = 0;
    while (cert_offset + RSA_OID_LEN <= size) {
        if (memcmp(ptr + cert_offset, RSA_OID, RSA_OID_LEN) == 0) {
            // Found potential certificate - extract reasonable chunk
            result.raw_cert_chain.resize(std::min(size - cert_offset, 2048ULL));
            memcpy(result.raw_cert_chain.data(), ptr + cert_offset, 
                   std::min<size_t>(size - cert_offset, 2048U));
            
            // Try to parse as DER-encoded certificate (simplified)
            if (result.raw_cert_chain.size() >= 12 && 
                result.raw_cert_chain[0] == 0x30) { // SEQUENCE tag
                result.valid = true;
                result.cert_count = 1;
                
                // Extract subject and issuer from common positions
                // These are approximate - real parsing needs ASN.1 decoder
                if (result.raw_cert_chain.size() > 256) {
                    safe_copy(reinterpret_cast<const char*>(ptr + cert_offset + 48), 
                             std::min<size_t>(result.raw_cert_chain.size() - 48, 64U),
                             result.subject);
                    
                    safe_copy(reinterpret_cast<const char*>(ptr + cert_offset + 120), 
                             std::min<size_t>(result.raw_cert_chain.size() - 120, 64U),
                             result.issuer);
                }
                
                return true;
            }
        }
        
        // Skip past potential certificate (heuristic)
        cert_offset += 512;
    }
    
    result.valid = false;
    result.cert_count = 0;
    return false;
}

// ============================================================================
// RSA/ECDSA Signature Verification
// ============================================================================

struct SigVerifyResult {
    bool valid;
    std::string algorithm;
    uint32_t hash_algorithm;
};

bool verify_signature(const void* data, size_t size, 
                      const void* key_data, size_t key_size,
                      SigVerifyResult& result) {
    // Simplified RSA verification - real implementation needs proper crypto library
    
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    
    // Check for PKCS#1 v1.5 padding (common in PE signatures)
    if (size >= 64 && ptr[size - 1] == 0x00 && ptr[size - 2] == 0xFF) {
        // Likely RSA signature with PKCS#1 v1.5 padding
        
        // For demo, we'll use a simple hash-based check
        // In production: proper RSA private key verification needed
        
        result.valid = true; // Assume valid for demonstration
        result.algorithm = "RSA-PKCS1v15";
        result.hash_algorithm = 0x8004; // SHA-256 (common in UEFI)
        
        return true;
    }
    
    result.valid = false;
    result.algorithm = "Unknown/Invalid";
    result.hash_algorithm = 0;
    
    return false;
}

// ============================================================================
// SMM Region Analysis
// ============================================================================

struct SmmAnalysis {
    std::vector<SmmRegion> regions;
    bool has_dangerous_regions;
    std::string suspicious_vendors;
};

SmmAnalysis analyze_smm(const void* data, size_t size) {
    SmmAnalysis result;
    
    // Check for common SMM base addresses (Intel/AMD)
    constexpr uint64_t COMMON_SMM_BASES[] = {
        0x0009F000000ULL,   // Intel PCH
        0x000A0000000ULL,   // AMD SMM
        0x000B0000000ULL    // Legacy SMM
    };
    
    constexpr size_t COMMON_SIZES[] = {
        0x100000,           // 1MB
        0x200000,           // 2MB
        0x400000            // 4MB
    };
    
    for (size_t i = 0; i < sizeof(COMMON_SIZES) / sizeof(COMMON_SIZES[0]); ++i) {
        if (COMMON_SMM_BASES[i] <= size && 
            data && memcmp(data + COMMON_SMM_BASES[i], "SM", 2) == 0) {
            
            SmmRegion region;
            region.base = COMMON_SMM_BASES[i];
            region.size = COMMON_SIZES[i];
            region.vendor = "Common/" + std::to_string(i);
            
            result.regions.push_back(region);
        }
    }
    
    // Check for suspicious patterns in SMM regions
    if (!result.regions.empty()) {
        for (const auto& reg : result.regions) {
            const uint8_t* ptr = static_cast<const uint8_t*>(data + reg.base);
            
            // Look for known dangerous strings or signatures
            std::string vendor_str;
            safe_copy(reinterpret_cast<const char*>(ptr), 64, vendor_str);
            
            if (vendor_str.find("Microsoft") != std::string::npos ||
                vendor_str.find("Intel") != std::string::npos) {
                
                // Check for known vulnerable SMM handlers
                constexpr const char* DANGEROUS_PATTERNS[] = {
                    "SmmCall",           // Generic handler
                    "SmramAlloc",        // Memory allocation
                    "SmramFree"          // Memory free
                };
                
                for (const auto* pattern : DANGEROUS_PATTERNS) {
                    if (strstr(vendor_str.c_str(), pattern)) {
                        result.suspicious_vendors += vendor_str + "; ";
                        result.has_dangerous_regions = true;
                    }
                }
            }
        }
    }
    
    return result;
}

// ============================================================================
// S3 Boot Script Parsing
// ============================================================================

struct S3ScriptResult {
    bool found;
    std::string script_path;
    uint32_t script_size;
    std::vector<std::string> commands;
    bool has_vulnerabilities;
};

S3ScriptResult parse_s3_script(const void* data, size_t size) {
    S3ScriptResult result;
    
    // Look for S3 boot script signature in PE header or sections
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    
    // Common S3 script locations (heuristic search)
    constexpr std::string_view SCRIPT_SIGNATURES[] = {
        "BootScript",
        "S3Resume",
        "SmramInit"
    };
    
    for (const auto& sig : SCRIPT_SIGNATURES) {
        size_t pos = 0;
        while ((pos = ptrfind(ptr, size, sig.data(), sig.size())) != std::string::npos) {
            result.found = true;
            result.script_path = "Found at offset: " + 
                std::to_string(pos);
            
            // Extract script content (simplified - real parsing needs more context)
            result.script_size = 0x1000; // Assume reasonable size
            
            // Look for common vulnerability patterns
            constexpr const char* VULN_PATTERNS[] = {
                "S3Resume",           // S3 resume handler
                "SmramAlloc",         // Dynamic allocation in SMM
                "MmAllocate"          // Memory allocation
            };
            
            result.commands.clear();
            for (const auto* vuln : VULN_PATTERNS) {
                if (ptrfind(ptr, size, vuln, strlen(vuln)) != std::string::npos) {
                    result.has_vulnerabilities = true;
                    result.commands.push_back(std::string(vuln));
                }
            }
            
            break; // Found one instance - in real code would search all
        }
    }
    
    return result;
}

// ============================================================================
// Known Threat Signatures
// ============================================================================

struct ThreatResult {
    std::vector<std::string> threats_found;
    uint32_t threat_count;
};

ThreatResult scan_threats(const void* data, size_t size) {
    ThreatResult result;
    
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    
    // Known malicious SMM handlers and patterns
    constexpr std::string_view THREAT_PATTERNS[] = {
        "SmmCall",                    // Generic handler often abused
        "SmramAlloc",                 // Dynamic allocation vulnerability
        "MmAllocate",                 // Memory allocation in SMM
        "GopModeSet",                 // Graphics mode manipulation
        "ConInRead"                   // Console input hooking
    };
    
    for (const auto& pattern : THREAT_PATTERNS) {
        size_t pos = 0;
        while ((pos = ptrfind(ptr, size, pattern.data(), pattern.size())) != std::string::npos) {
            result.threats_found.push_back(std::string(pattern));
            result.threat_count++;
            
            // Extract context around the match (up to 128 bytes)
            size_t start = pos > 32 ? pos - 32 : 0;
            size_t end = pos + pattern.size() + 64;
            if (end > size) end = size;
            
            safe_copy(reinterpret_cast<const char*>(ptr + start), 
                     end - start, result.threats_found.back());
        }
    }
    
    // Check for known vulnerable firmware versions (heuristic)
    constexpr std::string_view VULN_VERSIONS[] = {
        "0x1.2.3",                    // Common vulnerable version pattern
        "0x1.2.4"                     // Another common pattern
    };
    
    for (const auto& ver : VULN_VERSIONS) {
        if (ptrfind(ptr, size, ver.data(), ver.size()) != std::string::npos) {
            result.threats_found.push_back("Potential vulnerable version: " + 
                                           std::string(ver));
            result.threat_count++;
        }
    }
    
    return result;
}

// ============================================================================
// Main Validation Logic
// ============================================================================

struct SecureBootResult {
    bool secure_boot_enabled;
    CertChainResult cert_chain;
    SigVerifyResult signature;
    SmmAnalysis smm_analysis;
    S3ScriptResult s3_script;
    ThreatResult threats;
    
    std::string summary;
};

SecureBootResult validate_secure_boot(const void* data, size_t size) {
    SecureBootResult result;
    
    // Parse PE header first
    PeHeader pe_header;
    if (!parse_pe_header(data, size, pe_header)) {
        result.summary = "Not a valid PE file";
        return result;
    }
    
    // Check for SMM regions
    result.smm_analysis = analyze_smm(data, size);
    
    // Parse sections and look for certificates
    std::vector<SectionHeader> sections;
    parse_sections(pe_header, data, size, sections);
    
    if (!sections.empty()) {
        // Search through sections for X509 certificates
        for (const auto& sec : sections) {
            if ((sec.characteristics & 0x40000000) || 
                (sec.characteristics & 0x20000000)) { // Executable section
                
                CertChainResult temp;
                if (find_x509_certificate(data, size, temp)) {
                    result.cert_chain = temp;
                    break;
                }
            }
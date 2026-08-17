#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <memory>

namespace uefiscan {

// ============================================================================
// Constants and GUIDs for UEFI sections
// ============================================================================

constexpr uint32_t PE_SIGNATURE = 0x00004550; // "PE\0\0"
constexpr uint16_t IMAGE_NT_OPTIONAL_HDR_MAGIC_PE32 = 0x10b;
constexpr uint16_t IMAGE_NT_OPTIONAL_HDR_MAGIC_PE32PLUS = 0x20b;

// Common UEFI section GUIDs (little-endian)
struct Guid {
    uint8_t Data1[4];
    uint16_t Data2[2];
    uint16_t Data3[2];
    uint8_t Data4[8];
    
    bool operator==(const Guid& other) const {
        return memcmp(this, &other, sizeof(Guid)) == 0;
    }
};

constexpr Guid GUID_TEXT = {{0x5c, 0xe6, 0x91, 0x24, 
                              0x83, 0x7d, 0x1f, 0x47,
                              0x9b, 0x3e, 0x5a, 0xc1,
                              0x6f, 0x2c, 0x8d, 0x9e}}; // .text

constexpr Guid GUID_DATA = {{0x5c, 0xe6, 0x91, 0x24, 
                               0x83, 0x7d, 0x1f, 0x47,
                               0x9b, 0x3e, 0x5a, 0xc1,
                               0x6f, 0x2c, 0x8d, 0x9f}}; // .data

constexpr Guid GUID_RELOC = {{0x5c, 0xe6, 0x91, 0x24, 
                                0x83, 0x7d, 0x1f, 0x47,
                                0x9b, 0x3e, 0x5a, 0xc2,
                                0x6f, 0x2c, 0x8d, 0xa0}}; // .reloc

constexpr Guid GUID_SMM = {{0x5c, 0xe6, 0x91, 0x24, 
                               0x83, 0x7d, 0x1f, 0x47,
                               0x9b, 0x3e, 0x5a, 0xc3,
                               0x6f, 0x2c, 0x8d, 0xa1}}; // .smm

// ============================================================================
// Data structures for parsed sections
// ============================================================================

struct SectionInfo {
    Guid guid;
    uint32_t virtualAddress;
    uint32_t sizeOfRawData;
    uint32_t characteristics;
    std::string name;
    bool isSigned;
    
    bool operator==(const SectionInfo& other) const {
        return guid == other.guid && 
               virtualAddress == other.virtualAddress &&
               sizeOfRawData == other.sizeOfRawData;
    }
};

struct SmmModule {
    Guid guid;
    uint32_t entryPoint;
    uint32_t baseAddress;
    uint32_t imageSize;
    std::string name;
    bool isSigned;
    
    bool operator==(const SmmModule& other) const {
        return guid == other.guid && 
               entryPoint == other.entryPoint &&
               baseAddress == other.baseAddress;
    }
};

struct SecureBootKey {
    uint32_t keyId;
    uint8_t type; // 0=PK, 1=TK, 2=EK, 3=EK-Platform
    std::string name;
    bool present;
    
    bool operator==(const SecureBootKey& other) const {
        return keyId == other.keyId && 
               type == other.type &&
               name == other.name;
    }
};

struct S3BootScript {
    uint32_t entryPoint;
    uint32_t sizeOfCode;
    std::string name;
    
    bool operator==(const S3BootScript& other) const {
        return entryPoint == other.entryPoint && 
               sizeOfCode == other.sizeOfCode;
    }
};

struct FirmwareAuditResult {
    std::vector<SectionInfo> sections;
    std::vector<SmmModule> smmModules;
    std::vector<SecureBootKey> secureBootKeys;
    std::vector<S3BootScript> s3Scripts;
    
    bool hasUnsignedSections;
    bool hasUnsignedSmmModules;
    uint32_t unsignedSectionCount;
    uint32_t unsignedSmmModuleCount;
    uint32_t totalSectionCount;
    uint32_t totalSmmModuleCount;
};

// ============================================================================
// Helper functions for PE/COFF parsing
// ============================================================================

inline bool isPeHeader(const void* data, size_t size) {
    return size >= sizeof(uint32_t) && 
           *(const uint16_t*)data == IMAGE_NT_HEADERS::Signature;
}

struct ImageNtHeaders {
    uint32_t Signature;
    // ... more fields
};

inline bool isPe32Plus(const void* data, size_t size) {
    return size >= sizeof(uint32_t) && 
           *(const uint16_t*)data == IMAGE_NT_OPTIONAL_HDR_MAGIC_PE32PLUS;
}

// ============================================================================
// Section GUID matching (with tolerance for common variations)
// ============================================================================

inline bool matchGuid(const Guid& sectionGuid, const Guid& targetGuid) {
    // Exact match first
    if (sectionGuid == targetGuid) return true;
    
    // Check for common .text/.data variants
    uint8_t diff = 0;
    for (int i = 0; i < sizeof(Guid); ++i) {
        diff += std::abs(sectionGuid.Data1[i] - targetGuid.Data1[i]);
    }
    return diff <= 2; // Allow small variations in GUIDs
}

// ============================================================================
// SMM Module Detection and Analysis
// ============================================================================

struct SmmScanner {
    static bool detectSmmModules(const void* imageBase, size_t imageSize) {
        const uint8_t* ptr = (const uint8_t*)imageBase;
        
        // Look for common SMM entry point signatures
        // These are typically in .smm or similar sections
        
        // Check for SMM entry point patterns
        if (ptr + 0x100 < imageBase + imageSize) {
            // Check for "Smm" string signature
            uint8_t* p = (uint8_t*)ptr;
            while (p + 4 <= imageBase + imageSize - ptr && 
                   *(uint32_t*)p == 0x6D6D6D53) { // "Smm" little-endian
                if (matchGuid(*(const Guid*)(p - sizeof(Guid)), GUID_SMM)) {
                    return true;
                }
                p += 4;
            }
        }
        
        return false;
    }
    
    static std::vector<SmmModule> scanForSmmModules(
            const void* imageBase, size_t imageSize) {
        std::vector<SmmModule> modules;
        const uint8_t* ptr = (const uint8_t*)imageBase;
        
        // Scan for SMM section headers
        while (ptr + sizeof(Guid) <= imageBase + imageSize - ptr) {
            Guid guid;
            memcpy(&guid, ptr, sizeof(Guid));
            
            if (matchGuid(guid, GUID_SMM)) {
                uint32_t entryPoint = *(uint32_t*)(ptr + 4);
                modules.push_back({guid, entryPoint, 
                                   0, 0, ".smm", true});
            }
            
            ptr += sizeof(Guid) * 2; // Skip current and next GUID
        }
        
        return modules;
    }
};

// ============================================================================
// Secure Boot Key Detection
// ============================================================================

struct SecureBootScanner {
    static bool hasSecureBootKeys(const void* imageBase, size_t imageSize) {
        const uint8_t* ptr = (const uint8_t*)imageBase;
        
        // Look for PK/TK/EK certificate storage areas
        // These are typically in .data or dedicated sections
        
        if (ptr + 0x200 < imageBase + imageSize - ptr) {
            // Check for common key storage signatures
            uint8_t* p = (uint8_t*)ptr;
            while (p + 0x100 <= imageBase + imageSize - ptr) {
                if (*(uint32_t*)p == 0x4B595043) { // "PK" little-endian
                    return true;
                }
                p += 0x100;
            }
        }
        
        return false;
    }
    
    static std::vector<SecureBootKey> scanForKeys(
            const void* imageBase, size_t imageSize) {
        std::vector<SecureBootKey> keys;
        const uint8_t* ptr = (const uint8_t*)imageBase;
        
        // Look for PK/TK/EK certificate headers
        while (ptr + sizeof(uint32_t) <= imageBase + imageSize - ptr) {
            if (*(uint32_t*)ptr == 0x4B595043) { // "PK" signature
                SecureBootKey key;
                key.keyId = *(uint16_t*)(ptr + 4);
                key.type = 0; // PK
                
                keys.push_back(key);
            } else if (*(uint32_t*)ptr == 0x4B59544B) { // "TK" signature
                SecureBootKey key;
                key.keyId = *(uint16_t*)(ptr + 4);
                key.type = 1; // TK
                
                keys.push_back(key);
            } else if (*(uint32_t*)ptr == 0x4B59454B) { // "EK" signature
                SecureBootKey key;
                key.keyId = *(uint16_t*)(ptr + 4);
                key.type = 2; // EK
                
                keys.push_back(key);
            }
            
            ptr += sizeof(uint32_t) * 2;
        }
        
        return keys;
    }
};

// ============================================================================
// S3 Boot Script Parser
// ============================================================================

struct S3BootScriptParser {
    static bool hasS3BootScript(const void* imageBase, size_t imageSize) {
        const uint8_t* ptr = (const uint8_t*)imageBase;
        
        // Look for S3 boot script entry points
        if (ptr + 0x100 < imageBase + imageSize - ptr) {
            uint8_t* p = (uint8_t*)ptr;
            while (p + 4 <= imageBase + imageSize - ptr && 
                   *(uint32_t*)p == 0x53335342) { // "S3SB" little-endian
                if (*(uint16_t*)(p + 4) == IMAGE_NT_OPTIONAL_HDR_MAGIC_PE32) {
                    return true;
                }
                p += 4;
            }
        }
        
        return false;
    }
    
    static std::vector<S3BootScript> parseS3Scripts(
            const void* imageBase, size_t imageSize) {
        std::vector<S3BootScript> scripts;
        const uint8_t* ptr = (const uint8_t*)imageBase;
        
        // Look for S3-specific boot script sections
        while (ptr + sizeof(uint32_t) <= imageBase + imageSize - ptr) {
            if (*(uint32_t*)ptr == 0x53335342) { // "S3SB" signature
                S3BootScript script;
                script.entryPoint = *(uint32_t*)(ptr + 4);
                script.sizeOfCode = *(uint32_t*)(ptr + 8);
                
                scripts.push_back(script);
            }
            
            ptr += sizeof(uint32_t) * 2;
        }
        
        return scripts;
    }
};

// ============================================================================
// Main Firmware Parser Class
// ============================================================================

class UefiFirmwareParser {
public:
    static FirmwareAuditResult parse(const std::string& filepath) {
        FirmwareAuditResult result;
        result.totalSectionCount = 0;
        result.totalSmmModuleCount = 0;
        
        // Read file into memory
        std::ifstream file(filepath, std::ios::binary);
        if (!file.is_open()) {
            return result;
        }
        
        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        
        std::vector<uint8_t> buffer(fileSize);
        if (fileSize > 0) {
            file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
        }
        file.close();
        
        // Check for PE header
        if (fileSize < sizeof(uint32_t)) {
            return result;
        }
        
        const uint8_t* imageBase = buffer.data();
        size_t imageSize = fileSize;
        
        // Parse PE headers
        if (*(uint16_t*)imageBase == IMAGE_NT_HEADERS::Signature) {
            // Extract section headers
            ImageNtHeaders ntHeader;
            memcpy(&ntHeader, imageBase, sizeof(ImageNtHeaders));
            
            // Scan for sections
            result.sections = scanSections(imageBase, imageSize);
            result.totalSectionCount = result.sections.size();
        }
        
        // Detect SMM modules
        result.smmModules = SmmScanner::scanForSmmModules(
                imageBase, imageSize);
        result.totalSmmModuleCount = result.smmModules.size();
        
        // Check for Secure Boot keys
        result.secureBootKeys = SecureBootScanner::scanForKeys(
                imageBase, imageSize);
        
        // Parse S3 boot scripts
        result.s3Scripts = S3BootScriptParser::parseS3Scripts(
                imageBase, imageSize);
        
        // Count unsigned sections and modules
        for (const auto& section : result.sections) {
            if (!section.isSigned) {
                result.hasUnsignedSections = true;
                result.unsignedSectionCount++;
            }
        }
        
        for (const auto& smm : result.smmModules) {
            if (!smm.isSigned) {
                result.hasUnsignedSmmModules = true;
                result.unsignedSmmModuleCount++;
            }
        }
        
        return result;
    }
    
private:
    static std::vector<SectionInfo> scanSections(
            const void* imageBase, size_t imageSize) {
        std::vector<SectionInfo> sections;
        const uint8_t* ptr = (const uint8_t*)imageBase;
        
        // Scan for section headers by looking for GUID patterns
        while (ptr + sizeof(Guid) <= imageBase + imageSize - ptr) {
            Guid guid;
            memcpy(&guid, ptr, sizeof(Guid));
            
            SectionInfo info;
            info.guid = guid;
            
            // Check against known UEFI sections
            if (matchGuid(guid, GUID_TEXT)) {
                info.name = ".text";
                info.virtualAddress = *(uint32_t*)(ptr + 4);
                info.sizeOfRawData = *(uint32_t*)(ptr + 8);
                info.characteristics = *(uint32_t*)(ptr + 12);
                info.isSigned = true; // .text is typically signed
            } else if (matchGuid(guid, GUID_DATA)) {
                info.name = ".data";
                info.virtualAddress = *(uint32_t*)(ptr + 4);
                info.sizeOfRawData = *(uint32_t*)(ptr + 8);
                info.characteristics = *(uint32_t*)(ptr + 12);
                info.isSigned = true;
            } else if (matchGuid(guid, GUID_RELOC)) {
                info.name = ".reloc";
                info.virtualAddress = *(uint32_t*)(ptr + 4);
                info.sizeOfRawData = *(uint32_t*)(ptr + 8);
                info.characteristics = *(uint32_t*)(ptr + 12);
                info.isSigned = true;
            } else if (matchGuid(guid, GUID_SMM)) {
                info.name = ".smm";
                info.virtualAddress = *(uint32_t*)(ptr + 4);
                info.sizeOfRawData = *(uint32_t*)(ptr + 8);
                info.characteristics = *(uint32_t*)(ptr + 12);
                info.isSigned = true;
            } else {
                // Unknown section - mark as potentially unsigned
                info.name = ".unknown";
                info.virtual
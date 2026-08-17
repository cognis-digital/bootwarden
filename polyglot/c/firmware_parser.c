/*
 * uefiscan - UEFI Firmware Parser and Security Auditor
 * File: polyglot/c/firmware_parser.c
 * 
 * Parses UEFI firmware dumps for Secure Boot keys, unsigned modules,
 * S3 boot-script vulnerabilities, and known SMM threats.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* ============================================================================
 * CONSTANTS AND GUIDS
 * ============================================================================ */

#define EFI_SIGNATURE_32 0x0A7B5B89
#define EFI_SIGNATURE_64 0x0A7B5B89

#define MAX_FV_SIZE      (1024 * 1024)   /* 1MB max for demo */
#define MAX_MODULE_NAME  64
#define MAX_GUID_STR     38               /* "xxxxxxxx-xxxx-..." */

/* Common GUIDs for Secure Boot keys */
static const uint8_t PK_GUID[16] = { 0x9D, 0x2E, 0x5B, 0x7A, 0x4C, 0x3F, 
                                       0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6,
                                       0x07, 0x18, 0x29, 0x3A };

static const uint8_t KEK_GUID[16] = { 0x0B, 0x1C, 0x2D, 0x3E, 0x4F, 0x50,
                                        0x61, 0x72, 0x83, 0x94, 0xA5, 0xB6,
                                        0xC7, 0xD8, 0xE9, 0xFA };

static const uint8_t RO_GUID[16]   = { 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F,
                                        0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5,
                                        0xD6, 0xE7, 0xF8, 0x09 };

static const uint8_t TB_GUID[16]   = { 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70,
                                        0x81, 0x92, 0xA3, 0xB4, 0xC5, 0xD6,
                                        0xE7, 0xF8, 0x09, 0x1A };

/* SMM GUIDs */
static const uint8_t SMM_MODULE_GUID[16] = { 0x3C, 0x4D, 0x5E, 0x6F, 
                                              0x70, 0x81, 0x92, 0xA3,
                                              0xB4, 0xC5, 0xD6, 0xE7,
                                              0xF8, 0x09, 0x1A, 0x2B };

/* Known malicious SMM GUIDs (examples) */
static const uint8_t MALICIOUS_SMM_1[16] = { 0xDE, 0xAD, 0xBE, 0xEF, 
                                              0xCA, 0xFE, 0xBA, 0xBE,
                                              0x12, 0x34, 0x56, 0x78,
                                              0x9A, 0xBC, 0xDE, 0xF0 };

static const uint8_t MALICIOUS_SMM_2[16] = { 0xFF, 0xEE, 0xDD, 0xCC, 
                                              0xBB, 0xAA, 0x99, 0x88,
                                              0x77, 0x66, 0x55, 0x44,
                                              0x33, 0x22, 0x11, 0x00 };

/* ============================================================================
 * DATA STRUCTURES
 * ============================================================================ */

typedef struct {
    uint8_t  guid[16];
    uint32_t size;
    uint32_t revision;
    uint32_t attributes;
    uint32_t reserved;
} __attribute__((packed)) FV_HEADER;

typedef struct {
    uint32_t signature;
    uint8_t  guid[16];
    uint32_t size;
    uint32_t revision;
    uint32_t attributes;
    uint32_t reserved;
} __attribute__((packed)) PEI_CORE_HEADER;

typedef struct {
    uint32_t signature;
    uint8_t  guid[16];
    uint32_t size;
    uint32_t revision;
    uint32_t attributes;
    uint32_t reserved;
} __attribute__((packed)) DXE_CORE_HEADER;

typedef struct {
    uint32_t signature;
    uint8_t  guid[16];
    uint32_t size;
    uint32_t revision;
    uint32_t attributes;
    uint32_t reserved;
} __attribute__((packed)) SMM_HEADER;

typedef struct {
    char name[MAX_MODULE_NAME];
    uint8_t  guid[16];
    uint32_t size;
    bool signed;
    uint32_t signature_offset;
} ModuleInfo;

typedef struct {
    uint8_t  guid[16];
    uint32_t offset;
    uint32_t length;
    char name[MAX_MODULE_NAME];
} SecureBootKey;

typedef struct {
    uint8_t  guid[16];
    uint32_t offset;
    uint32_t length;
    char name[MAX_MODULE_NAME];
} SMMModule;

/* ============================================================================
 * GLOBAL STATE
 * ============================================================================ */

static const FV_HEADER *g_fv_header = NULL;
static const PEI_CORE_HEADER *g_pei_core = NULL;
static const DXE_CORE_HEADER *g_dxe_core = NULL;
static const SMM_HEADER *g_smm_headers[16] = {0};
static int g_smm_count = 0;

typedef struct {
    SecureBootKey keys[8];
    uint32_t key_count;
} SecureBootState;

static SecureBootState g_secure_boot = {0};

typedef struct {
    ModuleInfo modules[64];
    uint32_t module_count;
} ModuleState;

static ModuleState g_modules = {0};

typedef struct {
    SMMModule smm[16];
    uint32_t smm_count;
} SMMState;

static SMMState g_smm = {0};

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

static inline bool guid_equal(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 16) == 0;
}

static inline void guid_copy(uint8_t *dst, const uint8_t *src)
{
    memcpy(dst, src, 16);
}

static inline bool is_guid_zero(const uint8_t *guid)
{
    return !memcmp(guid, "\x00\x00\x00\x00\x00\x00\x00\x00"
                        "\x00\x00\x00\x00\x00\x00\x00\x00", 16);
}

static inline bool is_guid_all_ff(const uint8_t *guid)
{
    return !memcmp(guid, "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                            "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 16);
}

static inline bool is_valid_fv_header(const FV_HEADER *fv)
{
    if (!fv || !fv->signature) {
        return false;
    }
    
    /* Check for valid signature */
    if (fv->signature != EFI_SIGNATURE_32 && 
        fv->signature != EFI_SIGNATURE_64) {
        return false;
    }
    
    /* Size must be reasonable */
    if (fv->size < sizeof(FV_HEADER)) {
        return false;
    }
    
    return true;
}

static inline bool is_valid_pei_core(const PEI_CORE_HEADER *pe)
{
    if (!pe || !pe->signature) {
        return false;
    }
    
    /* Valid PEI core signature */
    if (pe->signature != 0x0A7B5B89) {
        return false;
    }
    
    return true;
}

static inline bool is_valid_dxe_core(const DXE_CORE_HEADER *dx)
{
    if (!dx || !dx->signature) {
        return false;
    }
    
    /* Valid DXE core signature */
    if (dx->signature != 0x0A7B5B89) {
        return false;
    }
    
    return true;
}

static inline bool is_valid_smm_header(const SMM_HEADER *smm, 
                                        const uint8_t *expected_guid)
{
    if (!smm || !smm->signature) {
        return false;
    }
    
    /* Check expected GUID */
    if (expected_guid && !guid_equal(smm->guid, expected_guid)) {
        return false;
    }
    
    return true;
}

/* ============================================================================
 * FIRMWARE PARSING - HEADER EXTRACTION
 * ============================================================================ */

static bool parse_fv_header(const uint8_t *data, size_t len)
{
    if (!data || len < sizeof(FV_HEADER)) {
        fprintf(stderr, "Error: Invalid data buffer for FV header\n");
        return false;
    }
    
    g_fv_header = (const FV_HEADER *)data;
    
    /* Validate header */
    if (!is_valid_fv_header(g_fv_header)) {
        fprintf(stderr, "Warning: Invalid or corrupted FV header\n");
        g_fv_header = NULL;
        return false;
    }
    
    printf("FV Header Parsed:\n");
    printf("  Signature: 0x%08X\n", g_fv_header->signature);
    printf("  Size: %u bytes\n", g_fv_header->size);
    printf("  Revision: 0x%X\n", g_fv_header->revision);
    printf("  Attributes: 0x%X\n", g_fv_header->attributes);
    
    /* Print GUID if not zero */
    if (!is_guid_zero(g_fv_header->guid)) {
        printf("  GUID: ");
        for (int i = 0; i < 16; i++) {
            printf("%02X", g_fv_header->guid[i]);
            if ((i + 1) % 4 == 0 && i < 15) {
                printf("-");
            }
        }
        printf("\n");
    }
    
    return true;
}

static bool parse_pei_core(const uint8_t *data, size_t len)
{
    if (!g_fv_header || !is_valid_fv_header(g_fv_header)) {
        fprintf(stderr, "Error: FV header not found\n");
        return false;
    }
    
    /* PEI core typically follows FV header */
    const uint8_t *pe_start = (const uint8_t *)g_fv_header + 
                              sizeof(FV_HEADER);
    
    if (len - pe_start < sizeof(PEI_CORE_HEADER)) {
        fprintf(stderr, "Error: Not enough data for PEI core\n");
        return false;
    }
    
    g_pei_core = (const PEI_CORE_HEADER *)pe_start;
    
    /* Validate header */
    if (!is_valid_pei_core(g_pei_core)) {
        fprintf(stderr, "Warning: Invalid or corrupted PEI core header\n");
        g_pei_core = NULL;
        return false;
    }
    
    printf("\nPEI Core Header Parsed:\n");
    printf("  Signature: 0x%08X\n", g_pei_core->signature);
    printf("  Size: %u bytes\n", g_pei_core->size);
    printf("  Revision: 0x%X\n", g_pei_core->revision);
    
    /* Print GUID if not zero */
    if (!is_guid_zero(g_pei_core->guid)) {
        printf("  GUID: ");
        for (int i = 0; i < 16; i++) {
            printf("%02X", g_pei_core->guid[i]);
            if ((i + 1) % 4 == 0 && i < 15) {
                printf("-");
            }
        }
        printf("\n");
    }
    
    return true;
}

static bool parse_dxe_core(const uint8_t *data, size_t len)
{
    if (!g_fv_header || !is_valid_fv_header(g_fv_header)) {
        fprintf(stderr, "Error: FV header not found\n");
        return false;
    }
    
    /* DXE core typically follows PEI core */
    const uint8_t *dx_start = (const uint8_t *)g_pei_core + 
                             sizeof(PEI_CORE_HEADER);
    
    if (len - dx_start < sizeof(DXE_CORE_HEADER)) {
        fprintf(stderr, "Error: Not enough data for DXE core\n");
        return false;
    }
    
    g_dxe_core = (const DXE_CORE_HEADER *)dx_start;
    
    /* Validate header */
    if (!is_valid_dxe_core(g_dxe_core)) {
        fprintf(stderr, "Warning: Invalid or corrupted DXE core header\n");
        g_dxe_core = NULL;
        return false;
    }
    
    printf("\nDXE Core Header Parsed:\n");
    printf("  Signature: 0x%08X\n", g_dxe_core->signature);
    printf("  Size: %u bytes\n", g_dxe_core->size);
    printf("  Revision: 0x%X\n", g_dxe_core->revision);
    
    /* Print GUID if not zero */
    if (!is_guid_zero(g_dxe_core->guid)) {
        printf("  GUID: ");
        for (int i = 0; i < 16; i++) {
            printf("%02X", g_dxe_core->guid[i]);
            if ((i + 1) % 4 == 0 && i < 15) {
                printf("-");
            }
        }
        printf("\n");
    }
    
    return true;
}

/* ============================================================================
 * SECURE BOOT KEY EXTRACTION
 * ============================================================================ */

static bool extract_secure_boot_keys(const uint8_t *data, size_t len)
{
    SecureBootState *sb = &g_secure_boot;
    sb->key_count = 0;
    
    /* Search for known key GUIDs in the firmware dump */
    printf("\n--- Secure Boot Key Analysis ---\n");
    
    const uint8_t *search_guids[] = {PK_GUID, KEK_GUID, RO_GUID, TB_GUID};
    const char *guid_names[] = {"PK", "KEK", "RO", "TB"};
    
    for (int i = 0; i < 4 && sb->key_count < 8; i++) {
        uint32_t found = 0;
        
        /* Linear search through data */
        const uint8_t *ptr = data;
        while ((uint32_t)(ptr - data) + 16 <= len) {
            if (guid_equal(ptr, search_guids[i])) {
                sb->keys[sb->key_count].offset = ptr - data;
                guid_copy(sb->keys[sb->key_count].guid, ptr);
                strncpy(sb->keys[sb->key_count].name, 
                        guid_names[i], MAX_MODULE_NAME - 1);
                
                /* Estimate key size (typically 256-512 bytes) */
                sb->keys[sb->key_count].length = 256;
                
                found++;
                printf("  Found %s at offset 0x%08X\n", 
                       guid_names[i], ptr - data);
            }
            ptr++;
        }
        
        if (found > 0) {
            sb->key_count++;
            printf("    Count: %u occurrences\n", found);
        } else {
            printf("  %s: Not found\n", guid
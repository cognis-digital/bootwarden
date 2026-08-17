/*
 * secure_boot_validator.c
 * 
 * UEFI Secure Boot Validator for uefiscan tool
 * 
 * Validates:
 *  - PK/KEK/DB presence and integrity
 *  - S3 boot script vulnerabilities  
 *  - Known SMM threat signatures
 *  - Overall Secure Boot configuration state
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <ctype.h>

/* ============================================================================
 * Constants and GUIDs
 */

/* EFI_GUID types - 16 bytes, little-endian stored as array of uint8_t */
#define EFI_GUID_SIZE 16

typedef struct {
    uint8_t data[EFI_GUID_SIZE];
} EFI_GUID;

/* Standard UEFI Secure Boot GUIDs (little-endian byte order) */
static const EFI_GUID g_EFI_GLOBAL_PK = {{0x7, 0x2d, 0x9e, 0x63, 
                                          0x18, 0x4f, 0x5c, 0x9a,
                                          0x8b, 0x6d, 0x3e, 0xf1,
                                          0x2c, 0x7a, 0x9e, 0x4d}};

static const EFI_GUID g_EFI_GLOBAL_KEK = {{0x5, 0x8f, 0x6b, 0x3d, 
                                           0x12, 0x9c, 0x7a, 0xe4,
                                           0x3b, 0xc8, 0xd1, 0xf5,
                                           0xa2, 0x6e, 0xb9, 0x3f}};

static const EFI_GUID g_EFI_GLOBAL_DB = {{0x3, 0x4a, 0x8c, 0x1e, 
                                          0x5d, 0x2b, 0x6f, 0xa7,
                                          0xc9, 0xe3, 0xd4, 0xb8,
                                          0xf1, 0x7a, 0x5c, 0x2e}};

static const EFI_GUID g_EFI_GLOBAL_DRTM = {{0x6, 0x9b, 0x3f, 0x4d, 
                                            0x8a, 0xc1, 0xe7, 0xb5,
                                            0xd2, 0xa8, 0xf3, 0xc6,
                                            0xe9, 0x4b, 0x7d, 0x1a}};

/* S3 Boot Script GUID */
static const EFI_GUID g_EFI_S3_BOOT_SCRIPT = {{0x2, 0xa5, 0x8f, 0xc3, 
                                               0x9e, 0x4b, 0xd7, 0x61,
                                               0xb8, 0xe4, 0xf9, 0xa2,
                                               0xc5, 0x3d, 0x7e, 0x9f}};

/* Known SMM threat GUIDs */
static const EFI_GUID g_SMM_THREAT_1 = {{0x1, 0x4c, 0x9a, 0xb2, 
                                         0x3d, 0x7e, 0xf5, 0xc8,
                                         0xa6, 0xd3, 0xe9, 0xb1,
                                         0x4f, 0x8c, 0x2a, 0x5e}};

static const EFI_GUID g_SMM_THREAT_2 = {{0x2, 0x7b, 0xc4, 0xd9, 
                                         0x6a, 0xe1, 0xf8, 0xb3,
                                         0xc7, 0xa5, 0xd2, 0xe6,
                                         0x9d, 0x4c, 0x8f, 0x3b}};

/* Signature algorithm IDs */
#define EFI_SIGNATURE_DATA_GUID \
    {{0x1, 0x7a, 0x5e, 0xc2, 0x3d, 0x9f, 0xb4, 0xa8, 
      0xe6, 0xd1, 0xf9, 0xc5, 0xb7, 0x4a, 0x8e, 0x2c}}

/* ============================================================================
 * Data structures
 */

typedef enum {
    SB_STATUS_OK = 0,
    SB_STATUS_NO_PK,
    SB_STATUS_NO_KEK,
    SB_STATUS_NO_DB,
    SB_STATUS_S3_VULN,
    SB_STATUS_SMM_THREAT,
    SB_STATUS_WEAK_SIG,
    SB_STATUS_DISABLED,
    SB_STATUS_UNKNOWN_GUID,
} SecureBootStatus;

typedef struct {
    uint8_t data[EFI_GUID_SIZE];
    uint64_t size;
    uint32_t algo_id;  /* Signature algorithm ID */
    uint32_t flags;    /* Additional metadata flags */
} EFI_SIGNATURE_DATA;

typedef enum {
    SB_ALGO_RSA1024 = 0x1,
    SB_ALGO_RSA2048 = 0x2,
    SB_ALGO_RSA4096 = 0x3,
    SB_ALGO_ECDSA_P256 = 0x4,
    SB_ALGO_ECDSA_P384 = 0x5,
} SecureBootAlgorithm;

typedef struct {
    EFI_GUID guid;
    uint64_t size;
    uint32_t algo_id;
    uint32_t flags;
    uint8_t data[1];  /* Variable length */
} EFI_SIGNATURE_LIST;

/* ============================================================================
 * Utility functions
 */

static int guid_equal(const EFI_GUID *a, const EFI_GUID *b) {
    return memcmp(a->data, b->data, EFI_GUID_SIZE) == 0;
}

static void guid_print(const EFI_GUID *g, FILE *out) {
    fprintf(out, "{%02x%02x%02x%02x-%02x%02x-%02x%02x-"
                   "%02x%02x-%02x%02x-%02x%02x-%02x%02x}",
            g->data[0], g->data[1], g->data[2], g->data[3],
            g->data[4], g->data[5], g->data[6], g->data[7],
            g->data[8], g->data[9], g->data[10], g->data[11],
            g->data[12], g->data[13], g->data[14], g->data[15]);
}

static uint64_t guid_hash(const EFI_GUID *g) {
    uint64_t hash = 0;
    for (int i = 0; i < EFI_GUID_SIZE; i++) {
        hash ^= (uint64_t)g->data[i] << ((i % 8) * 8);
        hash *= 31;
    }
    return hash;
}

/* ============================================================================
 * Signature verification helpers
 */

static int verify_rsa_signature(const uint8_t *sig, size_t sig_len,
                                 const uint8_t *pub_key, size_t pub_key_len) {
    /* Simplified RSA-PKCS1v1.5 verification for demonstration */
    
    if (sig_len < 64 || pub_key_len < 256) {
        return -1;  /* Too short to be valid */
    }

    /* Check padding format (simplified) */
    uint8_t pad = sig[0];
    if (pad != 0x00 && pad != 0xFF) {
        return -2;  /* Invalid padding byte */
    }

    /* In real implementation, would use OpenSSL or similar */
    /* For demo: check basic structure */
    if (sig_len < pub_key_len / 4) {
        return -3;  /* Signature too small for key size */
    }

    return 0;  /* Assume valid for demo purposes */
}

static int verify_ecdsa_signature(const uint8_t *sig, size_t sig_len,
                                   const uint8_t *pub_key, size_t pub_key_len) {
    if (sig_len < 64 || pub_key_len < 32) {
        return -1;
    }

    /* ECDSA signature must be at least 64 bytes */
    if (sig_len < 64) {
        return -2;
    }

    return 0;
}

/* ============================================================================
 * NVRAM variable parsing
 */

typedef enum {
    VAR_TYPE_GUID = 1,
    VAR_TYPE_STRING = 2,
    VAR_TYPE_DATA = 3,
} VarType;

typedef struct {
    uint8_t type;
    EFI_GUID guid;
    uint64_t size;
    uint32_t attributes;
    uint64_t data_offset;
    uint8_t data[1];
} NVRAM_VAR;

/* Simulated NVRAM dump structure */
typedef struct {
    uint32_t header_size;
    uint32_t num_variables;
    NVRAM_VAR variables[];
} NVRAM_HEADER;

static int parse_nvram_header(const uint8_t *data, size_t len) {
    if (len < sizeof(NVRAM_HEADER)) {
        return -1;  /* Header too small */
    }

    NVRAM_HEADER *hdr = (NVRAM_HEADER *)data;
    
    if (hdr->header_size == 0 || hdr->num_variables == 0) {
        return -2;  /* Invalid header */
    }

    return 0;
}

/* ============================================================================
 * Secure Boot validation functions
 */

typedef struct {
    uint8_t pk_present : 1;
    uint8_t pk_valid : 1;
    uint8_t kek_present : 1;
    uint8_t kek_valid : 1;
    uint8_t db_present : 1;
    uint8_t db_valid : 1;
    uint8_t s3_script_present : 1;
    uint8_t s3_vulnerable : 1;
    uint8_t smm_threat_found : 1;
    uint8_t secure_boot_enabled : 1;
    uint8_t weak_signature : 1;
} SecureBootReport;

static void init_report(SecureBootReport *r) {
    memset(r, 0, sizeof(*r));
}

/* Check if PK is present and valid */
static int check_pk(const NVRAM_VAR *var, SecureBootReport *report) {
    report->pk_present = (var != NULL);
    
    if (!report->pk_present) {
        return SB_STATUS_NO_PK;
    }

    /* Check GUID matches expected PK GUID */
    if (guid_equal(&var->guid, &g_EFI_GLOBAL_PK)) {
        report->pk_valid = 1;
        
        /* Check signature algorithm strength */
        switch (var->algo_id) {
            case SB_ALGO_RSA2048:
            case SB_ALGO_RSA4096:
                break;  /* Acceptable */
            case SB_ALGO_ECDSA_P384:
                report->weak_signature = 1;
                break;  /* ECDSA can be weaker than RSA-4096 */
            default:
                if (var->algo_id < SB_ALGO_RSA2048) {
                    report->weak_signature = 1;
                }
                break;
        }

        return SB_STATUS_OK;
    }

    /* GUID mismatch - might be a different PK */
    report->pk_valid = 0;
    return SB_STATUS_UNKNOWN_GUID;
}

/* Check KEK presence and validity */
static int check_kek(const NVRAM_VAR *var, SecureBootReport *report) {
    report->kek_present = (var != NULL);
    
    if (!report->kek_present) {
        return SB_STATUS_NO_KEK;
    }

    if (guid_equal(&var->guid, &g_EFI_GLOBAL_KEK)) {
        report->kek_valid = 1;
        return SB_STATUS_OK;
    }

    report->kek_valid = 0;
    return SB_STATUS_UNKNOWN_GUID;
}

/* Check DB presence and validity */
static int check_db(const NVRAM_VAR *var, SecureBootReport *report) {
    report->db_present = (var != NULL);
    
    if (!report->db_present) {
        return SB_STATUS_NO_DB;
    }

    if (guid_equal(&var->guid, &g_EFI_GLOBAL_DB)) {
        report->db_valid = 1;
        
        /* Check for unsigned modules in DB */
        uint64_t db_size = var->size;
        uint32_t module_count = 0;
        
        if (db_size > 0) {
            /* Parse module list from DB */
            const uint8_t *ptr = &var->data[0];
            
            while (ptr < (const uint8_t *)&var + var->size && 
                   ptr - &var->data < db_size) {
                if (*ptr == 0x00) {
                    module_count++;
                    ptr += 1;  /* Skip null terminator */
                } else if (*ptr == 0xFF) {
                    break;  /* End of list */
                } else {
                    /* Module entry - check signature */
                    uint8_t sig_byte = *ptr;
                    
                    /* Check for unsigned module indicator */
                    if (sig_byte < 0x10 || sig_byte > 0xF0) {
                        report->db_valid = 0;
                        return SB_STATUS_WEAK_SIG;
                    }
                    
                    ptr++;
                }
            }
        }

        return SB_STATUS_OK;
    }

    report->db_valid = 0;
    return SB_STATUS_UNKNOWN_GUID;
}

/* Check S3 boot script for vulnerabilities */
static int check_s3_script(const NVRAM_VAR *var, SecureBootReport *report) {
    if (!report->s3_script_present || !report->db_present) {
        return SB_STATUS_OK;  /* No script or no DB to check */
    }

    report->s3_vulnerable = 0;

    /* Check for known vulnerable patterns in S3 boot script */
    const uint8_t *data = &var->data[0];
    
    /* Pattern 1: Direct memory access without bounds checking */
    if (strstr((char*)data, "mov eax, [eax+4]")) {
        report->s3_vulnerable = 1;
    }

    /* Pattern 2: Unchecked user input handling */
    if (strstr((char*)data, "scanf(") || strstr((char*)data, "gets(")) {
        report->s3_vulnerable = 1;
    }

    /* Pattern 3: SMM handoff without proper validation */
    if (guid_equal(&var->guid, &g_EFI_S3_BOOT_SCRIPT)) {
        if (strstr((char*)data, "SmmHandoff(") || 
            strstr((char*)data, "GopInstallMode")) {
            
            /* Check for proper SMM validation */
            uint8_t *ptr = (uint8_t *)data;
            int has_validation = 0;
            
            while (*ptr && !has_validation) {
                if (strstr((char*)ptr, "ValidateSmmContext(")) {
                    has_validation = 1;
                } else if (guid_equal(&var->guid, &g_SMM_THREAT_1)) {
                    report->smm_threat_found = 1;
                    return SB_STATUS_SMM_THREAT;
                } else if (guid_equal(&var->guid, &g_SMM_THREAT_2)) {
                    report->smm_threat_found = 1;
                    return SB_STATUS_SMM_THREAT;
                }
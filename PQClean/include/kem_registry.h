#ifndef KEM_REGISTRY_H
#define KEM_REGISTRY_H

#include <stdint.h>
#include <stdbool.h>

// Maximum number of KEMs we can register (increased for all PQClean KEMs)
#define MAX_KEMS 50

// KEM algorithm information
typedef struct kem_info {
    const char* name;           // e.g., "ml-kem-512"
    const char* variant;        // e.g., "clean", "avx2", "aarch64"
    uint32_t pk_bytes;          // Public key size
    uint32_t sk_bytes;          // Secret key size
    uint32_t ct_bytes;          // Ciphertext size
    uint32_t ss_bytes;          // Shared secret size
    
    // Function pointers to the actual KEM operations
    int (*keypair)(uint8_t *pk, uint8_t *sk);
    int (*encaps)(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    int (*decaps)(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
    
    bool enabled;               // Whether this KEM is enabled for testing
} kem_info_t;

// Global KEM registry
extern kem_info_t kem_registry[MAX_KEMS];
extern uint32_t kem_count;

// KEM registration and discovery functions
void register_kem(const char* name, const char* variant,
                  uint32_t pk_bytes, uint32_t sk_bytes, uint32_t ct_bytes, uint32_t ss_bytes,
                  int (*keypair)(uint8_t*, uint8_t*),
                  int (*encaps)(uint8_t*, uint8_t*, const uint8_t*),
                  int (*decaps)(uint8_t*, const uint8_t*, const uint8_t*));

void discover_and_register_all_kems(void);
kem_info_t* get_kem_by_index(uint32_t index);
kem_info_t* get_enabled_kem(void);
kem_info_t* get_kem_by_name(const char* name);
uint32_t get_enabled_kem_count(void);
void enable_kem(const char* name, bool enabled);

// Utility functions
void print_registered_kems(void);
bool validate_kem_api(kem_info_t* kem);

#endif // KEM_REGISTRY_H

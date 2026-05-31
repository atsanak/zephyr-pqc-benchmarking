#ifndef SIGN_REGISTRY_H
#define SIGN_REGISTRY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define MAX_SIGNS 20  // Support up to 20 signature algorithms

// Function pointer typedefs for signature operations (matches KEM pattern)
typedef int (*sign_keypair_func_t)(uint8_t *pk, uint8_t *sk);
typedef int (*sign_signature_func_t)(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t m_len, const uint8_t *sk);
typedef int (*sign_verify_func_t)(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t m_len, const uint8_t *pk);

// Signature algorithm information - matches KEM structure exactly
// Note: Named sign_info (not sign_info_t) so forward declaration in utils.h works
typedef struct sign_info {
    const char* name;           // e.g., "ml-dsa-44"
    const char* variant;        // e.g., "clean", "avx2", "aarch64"
    uint32_t pk_bytes;          // Public key size
    uint32_t sk_bytes;          // Secret key size
    uint32_t signature_bytes;   // Signature size (named signature_bytes for clarity)
    
    // Function pointers to the actual signature operations
    sign_keypair_func_t keypair;
    sign_signature_func_t sign;
    sign_verify_func_t verify;
    
    bool enabled;               // Whether this signature is enabled for testing
} sign_info_t;

// Global signature registry
extern sign_info_t sign_registry[MAX_SIGNS];
extern uint32_t sign_count;

// Registry management functions
bool register_sign(const char* name, const char* variant,
                  uint32_t pk_bytes, uint32_t sk_bytes, uint32_t sig_bytes,
                  sign_keypair_func_t keypair_func,
                  sign_signature_func_t sign_func,
                  sign_verify_func_t verify_func);

void discover_and_register_all_signs(void);
void print_registered_signs(void);
sign_info_t* get_sign_by_name(const char* name);
bool validate_sign_api(sign_info_t* sign);

// Configuration functions  
void enable_sign(const char* name, bool enabled);
void disable_sign(const char* name);
void enable_all_signs(void);
void disable_all_signs(void);

// Statistics and info
uint32_t get_enabled_sign_count(void);
void list_enabled_signs(void);

// Index-based access (matches KEM registry pattern)
sign_info_t* get_sign_by_index(uint32_t index);
sign_info_t* get_enabled_sign(void);

#endif // SIGN_REGISTRY_H

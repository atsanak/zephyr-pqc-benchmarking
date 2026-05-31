#ifndef KEM_H
#define KEM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * @brief KEM descriptor structure for runtime crypto-agility
 * 
 * This structure provides a unified interface for all KEMs,
 * allowing runtime selection and dynamic benchmarking.
 */
typedef struct {
    const char  *name;           ///< KEM algorithm name (e.g., "ml-kem-512")
    const char  *variant;        ///< KEM variant (e.g., "clean", "avx2")
    size_t       pk_bytes;       ///< Public key size in bytes
    size_t       sk_bytes;       ///< Secret key size in bytes  
    size_t       ct_bytes;       ///< Ciphertext size in bytes
    size_t       ss_bytes;       ///< Shared secret size in bytes
    
    // KEM operations function pointers
    int  (*keypair)(uint8_t *pk, uint8_t *sk);
    int  (*encaps) (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    int  (*decaps) (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
    
    // Optional metadata
    const char  *description;    ///< Human-readable description
    uint32_t     security_level; ///< NIST security level (1-5)
    bool         enabled;        ///< Whether this KEM is enabled at compile time
} kem_desc_t;

/**
 * @brief Get all available KEM descriptors
 * @param count Pointer to store the number of available KEMs
 * @return Array of KEM descriptors
 */
const kem_desc_t* get_all_kems(size_t *count);

/**
 * @brief Find a KEM descriptor by name
 * @param name KEM name to search for
 * @return KEM descriptor or NULL if not found
 */
const kem_desc_t* find_kem_by_name(const char *name);

/**
 * @brief Get the maximum key/ciphertext size across all KEMs
 * @param max_pk_bytes Pointer to store maximum public key size
 * @param max_sk_bytes Pointer to store maximum secret key size
 * @param max_ct_bytes Pointer to store maximum ciphertext size
 * @param max_ss_bytes Pointer to store maximum shared secret size
 */
void get_max_kem_sizes(size_t *max_pk_bytes, size_t *max_sk_bytes, 
                       size_t *max_ct_bytes, size_t *max_ss_bytes);

#endif // KEM_H

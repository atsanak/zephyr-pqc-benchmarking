#include "kem_registry.h"
#include "utils.h"
#include <zephyr/sys/printk.h>
#include <zephyr/kernel.h>
#include <string.h>

// Global KEM registry storage
kem_info_t kem_registry[MAX_KEMS];
uint32_t kem_count = 0;

// Include all KEM API headers with fallback error handling
#include <stdint.h>

// ========================================================================
// ML-KEM-512 (if enabled via compile flag)
// ========================================================================
#ifdef ENABLE_ML_KEM_512
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_kem/ml-kem-512/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "ML-KEM-512 API header not found, using fallback constants"
// Use verified constants from NIST ML-KEM specification
#define PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES  800
#define PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES  1632
#define PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES 768
#define PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES           32
#define MLKEM512_USING_FALLBACK_CONSTANTS 1
#else
#define MLKEM512_USING_FALLBACK_CONSTANTS 0
#endif

// ML-KEM-512 API functions (if enabled)
#ifdef ENABLE_ML_KEM_512
extern int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif
#endif

// ML-KEM-768 API functions (available in PQClean but disabled by default)
#ifdef ENABLE_ML_KEM_768
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_kem/ml-kem-768/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "ML-KEM-768 API header not found, using fallback constants"
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES  1184
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES  2400
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES 1088
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES           32
#define MLKEM768_USING_FALLBACK_CONSTANTS 1
#else
#define MLKEM768_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

// ML-KEM-1024 API functions (available in PQClean but disabled by default)
#ifdef ENABLE_ML_KEM_1024
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_kem/ml-kem-1024/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "ML-KEM-1024 API header not found, using fallback constants"
#define PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES  1568
#define PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES  3168
#define PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES 1568
#define PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES           32
#define MLKEM1024_USING_FALLBACK_CONSTANTS 1
#else
#define MLKEM1024_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

// HQC-128 API functions (available in PQClean but disabled by default)
#ifdef ENABLE_HQC_128
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_kem/hqc-128/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "HQC-128 API header not found, using fallback constants"
#define PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES   2249
#define PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES   2305
#define PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES  4433
#define PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES            64
#define HQC128_USING_FALLBACK_CONSTANTS 1
#else
#define HQC128_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_HQC128_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_HQC128_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

// HQC-192 API functions 
#ifdef ENABLE_HQC_192
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_kem/hqc-192/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "HQC-192 API header not found, using fallback constants"
#define PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES   4522
#define PQCLEAN_HQC192_CLEAN_CRYPTO_SECRETKEYBYTES   4586
#define PQCLEAN_HQC192_CLEAN_CRYPTO_CIPHERTEXTBYTES  8978
#define PQCLEAN_HQC192_CLEAN_CRYPTO_BYTES            64
#define HQC192_USING_FALLBACK_CONSTANTS 1
#else
#define HQC192_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_HQC192_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_HQC192_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_HQC192_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

// HQC-256 API functions 
#ifdef ENABLE_HQC_256
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_kem/hqc-256/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "HQC-256 API header not found, using fallback constants"
#define PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES   7245
#define PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES   7317
#define PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES  14421
#define PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES            64
#define HQC256_USING_FALLBACK_CONSTANTS 1
#else
#define HQC256_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_HQC256_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_HQC256_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

// ========================================================================
// McEliece KEMs (Warning: Very large public keys - up to 1.3MB!)
// ========================================================================

// McEliece 348864 API functions (very large keys - 261KB public key!)
#ifdef ENABLE_MCELIECE_348864
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_kem/mceliece348864/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "McEliece348864 API header not found, using fallback constants"
#define PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_PUBLICKEYBYTES  261120  // 261KB public key!
#define PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_SECRETKEYBYTES  6492
#define PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_CIPHERTEXTBYTES 96
#define PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_BYTES           32
#define MCELIECE348864_USING_FALLBACK_CONSTANTS 1
#else
#define MCELIECE348864_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

// McEliece 348864f API functions (fast variant)
#ifdef ENABLE_MCELIECE_348864F
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_kem/mceliece348864f/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "McEliece348864f API header not found, using fallback constants"
#define PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_PUBLICKEYBYTES  261120
#define PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_SECRETKEYBYTES  6492
#define PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_CIPHERTEXTBYTES 96
#define PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_BYTES           32
#define MCELIECE348864F_USING_FALLBACK_CONSTANTS 1
#else
#define MCELIECE348864F_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

// McEliece 460896 
#ifdef ENABLE_MCELIECE_460896
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_kem/mceliece460896/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "McEliece460896 API header not found, using fallback constants"
#define PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_PUBLICKEYBYTES  524160
#define PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_SECRETKEYBYTES  13608
#define PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_CIPHERTEXTBYTES 156
#define PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_BYTES           32
#define MCELIECE460896_USING_FALLBACK_CONSTANTS 1
#else
#define MCELIECE460896_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

// McEliece 460896f (fast variant)
#ifdef ENABLE_MCELIECE_460896F
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_kem/mceliece460896f/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "McEliece460896f API header not found, using fallback constants"
#define PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_PUBLICKEYBYTES  524160
#define PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_SECRETKEYBYTES  13608
#define PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_CIPHERTEXTBYTES 156
#define PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_BYTES           32
#define MCELIECE460896F_USING_FALLBACK_CONSTANTS 1
#else
#define MCELIECE460896F_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

// McEliece 6688128
#ifdef ENABLE_MCELIECE_6688128
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_kem/mceliece6688128/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "McEliece6688128 API header not found, using fallback constants"
#define PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_PUBLICKEYBYTES  1044992
#define PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_SECRETKEYBYTES  13932
#define PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_CIPHERTEXTBYTES 208
#define PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_BYTES           32
#define MCELIECE6688128_USING_FALLBACK_CONSTANTS 1
#else
#define MCELIECE6688128_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

// McEliece 6688128f (fast variant)
#ifdef ENABLE_MCELIECE_6688128F
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_kem/mceliece6688128f/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "McEliece6688128f API header not found, using fallback constants"
#define PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_PUBLICKEYBYTES  1044992
#define PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_SECRETKEYBYTES  13932
#define PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_CIPHERTEXTBYTES 208
#define PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_BYTES           32
#define MCELIECE6688128F_USING_FALLBACK_CONSTANTS 1
#else
#define MCELIECE6688128F_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

// McEliece 6960119
#ifdef ENABLE_MCELIECE_6960119
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_kem/mceliece6960119/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "McEliece6960119 API header not found, using fallback constants"
#define PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES  1047319
#define PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES  13948
#define PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_CIPHERTEXTBYTES 194
#define PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES           32
#define MCELIECE6960119_USING_FALLBACK_CONSTANTS 1
#else
#define MCELIECE6960119_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

// McEliece 6960119f (fast variant)
#ifdef ENABLE_MCELIECE_6960119F
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_kem/mceliece6960119f/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "McEliece6960119f API header not found, using fallback constants"
#define PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_PUBLICKEYBYTES  1047319
#define PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_SECRETKEYBYTES  13948
#define PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_CIPHERTEXTBYTES 194
#define PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_BYTES           32
#define MCELIECE6960119F_USING_FALLBACK_CONSTANTS 1
#else
#define MCELIECE6960119F_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

// McEliece 8192128
#ifdef ENABLE_MCELIECE_8192128
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_kem/mceliece8192128/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "McEliece8192128 API header not found, using fallback constants"
#define PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_PUBLICKEYBYTES  1357824  // 1.3MB public key!
#define PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_SECRETKEYBYTES  14120
#define PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_CIPHERTEXTBYTES 208
#define PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_BYTES           32
#define MCELIECE8192128_USING_FALLBACK_CONSTANTS 1
#else
#define MCELIECE8192128_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

// McEliece 8192128f (fast variant) 
#ifdef ENABLE_MCELIECE_8192128F
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_kem/mceliece8192128f/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "McEliece8192128f API header not found, using fallback constants"
#define PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_PUBLICKEYBYTES  1357824
#define PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_SECRETKEYBYTES  14120
#define PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_CIPHERTEXTBYTES 208
#define PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_BYTES           32
#define MCELIECE8192128F_USING_FALLBACK_CONSTANTS 1
#else
#define MCELIECE8192128F_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

// ========================================================================
// KEM Registration Functions
// ========================================================================

void register_kem(const char* name, const char* variant,
                  uint32_t pk_bytes, uint32_t sk_bytes, uint32_t ct_bytes, uint32_t ss_bytes,
                  int (*keypair)(uint8_t*, uint8_t*),
                  int (*encaps)(uint8_t*, uint8_t*, const uint8_t*),
                  int (*decaps)(uint8_t*, const uint8_t*, const uint8_t*)) {
    
    // Comprehensive input validation - NO FALLBACKS OR FAKE DATA!
    if (!name) {
        printk("ERROR: register_kem - NULL name pointer\n");
        return;
    }
    
    if (!variant) {
        printk("ERROR: register_kem - NULL variant pointer\n");
        return;
    }
    
    if (!keypair) {
        printk("ERROR: register_kem - NULL keypair function for %s-%s\n", name, variant);
        return;
    }
    
    if (!encaps) {
        printk("ERROR: register_kem - NULL encaps function for %s-%s\n", name, variant);
        return;
    }
    
    if (!decaps) {
        printk("ERROR: register_kem - NULL decaps function for %s-%s\n", name, variant);
        return;
    }
    
    // Validate key sizes are realistic (not zero, not impossibly large)
    if (pk_bytes == 0) {
        printk("ERROR: register_kem - Zero public key size for %s-%s\n", name, variant);
        return;
    }
    
    if (sk_bytes == 0) {
        printk("ERROR: register_kem - Zero secret key size for %s-%s\n", name, variant);
        return;
    }
    
    if (ct_bytes == 0) {
        printk("ERROR: register_kem - Zero ciphertext size for %s-%s\n", name, variant);
        return;
    }
    
    if (ss_bytes == 0) {
        printk("ERROR: register_kem - Zero shared secret size for %s-%s\n", name, variant);
        return;
    }
    
    // Check for impossibly large sizes (>10MB indicates error)
    if (pk_bytes > 10*1024*1024) {
        printk("ERROR: register_kem - Public key too large for %s-%s: %u bytes\n", name, variant, pk_bytes);
        return;
    }
    
    if (sk_bytes > 10*1024*1024) {
        printk("ERROR: register_kem - Secret key too large for %s-%s: %u bytes\n", name, variant, sk_bytes);
        return;
    }
    
    if (kem_count >= MAX_KEMS) {
        printk("ERROR: register_kem - KEM registry full (%u/%u), cannot register %s-%s\n", 
               kem_count, MAX_KEMS, name, variant);
        return;
    }
    
    // Check for duplicate registration
    for (uint32_t i = 0; i < kem_count; i++) {
        if (strcmp(kem_registry[i].name, name) == 0 && strcmp(kem_registry[i].variant, variant) == 0) {
            printk("ERROR: register_kem - Duplicate registration attempt for %s-%s\n", name, variant);
            return;
        }
    }
    
    printk("*** Registering KEM: %s-%s (PK:%u, SK:%u, CT:%u, SS:%u bytes)\n", 
           name, variant, pk_bytes, sk_bytes, ct_bytes, ss_bytes);
    
    kem_info_t* kem = &kem_registry[kem_count];
    kem->name = name;
    kem->variant = variant;
    kem->pk_bytes = pk_bytes;
    kem->sk_bytes = sk_bytes;
    kem->ct_bytes = ct_bytes;
    kem->ss_bytes = ss_bytes;
    kem->keypair = keypair;
    kem->encaps = encaps;
    kem->decaps = decaps;
    kem->enabled = true;
    
    kem_count++;
    printk("Registered KEM: %s-%s (%u/%u/%u/%u bytes)\n", 
           name, variant, pk_bytes, sk_bytes, ct_bytes, ss_bytes);
}

void discover_and_register_all_kems(void) {
    printk("*** Comprehensive KEM Discovery & Registration ***\n");
    printk("=================================================\n");
    
    // Report API header detection status
    printk("*** API Header Detection Status ***\n");
#ifdef ENABLE_ML_KEM_512
    printk("ML-KEM-512: %s\n", MLKEM512_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_ML_KEM_768
    printk("ML-KEM-768: %s\n", MLKEM768_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_ML_KEM_1024
    printk("ML-KEM-1024: %s\n", MLKEM1024_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_HQC_128
    printk("HQC-128: %s\n", HQC128_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_HQC_192
    printk("HQC-192: %s\n", HQC192_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_HQC_256
    printk("HQC-256: %s\n", HQC256_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_MCELIECE_348864
    printk("McEliece348864: %s\n", MCELIECE348864_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_MCELIECE_348864F
    printk("McEliece348864f: %s\n", MCELIECE348864F_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_MCELIECE_460896
    printk("McEliece460896: %s\n", MCELIECE460896_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_MCELIECE_460896F
    printk("McEliece460896f: %s\n", MCELIECE460896F_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_MCELIECE_6688128
    printk("McEliece6688128: %s\n", MCELIECE6688128_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_MCELIECE_6688128F
    printk("McEliece6688128f: %s\n", MCELIECE6688128F_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_MCELIECE_6960119
    printk("McEliece6960119: %s\n", MCELIECE6960119_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_MCELIECE_6960119F
    printk("McEliece6960119f: %s\n", MCELIECE6960119F_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_MCELIECE_8192128
    printk("McEliece8192128: %s\n", MCELIECE8192128_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_MCELIECE_8192128F
    printk("McEliece8192128f: %s\n", MCELIECE8192128F_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
    printk("=====================================\n");
    
    // Register ML-KEM-512 (if enabled via compile flag)
#ifdef ENABLE_ML_KEM_512
    register_kem("ml-kem-512", "clean",
                 PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                 PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair,
                 PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc,
                 PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec);
#endif

    // Register ML-KEM-768 (if enabled via compile flag)
#ifdef ENABLE_ML_KEM_768
    register_kem("ml-kem-768", "clean",
                 PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                 PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair,
                 PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc,
                 PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec);
#endif

    // Register ML-KEM-1024 (if enabled via compile flag)
#ifdef ENABLE_ML_KEM_1024
    register_kem("ml-kem-1024", "clean",
                 PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                 PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair,
                 PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc,
                 PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec);
#endif

    // Register HQC-128 (if enabled via compile flag)
#ifdef ENABLE_HQC_128
    register_kem("hqc-128", "clean",
                 PQCLEAN_HQC128_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_HQC128_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_HQC128_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                 PQCLEAN_HQC128_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_HQC128_CLEAN_crypto_kem_keypair,
                 PQCLEAN_HQC128_CLEAN_crypto_kem_enc,
                 PQCLEAN_HQC128_CLEAN_crypto_kem_dec);
#endif

    // Register HQC-192 (if enabled via compile flag)
#ifdef ENABLE_HQC_192
    register_kem("hqc-192", "clean",
                 PQCLEAN_HQC192_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_HQC192_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_HQC192_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                 PQCLEAN_HQC192_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_HQC192_CLEAN_crypto_kem_keypair,
                 PQCLEAN_HQC192_CLEAN_crypto_kem_enc,
                 PQCLEAN_HQC192_CLEAN_crypto_kem_dec);
#endif

    // Register HQC-256 (if enabled via compile flag)
#ifdef ENABLE_HQC_256
    register_kem("hqc-256", "clean",
                 PQCLEAN_HQC256_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_HQC256_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_HQC256_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                 PQCLEAN_HQC256_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_HQC256_CLEAN_crypto_kem_keypair,
                 PQCLEAN_HQC256_CLEAN_crypto_kem_enc,
                 PQCLEAN_HQC256_CLEAN_crypto_kem_dec);
#endif

    // Register McEliece 348864 (if enabled - WARNING: 261KB public key!)
#ifdef ENABLE_MCELIECE_348864
    register_kem("mceliece348864", "clean",
                 PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                 PQCLEAN_MCELIECE348864_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_keypair,
                 PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_enc,
                 PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_dec);
#endif

    // Register McEliece 348864f (fast variant)
#ifdef ENABLE_MCELIECE_348864F
    register_kem("mceliece348864f", "clean",
                 PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                 PQCLEAN_MCELIECE348864F_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_keypair,
                 PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_enc,
                 PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_dec);
#endif

    // Register McEliece 460896
#ifdef ENABLE_MCELIECE_460896
    register_kem("mceliece460896", "clean",
                 PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                 PQCLEAN_MCELIECE460896_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_keypair,
                 PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_enc,
                 PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_dec);
#endif

    // Register McEliece 460896f (fast variant)
#ifdef ENABLE_MCELIECE_460896F
    register_kem("mceliece460896f", "clean",
                 PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                 PQCLEAN_MCELIECE460896F_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_keypair,
                 PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_enc,
                 PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_dec);
#endif

    // Register McEliece 6688128
#ifdef ENABLE_MCELIECE_6688128
    register_kem("mceliece6688128", "clean",
                 PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                 PQCLEAN_MCELIECE6688128_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_keypair,
                 PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_enc,
                 PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_dec);
#endif

    // Register McEliece 6688128f (fast variant)
#ifdef ENABLE_MCELIECE_6688128F
    register_kem("mceliece6688128f", "clean",
                 PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                 PQCLEAN_MCELIECE6688128F_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_keypair,
                 PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_enc,
                 PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_dec);
#endif

    // Register McEliece 6960119
#ifdef ENABLE_MCELIECE_6960119
    register_kem("mceliece6960119", "clean",
                 PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                 PQCLEAN_MCELIECE6960119_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair,
                 PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc,
                 PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_dec);
#endif

    // Register McEliece 6960119f (fast variant)
#ifdef ENABLE_MCELIECE_6960119F
    register_kem("mceliece6960119f", "clean",
                 PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                 PQCLEAN_MCELIECE6960119F_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_keypair,
                 PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_enc,
                 PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_dec);
#endif

    // Register McEliece 8192128
#ifdef ENABLE_MCELIECE_8192128
    register_kem("mceliece8192128", "clean",
                 PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                 PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_keypair,
                 PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_enc,
                 PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_dec);
#endif

    // Register McEliece 8192128f (fast variant)
#ifdef ENABLE_MCELIECE_8192128F
    register_kem("mceliece8192128f", "clean",
                 PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                 PQCLEAN_MCELIECE8192128F_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_keypair,
                 PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_enc,
                 PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_dec);
#endif

    printk("Total KEMs registered: %u\n", kem_count);
    printk("Note: Additional KEMs can be enabled via compile flags\n");
    printk("Warning: McEliece variants have very large keys (>250KB) and require significant memory\n");
}

kem_info_t* get_kem_by_index(uint32_t index) {
    if (index >= kem_count) {
        return NULL;
    }
    return &kem_registry[index];
}

kem_info_t* get_kem_by_name(const char* name) {
    for (uint32_t i = 0; i < kem_count; i++) {
        if (strcmp(kem_registry[i].name, name) == 0) {
            return &kem_registry[i];
        }
    }
    return NULL;
}

uint32_t get_enabled_kem_count(void) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < kem_count; i++) {
        if (kem_registry[i].enabled) {
            count++;
        }
    }
    return count;
}

void enable_kem(const char* name, bool enabled) {
    kem_info_t* kem = get_kem_by_name(name);
    if (kem) {
        kem->enabled = enabled;
        printk("KEM %s %s\n", name, enabled ? "enabled" : "disabled");
    } else {
        printk("KEM %s not found\n", name);
    }
}

void print_registered_kems(void) {
    printk("\n*** Registered KEMs (%u total)\n", kem_count);
    printk("================================\n");
    printk("Name\t\tVariant\t\tPK\tSK\tCT\tSS\tEnabled\n");
    printk("----\t\t-------\t\t--\t--\t--\t--\t-------\n");
    
    for (uint32_t i = 0; i < kem_count; i++) {
        kem_info_t* kem = &kem_registry[i];
        printk("%-12s\t%-8s\t%u\t%u\t%u\t%u\t%s\n",
               kem->name, kem->variant,
               kem->pk_bytes, kem->sk_bytes, kem->ct_bytes, kem->ss_bytes,
               kem->enabled ? "YES" : "NO");
    }
    printk("\n");
}

bool validate_kem_api(kem_info_t* kem) {
    // Comprehensive input validation - REAL DATA ONLY!
    if (!kem) {
        printk("ERROR: validate_kem_api - NULL kem pointer\n");
        return false;
    }
    
    if (!kem->name) {
        printk("ERROR: validate_kem_api - NULL kem name\n");
        return false;
    }
    
    if (!kem->keypair) {
        printk("ERROR: validate_kem_api - NULL keypair function for %s\n", kem->name);
        return false;
    }
    
    if (!kem->encaps) {
        printk("ERROR: validate_kem_api - NULL encaps function for %s\n", kem->name);
        return false;
    }
    
    if (!kem->decaps) {
        printk("ERROR: validate_kem_api - NULL decaps function for %s\n", kem->name);
        return false;
    }
    
    // Validate key sizes are realistic
    if (kem->pk_bytes == 0 || kem->sk_bytes == 0 || kem->ct_bytes == 0 || kem->ss_bytes == 0) {
        printk("ERROR: validate_kem_api - Invalid key sizes for %s (pk:%u, sk:%u, ct:%u, ss:%u)\n",
               kem->name, kem->pk_bytes, kem->sk_bytes, kem->ct_bytes, kem->ss_bytes);
        return false;
    }
    
    printk("*** Validating KEM %s-%s with REAL cryptographic operations\n", kem->name, kem->variant);
    printk("*** Key sizes: PK=%u, SK=%u, CT=%u, SS=%u bytes\n", 
           kem->pk_bytes, kem->sk_bytes, kem->ct_bytes, kem->ss_bytes);
    
    // Allocate buffers based on the actual KEM size requirements
    // Use dynamic allocation to avoid stack overflow for large KEMs
    uint8_t* pk = k_malloc(kem->pk_bytes);
    uint8_t* sk = k_malloc(kem->sk_bytes);
    uint8_t* ct = k_malloc(kem->ct_bytes);
    uint8_t* ss1 = k_malloc(kem->ss_bytes);
    uint8_t* ss2 = k_malloc(kem->ss_bytes);
    
    if (!pk || !sk || !ct || !ss1 || !ss2) {
        printk("ERROR: validate_kem_api - Memory allocation failed for KEM %s\n", kem->name);
        printk("ERROR: Required memory: PK=%u + SK=%u + CT=%u + SS1=%u + SS2=%u = %u bytes total\n",
               kem->pk_bytes, kem->sk_bytes, kem->ct_bytes, kem->ss_bytes, kem->ss_bytes,
               kem->pk_bytes + kem->sk_bytes + kem->ct_bytes + 2*kem->ss_bytes);
        goto cleanup_and_fail;
    }
    
    // Initialize buffers to detect uninitialized data
    memset(pk, 0xFF, kem->pk_bytes);
    memset(sk, 0xFF, kem->sk_bytes);
    memset(ct, 0xFF, kem->ct_bytes);
    memset(ss1, 0xFF, kem->ss_bytes);
    memset(ss2, 0xFF, kem->ss_bytes);
    
    printk("*** STEP 1: Testing keypair generation for %s\n", kem->name);
    
    // Test keypair generation with REAL cryptography
    int keypair_result = kem->keypair(pk, sk);
    if (keypair_result != 0) {
        printk("ERROR: validate_kem_api - KEM %s keypair generation failed with code %d\n", kem->name, keypair_result);
        goto cleanup_and_fail;
    }
    
    // Verify keys were actually generated (not all zeros or all 0xFF)
    bool pk_all_zero = true, pk_all_ff = true;
    bool sk_all_zero = true, sk_all_ff = true;
    
    for (uint32_t i = 0; i < kem->pk_bytes; i++) {
        if (pk[i] != 0x00) pk_all_zero = false;
        if (pk[i] != 0xFF) pk_all_ff = false;
    }
    
    for (uint32_t i = 0; i < kem->sk_bytes; i++) {
        if (sk[i] != 0x00) sk_all_zero = false;
        if (sk[i] != 0xFF) sk_all_ff = false;
    }
    
    if (pk_all_zero || pk_all_ff) {
        printk("ERROR: validate_kem_api - KEM %s generated invalid public key (all %s)\n", 
               kem->name, pk_all_zero ? "zeros" : "0xFF");
        goto cleanup_and_fail;
    }
    
    if (sk_all_zero || sk_all_ff) {
        printk("ERROR: validate_kem_api - KEM %s generated invalid secret key (all %s)\n", 
               kem->name, sk_all_zero ? "zeros" : "0xFF");
        goto cleanup_and_fail;
    }
    
    printk("*** STEP 1 PASSED: Real keypair generated for %s\n", kem->name);
    
    printk("*** STEP 2: Testing encapsulation for %s\n", kem->name);
    
    // Test encapsulation with REAL cryptography
    int encaps_result = kem->encaps(ct, ss1, pk);
    if (encaps_result != 0) {
        printk("ERROR: validate_kem_api - KEM %s encapsulation failed with code %d\n", kem->name, encaps_result);
        goto cleanup_and_fail;
    }
    
    // Verify ciphertext and shared secret were generated (not all zeros or all 0xFF)
    bool ct_all_zero = true, ct_all_ff = true;
    bool ss1_all_zero = true, ss1_all_ff = true;
    
    for (uint32_t i = 0; i < kem->ct_bytes; i++) {
        if (ct[i] != 0x00) ct_all_zero = false;
        if (ct[i] != 0xFF) ct_all_ff = false;
    }
    
    for (uint32_t i = 0; i < kem->ss_bytes; i++) {
        if (ss1[i] != 0x00) ss1_all_zero = false;
        if (ss1[i] != 0xFF) ss1_all_ff = false;
    }
    
    if (ct_all_zero || ct_all_ff) {
        printk("ERROR: validate_kem_api - KEM %s generated invalid ciphertext (all %s)\n", 
               kem->name, ct_all_zero ? "zeros" : "0xFF");
        goto cleanup_and_fail;
    }
    
    if (ss1_all_zero || ss1_all_ff) {
        printk("ERROR: validate_kem_api - KEM %s generated invalid shared secret (all %s)\n", 
               kem->name, ss1_all_zero ? "zeros" : "0xFF");
        goto cleanup_and_fail;
    }
    
    printk("*** STEP 2 PASSED: Real encapsulation completed for %s\n", kem->name);
    
    printk("*** STEP 3: Testing decapsulation for %s\n", kem->name);
    
    // Test decapsulation with REAL cryptography
    int decaps_result = kem->decaps(ss2, ct, sk);
    if (decaps_result != 0) {
        printk("ERROR: validate_kem_api - KEM %s decapsulation failed with code %d\n", kem->name, decaps_result);
        goto cleanup_and_fail;
    }
    
    // Verify second shared secret was generated (not all zeros or all 0xFF)
    bool ss2_all_zero = true, ss2_all_ff = true;
    
    for (uint32_t i = 0; i < kem->ss_bytes; i++) {
        if (ss2[i] != 0x00) ss2_all_zero = false;
        if (ss2[i] != 0xFF) ss2_all_ff = false;
    }
    
    if (ss2_all_zero || ss2_all_ff) {
        printk("ERROR: validate_kem_api - KEM %s generated invalid second shared secret (all %s)\n", 
               kem->name, ss2_all_zero ? "zeros" : "0xFF");
        goto cleanup_and_fail;
    }
    
    printk("*** STEP 3 PASSED: Real decapsulation completed for %s\n", kem->name);
    
    printk("*** STEP 4: Verifying shared secret agreement for %s\n", kem->name);
    
    // Verify shared secrets match - THIS IS THE CRITICAL REAL DATA TEST
    if (memcmp(ss1, ss2, kem->ss_bytes) != 0) {
        printk("ERROR: validate_kem_api - KEM %s CRITICAL FAILURE: shared secrets do not match!\n", kem->name);
        printk("ERROR: This indicates the KEM implementation is broken or data is fake\n");
        
        // Print first few bytes for debugging
        printk("ERROR: SS1 first 8 bytes: ");
        for (int i = 0; i < 8 && i < (int)kem->ss_bytes; i++) {
            printk("%02x ", ss1[i]);
        }
        printk("\n");
        
        printk("ERROR: SS2 first 8 bytes: ");
        for (int i = 0; i < 8 && i < (int)kem->ss_bytes; i++) {
            printk("%02x ", ss2[i]);
        }
        printk("\n");
        
        goto cleanup_and_fail;
    }
    
    printk("*** STEP 4 PASSED: Shared secrets match perfectly for %s\n", kem->name);
    printk("*** SUCCESS: KEM %s-%s validation PASSED with REAL cryptographic data\n", kem->name, kem->variant);
    
    // Cleanup successful validation
    k_free(pk); k_free(sk); k_free(ct); k_free(ss1); k_free(ss2);
    return true;
    
cleanup_and_fail:
    printk("ERROR: validate_kem_api - KEM %s validation FAILED - cleaning up\n", kem->name ? kem->name : "UNKNOWN");
    if (pk) k_free(pk);
    if (sk) k_free(sk);
    if (ct) k_free(ct);
    if (ss1) k_free(ss1);
    if (ss2) k_free(ss2);
    return false;
}

kem_info_t* get_enabled_kem(void) {
    for (uint32_t i = 0; i < kem_count; i++) {
        if (kem_registry[i].enabled) {
            return &kem_registry[i];
        }
    }
    return NULL;
}

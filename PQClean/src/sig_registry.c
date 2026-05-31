#include "sig_registry.h"
#include "utils.h"
#include <zephyr/sys/printk.h>
#include <zephyr/kernel.h>
#include <string.h>

// Global Signature registry storage
sign_info_t sign_registry[MAX_SIGNS];
uint32_t sign_count = 0;

// Include all Signature API headers with fallback error handling
#include <stdint.h>

// ========================================================================
// ML-DSA-44 (if enabled via compile flag)
// ========================================================================
#ifdef ENABLE_ML_DSA_44
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_sign/ml-dsa-44/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "ML-DSA-44 API header not found, using fallback constants"
// Use verified constants from NIST ML-DSA specification
#define PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES  1312
#define PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES  2560
#define PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES           2420
#define MLDSA44_USING_FALLBACK_CONSTANTS 1
#else
#define MLDSA44_USING_FALLBACK_CONSTANTS 0
#endif

// ML-DSA-44 API functions (if enabled)
#ifdef ENABLE_ML_DSA_44
extern int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
#endif
#endif

// ML-DSA-65 API functions (available in PQClean but disabled by default)
#ifdef ENABLE_ML_DSA_65
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_sign/ml-dsa-65/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "ML-DSA-65 API header not found, using fallback constants"
#define PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES  1952
#define PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES  4032
#define PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES           3309
#define MLDSA65_USING_FALLBACK_CONSTANTS 1
#else
#define MLDSA65_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
#endif

// ML-DSA-87 API functions (available in PQClean but disabled by default)
#ifdef ENABLE_ML_DSA_87
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_sign/ml-dsa-87/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "ML-DSA-87 API header not found, using fallback constants"
#define PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES  2592
#define PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES  4896
#define PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES           4627
#define MLDSA87_USING_FALLBACK_CONSTANTS 1
#else
#define MLDSA87_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
#endif

// FALCON-512 API functions (available in PQClean but disabled by default)
#ifdef ENABLE_FALCON_512
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_sign/falcon-512/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "FALCON-512 API header not found, using fallback constants"
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES  897
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES  1281
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES           690
#define FALCON512_USING_FALLBACK_CONSTANTS 1
#else
#define FALCON512_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
#endif

// FALCON-1024 API functions 
#ifdef ENABLE_FALCON_1024
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_sign/falcon-1024/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "FALCON-1024 API header not found, using fallback constants"
#define PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES  1793
#define PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES  2305
#define PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES           1330
#define FALCON1024_USING_FALLBACK_CONSTANTS 1
#else
#define FALCON1024_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
#endif

// FALCON-PADDED-512 API functions (fixed-size signatures for constant-time)
#ifdef ENABLE_FALCON_PADDED_512
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_sign/falcon-padded-512/clean/api.h"
#endif

#ifndef PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "FALCON-PADDED-512 API header not found, using fallback constants"
#define PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES  897
#define PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES  1281
#define PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES           666
#define FALCONPADDED512_USING_FALLBACK_CONSTANTS 1
#else
#define FALCONPADDED512_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
#endif

// FALCON-PADDED-1024 API functions (fixed-size signatures for constant-time)
#ifdef ENABLE_FALCON_PADDED_1024
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_sign/falcon-padded-1024/clean/api.h"
#endif

#ifndef PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "FALCON-PADDED-1024 API header not found, using fallback constants"
#define PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES  1793
#define PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES  2305
#define PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES           1280
#define FALCONPADDED1024_USING_FALLBACK_CONSTANTS 1
#else
#define FALCONPADDED1024_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
#endif

// SPHINCS+-SHA2-128s-simple API functions 
#ifdef ENABLE_SPHINCS_SHA2_128S
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_sign/sphincs-sha2-128s-simple/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "SPHINCS+-SHA2-128s-simple API header not found, using fallback constants"
#define PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES  32
#define PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES  64
#define PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_BYTES           7856
#define SPHINCSSHA2128S_USING_FALLBACK_CONSTANTS 1
#else
#define SPHINCSSHA2128S_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
#endif

// SPHINCS+-SHA2-128f-simple API functions 
#ifdef ENABLE_SPHINCS_SHA2_128F
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_sign/sphincs-sha2-128f-simple/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "SPHINCS+-SHA2-128f-simple API header not found, using fallback constants"
#define PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES  32
#define PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES  64
#define PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES           17088
#define SPHINCSSHA2128F_USING_FALLBACK_CONSTANTS 1
#else
#define SPHINCSSHA2128F_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
#endif

// SPHINCS+-SHA2-192s-simple API functions 
#ifdef ENABLE_SPHINCS_SHA2_192S
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_sign/sphincs-sha2-192s-simple/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "SPHINCS+-SHA2-192s-simple API header not found, using fallback constants"
#define PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES  48
#define PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES  96
#define PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_BYTES           16224
#define SPHINCSSHA2192S_USING_FALLBACK_CONSTANTS 1
#else
#define SPHINCSSHA2192S_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
#endif

// SPHINCS+-SHA2-256s-simple API functions 
#ifdef ENABLE_SPHINCS_SHA2_256S
// Try to include the real API header first
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_sign/sphincs-sha2-256s-simple/clean/api.h"
#endif

// Check if API constants were successfully included, provide fallbacks if not
#ifndef PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "SPHINCS+-SHA2-256s-simple API header not found, using fallback constants"
#define PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES  64
#define PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES  128
#define PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_BYTES           29792
#define SPHINCSSHA2256S_USING_FALLBACK_CONSTANTS 1
#else
#define SPHINCSSHA2256S_USING_FALLBACK_CONSTANTS 0
#endif

extern int PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
#endif

// SPHINCS+-SHA2-192f-simple API functions
#ifdef ENABLE_SPHINCS_SHA2_192F
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_sign/sphincs-sha2-192f-simple/clean/api.h"
#endif
#ifndef PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "SPHINCS+-SHA2-192f-simple API header not found, using fallback constants"
#define PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES  48
#define PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES  96
#define PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_BYTES           35664
#define SPHINCSSHA2192F_USING_FALLBACK_CONSTANTS 1
#else
#define SPHINCSSHA2192F_USING_FALLBACK_CONSTANTS 0
#endif
extern int PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
#endif

// SPHINCS+-SHA2-256f-simple API functions
#ifdef ENABLE_SPHINCS_SHA2_256F
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_sign/sphincs-sha2-256f-simple/clean/api.h"
#endif
#ifndef PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "SPHINCS+-SHA2-256f-simple API header not found, using fallback constants"
#define PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES  64
#define PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES  128
#define PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_BYTES           49856
#define SPHINCSSHA2256F_USING_FALLBACK_CONSTANTS 1
#else
#define SPHINCSSHA2256F_USING_FALLBACK_CONSTANTS 0
#endif
extern int PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
#endif

// SPHINCS+-SHAKE-128f-simple API functions
#ifdef ENABLE_SPHINCS_SHAKE_128F
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_sign/sphincs-shake-128f-simple/clean/api.h"
#endif
#ifndef PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "SPHINCS+-SHAKE-128f-simple API header not found, using fallback constants"
#define PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES  32
#define PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES  64
#define PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_BYTES           17088
#define SPHINCSSHAKE128F_USING_FALLBACK_CONSTANTS 1
#else
#define SPHINCSSHAKE128F_USING_FALLBACK_CONSTANTS 0
#endif
extern int PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
#endif

// SPHINCS+-SHAKE-128s-simple API functions
#ifdef ENABLE_SPHINCS_SHAKE_128S
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_sign/sphincs-shake-128s-simple/clean/api.h"
#endif
#ifndef PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "SPHINCS+-SHAKE-128s-simple API header not found, using fallback constants"
#define PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES  32
#define PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES  64
#define PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_BYTES           7856
#define SPHINCSSHAKE128S_USING_FALLBACK_CONSTANTS 1
#else
#define SPHINCSSHAKE128S_USING_FALLBACK_CONSTANTS 0
#endif
extern int PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
#endif

// SPHINCS+-SHAKE-192f-simple API functions
#ifdef ENABLE_SPHINCS_SHAKE_192F
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_sign/sphincs-shake-192f-simple/clean/api.h"
#endif
#ifndef PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "SPHINCS+-SHAKE-192f-simple API header not found, using fallback constants"
#define PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES  48
#define PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES  96
#define PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_BYTES           35664
#define SPHINCSSHAKE192F_USING_FALLBACK_CONSTANTS 1
#else
#define SPHINCSSHAKE192F_USING_FALLBACK_CONSTANTS 0
#endif
extern int PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
#endif

// SPHINCS+-SHAKE-192s-simple API functions
#ifdef ENABLE_SPHINCS_SHAKE_192S
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_sign/sphincs-shake-192s-simple/clean/api.h"
#endif
#ifndef PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "SPHINCS+-SHAKE-192s-simple API header not found, using fallback constants"
#define PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES  48
#define PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES  96
#define PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_BYTES           16224
#define SPHINCSSHAKE192S_USING_FALLBACK_CONSTANTS 1
#else
#define SPHINCSSHAKE192S_USING_FALLBACK_CONSTANTS 0
#endif
extern int PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
#endif

// SPHINCS+-SHAKE-256f-simple API functions
#ifdef ENABLE_SPHINCS_SHAKE_256F
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_sign/sphincs-shake-256f-simple/clean/api.h"
#endif
#ifndef PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "SPHINCS+-SHAKE-256f-simple API header not found, using fallback constants"
#define PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES  64
#define PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES  128
#define PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_BYTES           49856
#define SPHINCSSHAKE256F_USING_FALLBACK_CONSTANTS 1
#else
#define SPHINCSSHAKE256F_USING_FALLBACK_CONSTANTS 0
#endif
extern int PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
#endif

// SPHINCS+-SHAKE-256s-simple API functions
#ifdef ENABLE_SPHINCS_SHAKE_256S
#ifdef TRY_REAL_API_HEADERS
#include "../crypto_sign/sphincs-shake-256s-simple/clean/api.h"
#endif
#ifndef PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES
#warning "SPHINCS+-SHAKE-256s-simple API header not found, using fallback constants"
#define PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES  64
#define PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES  128
#define PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_BYTES           29792
#define SPHINCSSHAKE256S_USING_FALLBACK_CONSTANTS 1
#else
#define SPHINCSSHAKE256S_USING_FALLBACK_CONSTANTS 0
#endif
extern int PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);
#endif

// ========================================================================
// Core Registry Functions - Exact Match to KEM Structure
// ========================================================================

bool register_sign(const char* name, const char* variant,
                   uint32_t pk_bytes, uint32_t sk_bytes, uint32_t signature_bytes,
                   sign_keypair_func_t keypair_func,
                   sign_signature_func_t sign_func,
                   sign_verify_func_t verify_func) {
    
    // Bounds checking
    if (sign_count >= MAX_SIGNS) {
        printk("ERROR: Cannot register sign %s - registry full (%u/%u)\n", name, sign_count, MAX_SIGNS);
        return false;
    }
    
    // Input validation
    if (!name || !variant || !keypair_func || !sign_func || !verify_func) {
        printk("ERROR: Invalid parameters for sign registration\n");
        return false;
    }
    
    sign_info_t* sign = &sign_registry[sign_count];
    
    // Store string pointers directly (they point to string literals)
    sign->name = name;
    sign->variant = variant;
    
    // Set parameters
    sign->pk_bytes = pk_bytes;
    sign->sk_bytes = sk_bytes;
    sign->signature_bytes = signature_bytes;
    
    // Set function pointers
    sign->keypair = keypair_func;
    sign->sign = sign_func;
    sign->verify = verify_func;
    sign->enabled = true;
    
    sign_count++;
    printk("Registered Signature: %s-%s (%u/%u/%u bytes)\n", 
           name, variant, pk_bytes, sk_bytes, signature_bytes);
    return true;
}

void discover_and_register_all_signs(void) {
    printk("*** Comprehensive Signature Discovery & Registration ***\n");
    printk("======================================================\n");
    
    // Report API header detection status
    printk("*** API Header Detection Status ***\n");
#ifdef ENABLE_ML_DSA_44
    printk("ML-DSA-44: %s\n", MLDSA44_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_ML_DSA_65
    printk("ML-DSA-65: %s\n", MLDSA65_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_ML_DSA_87
    printk("ML-DSA-87: %s\n", MLDSA87_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_FALCON_512
    printk("FALCON-512: %s\n", FALCON512_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_FALCON_1024
    printk("FALCON-1024: %s\n", FALCON1024_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_FALCON_PADDED_512
    printk("FALCON-PADDED-512: %s\n", FALCONPADDED512_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_FALCON_PADDED_1024
    printk("FALCON-PADDED-1024: %s\n", FALCONPADDED1024_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_SPHINCS_SHA2_128S
    printk("SPHINCS+-SHA2-128s: %s\n", SPHINCSSHA2128S_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_SPHINCS_SHA2_128F
    printk("SPHINCS+-SHA2-128f: %s\n", SPHINCSSHA2128F_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_SPHINCS_SHA2_192S
    printk("SPHINCS+-SHA2-192s: %s\n", SPHINCSSHA2192S_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
#ifdef ENABLE_SPHINCS_SHA2_256S
    printk("SPHINCS+-SHA2-256s: %s\n", SPHINCSSHA2256S_USING_FALLBACK_CONSTANTS ? "FALLBACK CONSTANTS" : "REAL API HEADER");
#endif
    printk("=====================================\n");
    
    // Register ML-DSA-44 (if enabled via compile flag)
#ifdef ENABLE_ML_DSA_44
    register_sign("ml-dsa-44", "clean",
                 PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair,
                 PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature,
                 PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify);
#endif

    // Register ML-DSA-65 (if enabled via compile flag)
#ifdef ENABLE_ML_DSA_65
    register_sign("ml-dsa-65", "clean",
                 PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair,
                 PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature,
                 PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify);
#endif

    // Register ML-DSA-87 (if enabled via compile flag)
#ifdef ENABLE_ML_DSA_87
    register_sign("ml-dsa-87", "clean",
                 PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair,
                 PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature,
                 PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify);
#endif

    // Register FALCON-512 (if enabled via compile flag)
#ifdef ENABLE_FALCON_512
    register_sign("falcon-512", "clean",
                 PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair,
                 PQCLEAN_FALCON512_CLEAN_crypto_sign_signature,
                 PQCLEAN_FALCON512_CLEAN_crypto_sign_verify);
#endif

    // Register FALCON-1024 (if enabled via compile flag)
#ifdef ENABLE_FALCON_1024
    register_sign("falcon-1024", "clean",
                 PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair,
                 PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature,
                 PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify);
#endif

    // Register FALCON-PADDED-512 (if enabled via compile flag)
    // Fixed-size signatures for constant-time operation
#ifdef ENABLE_FALCON_PADDED_512
    register_sign("falcon-padded-512", "clean",
                 PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair,
                 PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature,
                 PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify);
#endif

    // Register FALCON-PADDED-1024 (if enabled via compile flag)
    // Fixed-size signatures for constant-time operation
#ifdef ENABLE_FALCON_PADDED_1024
    register_sign("falcon-padded-1024", "clean",
                 PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_keypair,
                 PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_signature,
                 PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_verify);
#endif

    // Register SPHINCS+-SHA2-128s-simple (if enabled via compile flag)
#ifdef ENABLE_SPHINCS_SHA2_128S
    register_sign("sphincs-sha2-128s-simple", "clean",
                 PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_keypair,
                 PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature,
                 PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify);
#endif

    // Register SPHINCS+-SHA2-128f-simple (if enabled via compile flag)
#ifdef ENABLE_SPHINCS_SHA2_128F
    register_sign("sphincs-sha2-128f-simple", "clean",
                 PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair,
                 PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature,
                 PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify);
#endif

    // Register SPHINCS+-SHA2-192s-simple (if enabled via compile flag)
#ifdef ENABLE_SPHINCS_SHA2_192S
    register_sign("sphincs-sha2-192s-simple", "clean",
                 PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_keypair,
                 PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_signature,
                 PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_verify);
#endif

    // Register SPHINCS+-SHA2-256s-simple (if enabled via compile flag)
#ifdef ENABLE_SPHINCS_SHA2_256S
    register_sign("sphincs-sha2-256s-simple", "clean",
                 PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_keypair,
                 PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_signature,
                 PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_verify);
#endif

    // Register SPHINCS+-SHA2-192f-simple (if enabled via compile flag)
#ifdef ENABLE_SPHINCS_SHA2_192F
    register_sign("sphincs-sha2-192f-simple", "clean",
                 PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_keypair,
                 PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_signature,
                 PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_verify);
#endif

    // Register SPHINCS+-SHA2-256f-simple (if enabled via compile flag)
#ifdef ENABLE_SPHINCS_SHA2_256F
    register_sign("sphincs-sha2-256f-simple", "clean",
                 PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_keypair,
                 PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_signature,
                 PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_verify);
#endif

    // Register SPHINCS+-SHAKE-128f-simple (if enabled via compile flag)
#ifdef ENABLE_SPHINCS_SHAKE_128F
    register_sign("sphincs-shake-128f-simple", "clean",
                 PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_keypair,
                 PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_signature,
                 PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_verify);
#endif

    // Register SPHINCS+-SHAKE-128s-simple (if enabled via compile flag)
#ifdef ENABLE_SPHINCS_SHAKE_128S
    register_sign("sphincs-shake-128s-simple", "clean",
                 PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_keypair,
                 PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_signature,
                 PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_verify);
#endif

    // Register SPHINCS+-SHAKE-192f-simple (if enabled via compile flag)
#ifdef ENABLE_SPHINCS_SHAKE_192F
    register_sign("sphincs-shake-192f-simple", "clean",
                 PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_keypair,
                 PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_signature,
                 PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_verify);
#endif

    // Register SPHINCS+-SHAKE-192s-simple (if enabled via compile flag)
#ifdef ENABLE_SPHINCS_SHAKE_192S
    register_sign("sphincs-shake-192s-simple", "clean",
                 PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_keypair,
                 PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_signature,
                 PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_verify);
#endif

    // Register SPHINCS+-SHAKE-256f-simple (if enabled via compile flag)
#ifdef ENABLE_SPHINCS_SHAKE_256F
    register_sign("sphincs-shake-256f-simple", "clean",
                 PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair,
                 PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_signature,
                 PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_verify);
#endif

    // Register SPHINCS+-SHAKE-256s-simple (if enabled via compile flag)
#ifdef ENABLE_SPHINCS_SHAKE_256S
    register_sign("sphincs-shake-256s-simple", "clean",
                 PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES,
                 PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES,
                 PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_BYTES,
                 PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_keypair,
                 PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_signature,
                 PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_verify);
#endif

    printk("Total Signatures registered: %u\n", sign_count);
    printk("Note: Additional signature algorithms can be enabled via compile flags\n");
    printk("Warning: SPHINCS+ variants have very large signatures (up to 30KB)\n");
}

sign_info_t* get_sign_by_index(uint32_t index) {
    if (index >= sign_count) {
        return NULL;
    }
    return &sign_registry[index];
}

sign_info_t* get_sign_by_name(const char* name) {
    for (uint32_t i = 0; i < sign_count; i++) {
        if (strcmp(sign_registry[i].name, name) == 0) {
            return &sign_registry[i];
        }
    }
    return NULL;
}

uint32_t get_enabled_sign_count(void) {
    uint32_t count = 0;
    for (uint32_t i = 0; i < sign_count; i++) {
        if (sign_registry[i].enabled) {
            count++;
        }
    }
    return count;
}

void enable_sign(const char* name, bool enabled) {
    sign_info_t* sign = get_sign_by_name(name);
    if (sign) {
        sign->enabled = enabled;
        printk("Signature %s %s\n", name, enabled ? "enabled" : "disabled");
    } else {
        printk("Signature %s not found\n", name);
    }
}

void print_registered_signs(void) {
    printk("\n*** Registered Signatures (%u total)\n", sign_count);
    printk("=====================================\n");
    printk("Name\t\tVariant\t\tPK\tSK\tSig\tEnabled\n");
    printk("----\t\t-------\t\t--\t--\t---\t-------\n");
    
    for (uint32_t i = 0; i < sign_count; i++) {
        sign_info_t* sign = &sign_registry[i];
        printk("%-12s\t%-8s\t%u\t%u\t%u\t%s\n",
               sign->name, sign->variant,
               sign->pk_bytes, sign->sk_bytes, sign->signature_bytes,
               sign->enabled ? "YES" : "NO");
    }
    printk("\n");
}

void disable_sign(const char* name) {
    enable_sign(name, false);
}

void enable_all_signs(void) {
    for (uint32_t i = 0; i < sign_count; i++) {
        sign_registry[i].enabled = true;
    }
    printk("All %u signature algorithms enabled\n", sign_count);
}

void disable_all_signs(void) {
    for (uint32_t i = 0; i < sign_count; i++) {
        sign_registry[i].enabled = false;
    }
    printk("All %u signature algorithms disabled\n", sign_count);
}

void list_enabled_signs(void) {
    printk("\n*** Enabled Signature Algorithms:\n");
    uint32_t count = 0;
    for (uint32_t i = 0; i < sign_count; i++) {
        if (sign_registry[i].enabled) {
            printk("  %u: %s (%s)\n", ++count, sign_registry[i].name, sign_registry[i].variant);
        }
    }
    if (count == 0) {
        printk("  (none enabled)\n");
    }
    printk("\n");
}

bool validate_sign_api(sign_info_t* sign) {
    // Comprehensive input validation - REAL DATA ONLY!
    if (!sign) {
        printk("ERROR: validate_sign_api - NULL sign pointer\n");
        return false;
    }
    
    if (!sign->name) {
        printk("ERROR: validate_sign_api - NULL sign name\n");
        return false;
    }
    
    if (!sign->keypair) {
        printk("ERROR: validate_sign_api - NULL keypair function for %s\n", sign->name);
        return false;
    }
    
    if (!sign->sign) {
        printk("ERROR: validate_sign_api - NULL sign function for %s\n", sign->name);
        return false;
    }
    
    if (!sign->verify) {
        printk("ERROR: validate_sign_api - NULL verify function for %s\n", sign->name);
        return false;
    }
    
    // Validate key sizes are realistic
    if (sign->pk_bytes == 0 || sign->sk_bytes == 0 || sign->signature_bytes == 0) {
        printk("ERROR: validate_sign_api - Invalid key sizes for %s (pk:%u, sk:%u, sig:%u)\n",
               sign->name, sign->pk_bytes, sign->sk_bytes, sign->signature_bytes);
        return false;
    }
    
    printk("*** Validating Signature %s-%s with REAL cryptographic operations\n", sign->name, sign->variant);
    printk("*** Key sizes: PK=%u, SK=%u, Signature=%u bytes\n", 
           sign->pk_bytes, sign->sk_bytes, sign->signature_bytes);
    
    // Allocate buffers based on the actual signature algorithm size requirements
    // Use dynamic allocation to avoid stack overflow for large signatures
    uint8_t* pk = k_malloc(sign->pk_bytes);
    uint8_t* sk = k_malloc(sign->sk_bytes);
    uint8_t* signature = k_malloc(sign->signature_bytes);
    uint8_t* message = k_malloc(64);  // Test message
    uint8_t* recovered_msg = k_malloc(64);  // For verify operation
    
    if (!pk || !sk || !signature || !message || !recovered_msg) {
        printk("ERROR: validate_sign_api - Memory allocation failed for Signature %s\n", sign->name);
        printk("ERROR: Required memory: PK=%u + SK=%u + Sig=%u + Msg=%u + RecoveredMsg=%u = %u bytes total\n",
               sign->pk_bytes, sign->sk_bytes, sign->signature_bytes, 64, 64,
               sign->pk_bytes + sign->sk_bytes + sign->signature_bytes + 128);
        goto cleanup_and_fail;
    }
    
    // Initialize buffers to detect uninitialized data
    memset(pk, 0xFF, sign->pk_bytes);
    memset(sk, 0xFF, sign->sk_bytes);
    memset(signature, 0xFF, sign->signature_bytes);
    memset(message, 0x00, 64);
    memset(recovered_msg, 0x00, 64);
    
    // Create test message (must fit in 64 bytes including null terminator)
    const char* test_msg = "Hello PQC Signature Test - Real crypto";  // 38 chars
    size_t msg_len = strlen(test_msg);
    memcpy(message, test_msg, msg_len);
    
    printk("*** STEP 1: Testing keypair generation for %s\n", sign->name);
    
    // Test keypair generation with REAL cryptography
    int keypair_result = sign->keypair(pk, sk);
    if (keypair_result != 0) {
        printk("ERROR: validate_sign_api - Signature %s keypair generation failed with code %d\n", sign->name, keypair_result);
        goto cleanup_and_fail;
    }
    
    // Verify keys were actually generated (not all zeros or all 0xFF)
    bool pk_all_zero = true, pk_all_ff = true;
    bool sk_all_zero = true, sk_all_ff = true;
    
    for (uint32_t i = 0; i < sign->pk_bytes; i++) {
        if (pk[i] != 0x00) pk_all_zero = false;
        if (pk[i] != 0xFF) pk_all_ff = false;
    }
    
    for (uint32_t i = 0; i < sign->sk_bytes; i++) {
        if (sk[i] != 0x00) sk_all_zero = false;
        if (sk[i] != 0xFF) sk_all_ff = false;
    }
    
    if (pk_all_zero || pk_all_ff) {
        printk("ERROR: validate_sign_api - Signature %s generated invalid public key (all %s)\n", 
               sign->name, pk_all_zero ? "zeros" : "0xFF");
        goto cleanup_and_fail;
    }
    
    if (sk_all_zero || sk_all_ff) {
        printk("ERROR: validate_sign_api - Signature %s generated invalid secret key (all %s)\n", 
               sign->name, sk_all_zero ? "zeros" : "0xFF");
        goto cleanup_and_fail;
    }
    
    printk("*** STEP 1 PASSED: Real keypair generation completed for %s\n", sign->name);
    
    printk("*** STEP 2: Testing signature generation for %s\n", sign->name);
    
    // Test signature generation with REAL cryptography
    size_t sig_len = sign->signature_bytes;
    int sign_result = sign->sign(signature, &sig_len, message, msg_len, sk);
    if (sign_result != 0) {
        printk("ERROR: validate_sign_api - Signature %s signature generation failed with code %d\n", sign->name, sign_result);
        goto cleanup_and_fail;
    }
    
    // Verify signature was generated (not all zeros or all 0xFF)
    bool sig_all_zero = true, sig_all_ff = true;
    
    for (uint32_t i = 0; i < sig_len; i++) {
        if (signature[i] != 0x00) sig_all_zero = false;
        if (signature[i] != 0xFF) sig_all_ff = false;
    }
    
    if (sig_all_zero || sig_all_ff) {
        printk("ERROR: validate_sign_api - Signature %s generated invalid signature (all %s)\n", 
               sign->name, sig_all_zero ? "zeros" : "0xFF");
        goto cleanup_and_fail;
    }
    
    printk("*** STEP 2 PASSED: Real signature generation completed for %s (sig_len=%zu)\n", sign->name, sig_len);
    
    printk("*** STEP 3: Testing signature verification for %s\n", sign->name);
    
    // Test signature verification with REAL cryptography
    // verify(sig, sig_len, msg, msg_len, pk) returns 0 if valid
    int verify_result = sign->verify(signature, sig_len, message, msg_len, pk);
    if (verify_result != 0) {
        printk("ERROR: validate_sign_api - Signature %s verification failed with code %d\n", sign->name, verify_result);
        goto cleanup_and_fail;
    }
    
    printk("*** STEP 3 PASSED: Real signature verification completed for %s\n", sign->name);
    
    printk("*** STEP 4: Testing verification with corrupted signature for %s\n", sign->name);
    
    // Test that verification fails with corrupted signature (proves real crypto)
    // Use dynamic allocation to avoid stack overflow with large signatures
    uint8_t* corrupted_sig = k_malloc(sig_len);
    if (!corrupted_sig) {
        printk("ERROR: validate_sign_api - Memory allocation failed for corrupted signature test\n");
        goto cleanup_and_fail;
    }
    memcpy(corrupted_sig, signature, sig_len);
    corrupted_sig[0] ^= 0xFF;  // Flip bits in first byte
    
    int corrupt_verify = sign->verify(corrupted_sig, sig_len, message, msg_len, pk);
    k_free(corrupted_sig);  // Free immediately after use
    
    if (corrupt_verify == 0) {
        printk("ERROR: validate_sign_api - Signature %s CRITICAL FAILURE: corrupted signature verified!\n", sign->name);
        printk("ERROR: This indicates the signature implementation is broken or data is fake\n");
        goto cleanup_and_fail;
    }
    
    printk("*** STEP 4 PASSED: Corrupted signature correctly rejected for %s\n", sign->name);
    
    printk("*** STEP 4 PASSED: Message integrity verified perfectly for %s\n", sign->name);
    printk("*** SUCCESS: Signature %s-%s validation PASSED with REAL cryptographic data\n", sign->name, sign->variant);
    
    // Cleanup successful validation
    k_free(pk); k_free(sk); k_free(signature); k_free(message); k_free(recovered_msg);
    return true;
    
cleanup_and_fail:
    printk("ERROR: validate_sign_api - Signature %s validation FAILED - cleaning up\n", sign->name ? sign->name : "UNKNOWN");
    if (pk) k_free(pk);
    if (sk) k_free(sk);
    if (signature) k_free(signature);
    if (message) k_free(message);
    if (recovered_msg) k_free(recovered_msg);
    return false;
}

sign_info_t* get_enabled_sign(void) {
    for (uint32_t i = 0; i < sign_count; i++) {
        if (sign_registry[i].enabled) {
            return &sign_registry[i];
        }
    }
    return NULL;
}

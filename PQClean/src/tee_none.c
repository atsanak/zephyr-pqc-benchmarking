/**
 * @file tee_none.c
 * @brief TEE_MODE_NONE Implementation (Baseline/No-TEE)
 * 
 * This file implements the baseline "no TEE" mode, where all operations
 * execute directly in normal world without any secure world transitions.
 * 
 * This serves as:
 * 1. The baseline measurement for TEE overhead comparisons
 * 2. The fallback when no TEE is available on the platform
 * 3. The default mode for existing QEMU-based benchmarks
 * 
 * @version 1.0.0
 * @date 2025-11-27
 */

#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/printk.h>
#include <string.h>
#include <errno.h>
#include "tee_abstraction.h"

// Forward declarations of PQClean KEM API functions
// These are defined in the specific KEM implementation being benchmarked
extern int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// Forward declarations of PQClean DSA API functions
// These are defined in the specific DSA implementation being benchmarked
extern int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int crypto_sign_signature(uint8_t *sig, size_t *siglen, 
                                  const uint8_t *m, size_t mlen, 
                                  const uint8_t *sk);
extern int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                               const uint8_t *m, size_t mlen,
                               const uint8_t *pk);

// ========================================================================
// BASELINE IMPLEMENTATION (NO TEE)
// ========================================================================

/**
 * @brief Initialize baseline (no-TEE) context
 * 
 * No actual initialization needed for baseline mode.
 * Just validates that mode is set correctly.
 */
int tee_none_init(tee_context_t *ctx) {
    if (!ctx) {
        return -EINVAL;
    }
    
    if (ctx->mode != TEE_MODE_NONE) {
        printk("ERROR: tee_none_init called with mode=%d (expected TEE_MODE_NONE)\n", 
               ctx->mode);
        return -EINVAL;
    }
    
    ctx->provider = TEE_PROVIDER_NONE;
    ctx->private_data = NULL;
    
    printk("TEE baseline mode initialized (no secure world)\n");
    return 0;
}

/**
 * @brief Deinitialize baseline (no-TEE) context
 * 
 * No cleanup needed for baseline mode.
 */
int tee_none_deinit(tee_context_t *ctx) {
    if (!ctx) {
        return -EINVAL;
    }
    
    // Nothing to clean up
    return 0;
}

/**
 * @brief Baseline keygen (direct PQClean call)
 * 
 * Executes crypto_kem_keypair() directly without TEE boundary.
 * Overhead metrics report zero (no TEE overhead).
 */
int tee_none_kem_keygen(tee_context_t *ctx, 
                        uint8_t *pk, uint8_t *sk,
                        uint32_t pk_len, uint32_t sk_len,
                        tee_overhead_t *overhead) {
    if (!ctx || !pk || !sk) {
        return -EINVAL;
    }
    
    // Clear overhead metrics (no TEE overhead for baseline)
    if (overhead) {
        memset(overhead, 0, sizeof(*overhead));
    }
    
    // Direct call to PQClean KEM API (defined in api.h)
    int ret = crypto_kem_keypair(pk, sk);
    
    if (ret != 0) {
        printk("ERROR: crypto_kem_keypair() failed: %d\n", ret);
        return -EIO;
    }
    
    return 0;
}

/**
 * @brief Baseline encaps (direct PQClean call)
 * 
 * Executes crypto_kem_enc() directly without TEE boundary.
 */
int tee_none_kem_encaps(tee_context_t *ctx,
                        uint8_t *ct, uint8_t *ss,
                        const uint8_t *pk,
                        uint32_t ct_len, uint32_t ss_len, uint32_t pk_len,
                        tee_overhead_t *overhead) {
    if (!ctx || !ct || !ss || !pk) {
        return -EINVAL;
    }
    
    // Clear overhead metrics
    if (overhead) {
        memset(overhead, 0, sizeof(*overhead));
    }
    
    // Direct call to PQClean KEM API
    int ret = crypto_kem_enc(ct, ss, pk);
    
    if (ret != 0) {
        printk("ERROR: crypto_kem_enc() failed: %d\n", ret);
        return -EIO;
    }
    
    return 0;
}

/**
 * @brief Baseline decaps (direct PQClean call)
 * 
 * Executes crypto_kem_dec() directly without TEE boundary.
 */
int tee_none_kem_decaps(tee_context_t *ctx,
                        uint8_t *ss, const uint8_t *sk, const uint8_t *ct,
                        uint32_t ss_len, uint32_t sk_len, uint32_t ct_len,
                        tee_overhead_t *overhead) {
    if (!ctx || !ss || !sk || !ct) {
        return -EINVAL;
    }
    
    // Clear overhead metrics
    if (overhead) {
        memset(overhead, 0, sizeof(*overhead));
    }
    
    // Direct call to PQClean KEM API
    int ret = crypto_kem_dec(ss, ct, sk);
    
    if (ret != 0) {
        printk("ERROR: crypto_kem_dec() failed: %d\n", ret);
        return -EIO;
    }
    
    return 0;
}

/**
 * @brief Baseline RNG (direct sys_csrand_get call)
 * 
 * Uses Zephyr's standard entropy API without TEE routing.
 */
int tee_none_rng_get_bytes(tee_context_t *ctx, uint8_t *buf, size_t len) {
    if (!ctx || !buf || len == 0) {
        return -EINVAL;
    }
    
    // Use Zephyr's sys_csrand_get (same as current PQClean randombytes())
    int ret = sys_csrand_get(buf, len);
    
    if (ret != 0) {
        printk("ERROR: sys_csrand_get() failed: %d\n", ret);
        return -EIO;
    }
    
    return 0;
}

// ========================================================================
// BASELINE DSA IMPLEMENTATION (NO TEE) - FIPS 204/205/206
// ========================================================================

/**
 * @brief Baseline DSA keygen (direct PQClean call)
 * 
 * Executes crypto_sign_keypair() directly without TEE boundary.
 * Supports ML-DSA, SPHINCS+, Falcon algorithms.
 */
int tee_none_dsa_keygen(tee_context_t *ctx,
                        uint8_t *pk, uint8_t *sk,
                        uint32_t pk_len, uint32_t sk_len,
                        tee_overhead_t *overhead) {
    if (!ctx || !pk || !sk) {
        return -EINVAL;
    }
    
    // Clear overhead metrics (no TEE overhead for baseline)
    if (overhead) {
        memset(overhead, 0, sizeof(*overhead));
    }
    
    // Direct call to PQClean DSA API
    int ret = crypto_sign_keypair(pk, sk);
    
    if (ret != 0) {
        printk("ERROR: crypto_sign_keypair() failed: %d\n", ret);
        return -EIO;
    }
    
    return 0;
}

/**
 * @brief Baseline DSA sign (direct PQClean call)
 * 
 * Executes crypto_sign_signature() directly without TEE boundary.
 */
int tee_none_dsa_sign(tee_context_t *ctx,
                      uint8_t *sig, size_t *siglen,
                      const uint8_t *msg, size_t msglen,
                      const uint8_t *sk, uint32_t sk_len,
                      uint32_t sig_max_len,
                      tee_overhead_t *overhead) {
    if (!ctx || !sig || !siglen || !msg || !sk) {
        return -EINVAL;
    }
    
    // Clear overhead metrics
    if (overhead) {
        memset(overhead, 0, sizeof(*overhead));
    }
    
    // Direct call to PQClean DSA API
    int ret = crypto_sign_signature(sig, siglen, msg, msglen, sk);
    
    if (ret != 0) {
        printk("ERROR: crypto_sign_signature() failed: %d\n", ret);
        return -EIO;
    }
    
    return 0;
}

/**
 * @brief Baseline DSA verify (direct PQClean call)
 * 
 * Executes crypto_sign_verify() directly without TEE boundary.
 */
int tee_none_dsa_verify(tee_context_t *ctx,
                        const uint8_t *sig, size_t siglen,
                        const uint8_t *msg, size_t msglen,
                        const uint8_t *pk, uint32_t pk_len,
                        tee_overhead_t *overhead) {
    if (!ctx || !sig || !msg || !pk) {
        return -EINVAL;
    }
    
    // Clear overhead metrics
    if (overhead) {
        memset(overhead, 0, sizeof(*overhead));
    }
    
    // Direct call to PQClean DSA API
    // Returns 0 if signature is valid, non-zero otherwise
    int ret = crypto_sign_verify(sig, siglen, msg, msglen, pk);
    
    if (ret != 0) {
        // Note: For verify, non-zero can mean invalid signature (not necessarily error)
        return -EBADMSG;  // Signature verification failed
    }
    
    return 0;
}

// ========================================================================
// DISPATCHER INTEGRATION
// ========================================================================

/**
 * @brief Check if baseline (no-TEE) mode is available
 * 
 * Baseline mode is always available (no dependencies).
 */
bool tee_none_is_available(void) {
    return true;  // Always available
}

/**
 * @brief Get baseline mode description
 */
const char* tee_none_get_description(void) {
    return "Baseline (no TEE, normal world only)";
}

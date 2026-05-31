/**
 * @file tee_abstraction.c
 * @brief TEE Abstraction Layer Dispatcher
 * 
 * This file implements the central dispatcher that routes TEE operations
 * to the appropriate backend implementation based on the TEE context mode.
 * 
 * Routing Logic:
 * - TEE_MODE_NONE → tee_none.c (baseline)
 * - TEE_MODE_TFM_RNG_ONLY → tee_tfm_rng.c (Phase 1)
 * - TEE_MODE_TFM_FULL_KEM → tee_tfm_full.c (Phase 2)
 * - TEE_MODE_KEYSTONE → tee_keystone.c (Phase 3, optional)
 * - TEE_MODE_SGX → tee_sgx.c (Phase 4, optional)
 * - TEE_MODE_TDX → tee_tdx.c (Phase 4, optional)
 * - TEE_MODE_SIMULATED → tee_simulated.c (testing)
 * 
 * @version 1.0.0
 * @date 2025-11-27
 */

#include "tee_abstraction.h"
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <string.h>
#include <errno.h>

// ========================================================================
// BACKEND FUNCTION DECLARATIONS
// ========================================================================

// Baseline (no TEE) backend - always available
extern int tee_none_init(tee_context_t *ctx);
extern int tee_none_deinit(tee_context_t *ctx);
extern int tee_none_kem_keygen(tee_context_t *ctx, uint8_t *pk, uint8_t *sk,
                                uint32_t pk_len, uint32_t sk_len,
                                tee_overhead_t *overhead);
extern int tee_none_kem_encaps(tee_context_t *ctx, uint8_t *ct, uint8_t *ss,
                                const uint8_t *pk, uint32_t ct_len,
                                uint32_t ss_len, uint32_t pk_len,
                                tee_overhead_t *overhead);
extern int tee_none_kem_decaps(tee_context_t *ctx, uint8_t *ss,
                                const uint8_t *sk, const uint8_t *ct,
                                uint32_t ss_len, uint32_t sk_len,
                                uint32_t ct_len, tee_overhead_t *overhead);
extern int tee_none_rng_get_bytes(tee_context_t *ctx, uint8_t *buf, size_t len);
extern bool tee_none_is_available(void);

// DSA operations for baseline
extern int tee_none_dsa_keygen(tee_context_t *ctx, uint8_t *pk, uint8_t *sk,
                                uint32_t pk_len, uint32_t sk_len,
                                tee_overhead_t *overhead);
extern int tee_none_dsa_sign(tee_context_t *ctx, uint8_t *sig, size_t *siglen,
                              const uint8_t *msg, size_t msglen,
                              const uint8_t *sk, uint32_t sk_len,
                              uint32_t sig_max_len, tee_overhead_t *overhead);
extern int tee_none_dsa_verify(tee_context_t *ctx, const uint8_t *sig, size_t siglen,
                                const uint8_t *msg, size_t msglen,
                                const uint8_t *pk, uint32_t pk_len,
                                tee_overhead_t *overhead);

// TF-M RNG-only backend (Phase 1) - conditionally compiled
#if CONFIG_TEE_TFM_ENABLED
extern int tee_tfm_rng_init(tee_context_t *ctx);
extern int tee_tfm_rng_deinit(tee_context_t *ctx);
extern int tee_tfm_rng_kem_keygen(tee_context_t *ctx, uint8_t *pk, uint8_t *sk,
                                   uint32_t pk_len, uint32_t sk_len,
                                   tee_overhead_t *overhead);
extern int tee_tfm_rng_kem_encaps(tee_context_t *ctx, uint8_t *ct, uint8_t *ss,
                                   const uint8_t *pk, uint32_t ct_len,
                                   uint32_t ss_len, uint32_t pk_len,
                                   tee_overhead_t *overhead);
extern int tee_tfm_rng_kem_decaps(tee_context_t *ctx, uint8_t *ss,
                                   const uint8_t *sk, const uint8_t *ct,
                                   uint32_t ss_len, uint32_t sk_len,
                                   uint32_t ct_len, tee_overhead_t *overhead);
extern int tee_tfm_rng_get_bytes(tee_context_t *ctx, uint8_t *buf, size_t len);
extern bool tee_tfm_rng_is_available(void);

// DSA operations for TF-M RNG mode
extern int tee_tfm_rng_dsa_keygen(tee_context_t *ctx, uint8_t *pk, uint8_t *sk,
                                   uint32_t pk_len, uint32_t sk_len,
                                   tee_overhead_t *overhead);
extern int tee_tfm_rng_dsa_sign(tee_context_t *ctx, uint8_t *sig, size_t *siglen,
                                 const uint8_t *msg, size_t msglen,
                                 const uint8_t *sk, uint32_t sk_len,
                                 uint32_t sig_max_len, tee_overhead_t *overhead);
extern int tee_tfm_rng_dsa_verify(tee_context_t *ctx, const uint8_t *sig, size_t siglen,
                                   const uint8_t *msg, size_t msglen,
                                   const uint8_t *pk, uint32_t pk_len,
                                   tee_overhead_t *overhead);
#endif

// TF-M full KEM backend (Phase 2) - conditionally compiled
#if CONFIG_TEE_TFM_ENABLED
extern int tee_tfm_full_init(tee_context_t *ctx);
extern int tee_tfm_full_deinit(tee_context_t *ctx);
extern int tee_tfm_full_kem_keygen(tee_context_t *ctx, uint8_t *pk, uint8_t *sk,
                                    uint32_t pk_len, uint32_t sk_len,
                                    tee_overhead_t *overhead);
extern int tee_tfm_full_kem_encaps(tee_context_t *ctx, uint8_t *ct, uint8_t *ss,
                                    const uint8_t *pk, uint32_t ct_len,
                                    uint32_t ss_len, uint32_t pk_len,
                                    tee_overhead_t *overhead);
extern int tee_tfm_full_kem_decaps(tee_context_t *ctx, uint8_t *ss,
                                    const uint8_t *sk, const uint8_t *ct,
                                    uint32_t ss_len, uint32_t sk_len,
                                    uint32_t ct_len, tee_overhead_t *overhead);
extern int tee_tfm_full_rng_get_bytes(tee_context_t *ctx, uint8_t *buf, size_t len);
extern bool tee_tfm_full_is_available(void);

// DSA operations for TF-M full mode
extern int tee_tfm_full_dsa_keygen(tee_context_t *ctx, uint8_t *pk, uint8_t *sk,
                                    uint32_t pk_len, uint32_t sk_len,
                                    tee_overhead_t *overhead);
extern int tee_tfm_full_dsa_sign(tee_context_t *ctx, uint8_t *sig, size_t *siglen,
                                  const uint8_t *msg, size_t msglen,
                                  const uint8_t *sk, uint32_t sk_len,
                                  uint32_t sig_max_len, tee_overhead_t *overhead);
extern int tee_tfm_full_dsa_verify(tee_context_t *ctx, const uint8_t *sig, size_t siglen,
                                    const uint8_t *msg, size_t msglen,
                                    const uint8_t *pk, uint32_t pk_len,
                                    tee_overhead_t *overhead);
#endif

// Simulated TEE backend (testing) - conditionally compiled
#if CONFIG_TEE_SIMULATED
extern int tee_simulated_init(tee_context_t *ctx);
extern int tee_simulated_deinit(tee_context_t *ctx);
extern int tee_simulated_kem_keygen(tee_context_t *ctx, uint8_t *pk, uint8_t *sk,
                                     uint32_t pk_len, uint32_t sk_len,
                                     tee_overhead_t *overhead);
extern int tee_simulated_kem_encaps(tee_context_t *ctx, uint8_t *ct, uint8_t *ss,
                                     const uint8_t *pk, uint32_t ct_len,
                                     uint32_t ss_len, uint32_t pk_len,
                                     tee_overhead_t *overhead);
extern int tee_simulated_kem_decaps(tee_context_t *ctx, uint8_t *ss,
                                     const uint8_t *sk, const uint8_t *ct,
                                     uint32_t ss_len, uint32_t sk_len,
                                     uint32_t ct_len, tee_overhead_t *overhead);
extern int tee_simulated_rng_get_bytes(tee_context_t *ctx, uint8_t *buf, size_t len);
extern bool tee_simulated_is_available(void);

// DSA operations for simulated TEE
extern int tee_simulated_dsa_keygen(tee_context_t *ctx, uint8_t *pk, uint8_t *sk,
                                     uint32_t pk_len, uint32_t sk_len,
                                     tee_overhead_t *overhead);
extern int tee_simulated_dsa_sign(tee_context_t *ctx, uint8_t *sig, size_t *siglen,
                                   const uint8_t *msg, size_t msglen,
                                   const uint8_t *sk, uint32_t sk_len,
                                   uint32_t sig_max_len, tee_overhead_t *overhead);
extern int tee_simulated_dsa_verify(tee_context_t *ctx, const uint8_t *sig, size_t siglen,
                                     const uint8_t *msg, size_t msglen,
                                     const uint8_t *pk, uint32_t pk_len,
                                     tee_overhead_t *overhead);
#endif

// ========================================================================
// PUBLIC API IMPLEMENTATION (DISPATCHER)
// ========================================================================

/**
 * @brief Initialize TEE context (dispatcher)
 */
int tee_init(tee_context_t *ctx) {
    if (!ctx) {
        return -EINVAL;
    }
    
    printk("TEE: Initializing mode=%d provider=%d\n", ctx->mode, ctx->provider);
    
    switch (ctx->mode) {
        case TEE_MODE_NONE:
            return tee_none_init(ctx);
            
#if CONFIG_TEE_TFM_ENABLED
        case TEE_MODE_TFM_RNG_ONLY:
            if (!tee_tfm_rng_is_available()) {
                printk("ERROR: TF-M RNG mode requested but not available\n");
                return -ENOTSUP;
            }
            return tee_tfm_rng_init(ctx);
            
        case TEE_MODE_TFM_FULL_KEM:
            if (!tee_tfm_full_is_available()) {
                printk("ERROR: TF-M full KEM mode requested but not available\n");
                return -ENOTSUP;
            }
            return tee_tfm_full_init(ctx);
#endif
            
#if CONFIG_TEE_SIMULATED
        case TEE_MODE_SIMULATED:
            if (!tee_simulated_is_available()) {
                printk("ERROR: Simulated TEE mode requested but not available\n");
                return -ENOTSUP;
            }
            return tee_simulated_init(ctx);
#endif
            
        default:
            printk("ERROR: Unsupported TEE mode: %d\n", ctx->mode);
            return -ENOTSUP;
    }
}

/**
 * @brief Deinitialize TEE context (dispatcher)
 */
int tee_deinit(tee_context_t *ctx) {
    if (!ctx) {
        return -EINVAL;
    }
    
    switch (ctx->mode) {
        case TEE_MODE_NONE:
            return tee_none_deinit(ctx);
            
#if CONFIG_TEE_TFM_ENABLED
        case TEE_MODE_TFM_RNG_ONLY:
            return tee_tfm_rng_deinit(ctx);
            
        case TEE_MODE_TFM_FULL_KEM:
            return tee_tfm_full_deinit(ctx);
#endif
            
#if CONFIG_TEE_SIMULATED
        case TEE_MODE_SIMULATED:
            return tee_simulated_deinit(ctx);
#endif
            
        default:
            return -ENOTSUP;
    }
}

/**
 * @brief KEM keygen dispatcher
 */
int tee_kem_keygen(tee_context_t *ctx, 
                   uint8_t *pk, uint8_t *sk,
                   uint32_t pk_len, uint32_t sk_len,
                   tee_overhead_t *overhead) {
    if (!ctx || !pk || !sk) {
        return -EINVAL;
    }
    
    switch (ctx->mode) {
        case TEE_MODE_NONE:
            return tee_none_kem_keygen(ctx, pk, sk, pk_len, sk_len, overhead);
            
#if CONFIG_TEE_TFM_ENABLED
        case TEE_MODE_TFM_RNG_ONLY:
            return tee_tfm_rng_kem_keygen(ctx, pk, sk, pk_len, sk_len, overhead);
            
        case TEE_MODE_TFM_FULL_KEM:
            return tee_tfm_full_kem_keygen(ctx, pk, sk, pk_len, sk_len, overhead);
#endif
            
#if CONFIG_TEE_SIMULATED
        case TEE_MODE_SIMULATED:
            return tee_simulated_kem_keygen(ctx, pk, sk, pk_len, sk_len, overhead);
#endif
            
        default:
            return -ENOTSUP;
    }
}

/**
 * @brief KEM encaps dispatcher
 */
int tee_kem_encaps(tee_context_t *ctx,
                   uint8_t *ct, uint8_t *ss,
                   const uint8_t *pk,
                   uint32_t ct_len, uint32_t ss_len, uint32_t pk_len,
                   tee_overhead_t *overhead) {
    if (!ctx || !ct || !ss || !pk) {
        return -EINVAL;
    }
    
    switch (ctx->mode) {
        case TEE_MODE_NONE:
            return tee_none_kem_encaps(ctx, ct, ss, pk, ct_len, ss_len, pk_len, overhead);
            
#if CONFIG_TEE_TFM_ENABLED
        case TEE_MODE_TFM_RNG_ONLY:
            return tee_tfm_rng_kem_encaps(ctx, ct, ss, pk, ct_len, ss_len, pk_len, overhead);
            
        case TEE_MODE_TFM_FULL_KEM:
            return tee_tfm_full_kem_encaps(ctx, ct, ss, pk, ct_len, ss_len, pk_len, overhead);
#endif
            
#if CONFIG_TEE_SIMULATED
        case TEE_MODE_SIMULATED:
            return tee_simulated_kem_encaps(ctx, ct, ss, pk, ct_len, ss_len, pk_len, overhead);
#endif
            
        default:
            return -ENOTSUP;
    }
}

/**
 * @brief KEM decaps dispatcher
 */
int tee_kem_decaps(tee_context_t *ctx,
                   uint8_t *ss, const uint8_t *sk, const uint8_t *ct,
                   uint32_t ss_len, uint32_t sk_len, uint32_t ct_len,
                   tee_overhead_t *overhead) {
    if (!ctx || !ss || !sk || !ct) {
        return -EINVAL;
    }
    
    switch (ctx->mode) {
        case TEE_MODE_NONE:
            return tee_none_kem_decaps(ctx, ss, sk, ct, ss_len, sk_len, ct_len, overhead);
            
#if CONFIG_TEE_TFM_ENABLED
        case TEE_MODE_TFM_RNG_ONLY:
            return tee_tfm_rng_kem_decaps(ctx, ss, sk, ct, ss_len, sk_len, ct_len, overhead);
            
        case TEE_MODE_TFM_FULL_KEM:
            return tee_tfm_full_kem_decaps(ctx, ss, sk, ct, ss_len, sk_len, ct_len, overhead);
#endif
            
#if CONFIG_TEE_SIMULATED
        case TEE_MODE_SIMULATED:
            return tee_simulated_kem_decaps(ctx, ss, sk, ct, ss_len, sk_len, ct_len, overhead);
#endif
            
        default:
            return -ENOTSUP;
    }
}

/**
 * @brief RNG dispatcher
 */
int tee_rng_get_bytes(tee_context_t *ctx, uint8_t *buf, size_t len) {
    if (!ctx || !buf || len == 0) {
        return -EINVAL;
    }
    
    switch (ctx->mode) {
        case TEE_MODE_NONE:
            return tee_none_rng_get_bytes(ctx, buf, len);
            
#if CONFIG_TEE_TFM_ENABLED
        case TEE_MODE_TFM_RNG_ONLY:
        case TEE_MODE_TFM_FULL_KEM:
            // Both TF-M modes use secure RNG
            return tee_tfm_rng_get_bytes(ctx, buf, len);
#endif
            
#if CONFIG_TEE_SIMULATED
        case TEE_MODE_SIMULATED:
            return tee_simulated_rng_get_bytes(ctx, buf, len);
#endif
            
        default:
            return -ENOTSUP;
    }
}

// ========================================================================
// DSA (DIGITAL SIGNATURE) DISPATCHER FUNCTIONS - FIPS 204/205/206
// ========================================================================

/**
 * @brief DSA keygen dispatcher
 * 
 * Routes keypair generation for ML-DSA, SPHINCS+, Falcon through TEE.
 */
int tee_dsa_keygen(tee_context_t *ctx,
                   uint8_t *pk, uint8_t *sk,
                   uint32_t pk_len, uint32_t sk_len,
                   tee_overhead_t *overhead) {
    if (!ctx || !pk || !sk) {
        return -EINVAL;
    }
    
    switch (ctx->mode) {
        case TEE_MODE_NONE:
            return tee_none_dsa_keygen(ctx, pk, sk, pk_len, sk_len, overhead);
            
#if CONFIG_TEE_TFM_ENABLED
        case TEE_MODE_TFM_RNG_ONLY:
            return tee_tfm_rng_dsa_keygen(ctx, pk, sk, pk_len, sk_len, overhead);
            
        case TEE_MODE_TFM_FULL_KEM:
            return tee_tfm_full_dsa_keygen(ctx, pk, sk, pk_len, sk_len, overhead);
#endif
            
#if CONFIG_TEE_SIMULATED
        case TEE_MODE_SIMULATED:
            return tee_simulated_dsa_keygen(ctx, pk, sk, pk_len, sk_len, overhead);
#endif
            
        default:
            return -ENOTSUP;
    }
}

/**
 * @brief DSA sign dispatcher
 * 
 * Routes signing operation for ML-DSA, SPHINCS+, Falcon through TEE.
 */
int tee_dsa_sign(tee_context_t *ctx,
                 uint8_t *sig, size_t *siglen,
                 const uint8_t *msg, size_t msglen,
                 const uint8_t *sk, uint32_t sk_len,
                 uint32_t sig_max_len,
                 tee_overhead_t *overhead) {
    if (!ctx || !sig || !siglen || !msg || !sk) {
        return -EINVAL;
    }
    
    switch (ctx->mode) {
        case TEE_MODE_NONE:
            return tee_none_dsa_sign(ctx, sig, siglen, msg, msglen, sk, sk_len, sig_max_len, overhead);
            
#if CONFIG_TEE_TFM_ENABLED
        case TEE_MODE_TFM_RNG_ONLY:
            return tee_tfm_rng_dsa_sign(ctx, sig, siglen, msg, msglen, sk, sk_len, sig_max_len, overhead);
            
        case TEE_MODE_TFM_FULL_KEM:
            return tee_tfm_full_dsa_sign(ctx, sig, siglen, msg, msglen, sk, sk_len, sig_max_len, overhead);
#endif
            
#if CONFIG_TEE_SIMULATED
        case TEE_MODE_SIMULATED:
            return tee_simulated_dsa_sign(ctx, sig, siglen, msg, msglen, sk, sk_len, sig_max_len, overhead);
#endif
            
        default:
            return -ENOTSUP;
    }
}

/**
 * @brief DSA verify dispatcher
 * 
 * Routes verification operation for ML-DSA, SPHINCS+, Falcon through TEE.
 */
int tee_dsa_verify(tee_context_t *ctx,
                   const uint8_t *sig, size_t siglen,
                   const uint8_t *msg, size_t msglen,
                   const uint8_t *pk, uint32_t pk_len,
                   tee_overhead_t *overhead) {
    if (!ctx || !sig || !msg || !pk) {
        return -EINVAL;
    }
    
    switch (ctx->mode) {
        case TEE_MODE_NONE:
            return tee_none_dsa_verify(ctx, sig, siglen, msg, msglen, pk, pk_len, overhead);
            
#if CONFIG_TEE_TFM_ENABLED
        case TEE_MODE_TFM_RNG_ONLY:
            return tee_tfm_rng_dsa_verify(ctx, sig, siglen, msg, msglen, pk, pk_len, overhead);
            
        case TEE_MODE_TFM_FULL_KEM:
            return tee_tfm_full_dsa_verify(ctx, sig, siglen, msg, msglen, pk, pk_len, overhead);
#endif
            
#if CONFIG_TEE_SIMULATED
        case TEE_MODE_SIMULATED:
            return tee_simulated_dsa_verify(ctx, sig, siglen, msg, msglen, pk, pk_len, overhead);
#endif
            
        default:
            return -ENOTSUP;
    }
}

// ========================================================================
// UTILITY FUNCTIONS
// ========================================================================

/**
 * @brief Convert TEE mode to string
 */
const char* tee_mode_to_string(tee_mode_t mode) {
    switch (mode) {
        case TEE_MODE_NONE:
            return "NONE";
        case TEE_MODE_TFM_RNG_ONLY:
            return "TFM_RNG_ONLY";
        case TEE_MODE_TFM_FULL_KEM:
            return "TFM_FULL_KEM";
        case TEE_MODE_KEYSTONE:
            return "KEYSTONE";
        case TEE_MODE_SGX:
            return "SGX";
        case TEE_MODE_TDX:
            return "TDX";
        case TEE_MODE_SIMULATED:
            return "SIMULATED";
        default:
            return "UNKNOWN";
    }
}

/**
 * @brief Convert TEE provider to string
 */
const char* tee_provider_to_string(tee_provider_t provider) {
    switch (provider) {
        case TEE_PROVIDER_NONE:
            return "none";
        case TEE_PROVIDER_TFM:
            return "TF-M";
        case TEE_PROVIDER_KEYSTONE:
            return "Keystone";
        case TEE_PROVIDER_SGX:
            return "SGX";
        case TEE_PROVIDER_TDX:
            return "TDX";
        case TEE_PROVIDER_SIMULATED:
            return "Simulated";
        default:
            return "unknown";
    }
}

/**
 * @brief Check if TEE provider is available
 */
bool tee_is_available(tee_provider_t provider) {
    switch (provider) {
        case TEE_PROVIDER_NONE:
            return tee_none_is_available();
            
#if CONFIG_TEE_TFM_ENABLED
        case TEE_PROVIDER_TFM:
            return tee_tfm_rng_is_available();
#endif
            
#if CONFIG_TEE_SIMULATED
        case TEE_PROVIDER_SIMULATED:
            return tee_simulated_is_available();
#endif
            
        default:
            return false;
    }
}

/**
 * @brief Get default TEE context
 * 
 * Auto-detects available TEE and returns initialized context.
 * Priority order: TF-M > Simulated > None
 */
tee_context_t tee_get_default_context(void) {
    tee_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    
    // Get board name safely - CONFIG_BOARD is only defined in Zephyr build
#if defined(CONFIG_BOARD)
    const char *board = CONFIG_BOARD;
#else
    const char *board = "unknown";
#endif
    
    // Priority 1: TF-M (if enabled and available)
#if CONFIG_TEE_TFM_ENABLED
    if (tee_tfm_rng_is_available()) {
        ctx.mode = TEE_MODE_TFM_RNG_ONLY;  // Default to RNG-only for Phase 1
        ctx.provider = TEE_PROVIDER_TFM;
        ctx.board_name = board;
        printk("TEE: Auto-detected TF-M (RNG-only mode)\n");
        return ctx;
    }
#endif
    
    // Priority 2: Simulated TEE (if enabled)
#if CONFIG_TEE_SIMULATED
    if (tee_simulated_is_available()) {
        ctx.mode = TEE_MODE_SIMULATED;
        ctx.provider = TEE_PROVIDER_SIMULATED;
        ctx.board_name = board;
        printk("TEE: Auto-detected simulated TEE\n");
        return ctx;
    }
#endif
    
    // Priority 3: Baseline (no TEE) - always available
    ctx.mode = TEE_MODE_NONE;
    ctx.provider = TEE_PROVIDER_NONE;
    ctx.board_name = board;
    printk("TEE: No TEE available, using baseline mode\n");
    return ctx;
}

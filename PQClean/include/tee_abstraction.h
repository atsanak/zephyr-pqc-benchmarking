/**
 * @file tee_abstraction.h
 * @brief TEE Abstraction Layer for PQC Benchmarking Framework
 * 
 * This header defines a unified interface for Trusted Execution Environment (TEE)
 * integration across multiple ISAs and TEE technologies:
 * - ARM TrustZone-M (TF-M on Cortex-M33)
 * - RISC-V Keystone enclaves
 * - Intel SGX/TDX enclaves
 * - Software-simulated TEE (for testing)
 * 
 * Design Principles:
 * 1. Single API for all TEE backends
 * 2. Opt-in via compile-time flags
 * 3. Preserves existing benchmark interface
 * 4. Entropy parity between TEE and non-TEE
 * 5. Minimal CSV schema changes (2 new columns)
 * 
 * @version 1.0.0
 * @date 2025-11-27
 * @author PQC Benchmarking Framework Team
 */

#ifndef TEE_ABSTRACTION_H
#define TEE_ABSTRACTION_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ========================================================================
// TEE MODE AND PROVIDER DEFINITIONS
// ========================================================================

/**
 * @brief TEE execution mode
 * 
 * Defines how the benchmark operates with respect to TEE boundaries:
 * - NONE: All operations in normal world (baseline)
 * - TFM_RNG_ONLY: Only RNG calls route through TF-M secure world
 * - TFM_FULL_KEM: All KEM operations execute in TF-M secure partition
 * - KEYSTONE: RISC-V Keystone enclave execution
 * - SGX/TDX: Intel x86 enclave execution
 * - SIMULATED: Software-emulated TEE boundary (testing only)
 */
typedef enum {
    TEE_MODE_NONE = 0,           /**< No TEE (normal world only) */
    TEE_MODE_TFM_RNG_ONLY = 1,   /**< TF-M secure RNG service */
    TEE_MODE_TFM_FULL_KEM = 2,   /**< Full KEM operations in TF-M partition */
    TEE_MODE_KEYSTONE = 3,       /**< RISC-V Keystone enclave */
    TEE_MODE_SGX = 4,            /**< Intel SGX enclave */
    TEE_MODE_TDX = 5,            /**< Intel TDX trusted domain */
    TEE_MODE_SIMULATED = 99      /**< Software-emulated TEE boundary */
} tee_mode_t;

/**
 * @brief TEE provider identification
 * 
 * Identifies which TEE technology is providing the trusted execution.
 */
typedef enum {
    TEE_PROVIDER_NONE = 0,       /**< No TEE provider */
    TEE_PROVIDER_TFM = 1,        /**< ARM Trusted Firmware-M */
    TEE_PROVIDER_KEYSTONE = 2,   /**< RISC-V Keystone */
    TEE_PROVIDER_SGX = 3,        /**< Intel SGX */
    TEE_PROVIDER_TDX = 4,        /**< Intel TDX */
    TEE_PROVIDER_SIMULATED = 99  /**< Software-only boundary */
} tee_provider_t;

// ========================================================================
// TEE CONTEXT AND OVERHEAD STRUCTURES
// ========================================================================

/**
 * @brief TEE initialization context
 * 
 * Contains configuration and state for a TEE session.
 */
typedef struct {
    tee_mode_t mode;             /**< Current TEE execution mode */
    tee_provider_t provider;     /**< TEE technology provider */
    const char *board_name;      /**< Board identifier (e.g., "nrf5340dk") */
    uint32_t flags;              /**< Reserved for future use (e.g., encryption flags) */
    void *private_data;          /**< Backend-specific context pointer */
} tee_context_t;

/**
 * @brief TEE overhead metrics (per-operation breakdown)
 * 
 * Captures fine-grained timing breakdown for individual TEE operations.
 * Used to isolate TEE-specific costs from baseline execution.
 * 
 * Measurement points for ARM TrustZone-M:
 * - world_switch_cycles: SMC instruction (normal→secure + secure→normal)
 * - context_save_cycles: Register save before world switch (16 GPRs + FPU)
 * - context_restore_cycles: Register restore after return
 * - ipc_overhead_cycles: TF-M IPC handling (SPM dispatch)
 * - secure_exec_cycles: Actual execution in secure partition
 */
typedef struct {
    // Core world-switching metrics
    uint64_t world_switch_cycles;      /**< SMC/ECALL instruction overhead (~50 cycles) */
    uint64_t context_save_cycles;      /**< Register save before switch (~300 cycles) */
    uint64_t context_restore_cycles;   /**< Register restore after return (~300 cycles) */
    uint64_t ipc_overhead_cycles;      /**< TF-M IPC/SPM handling (~500-1000 cycles) */
    
    // Execution metrics
    uint64_t secure_exec_cycles;       /**< Execution time in secure world */
    uint64_t param_marshal_cycles;     /**< Parameter marshalling cost */
    
    // RNG-specific metrics
    uint64_t rng_overhead_cycles;      /**< psa_generate_random() vs sys_csrand_get() */
    uint32_t rng_bytes_requested;      /**< Bytes of entropy requested */
    uint32_t rng_calls_count;          /**< Number of RNG calls in operation */
    
    // Optional advanced metrics
    uint64_t attestation_cycles;       /**< Attestation overhead (if enabled) */
    uint64_t key_storage_cycles;       /**< Secure key storage access time */
    double encrypted_mem_slowdown;     /**< Encrypted memory multiplier (1.0 = none) */
    
    // Aggregate metrics (computed)
    uint64_t total_overhead_cycles;    /**< Sum of all TEE overhead */
    double overhead_percent;           /**< (TEE - baseline) / baseline × 100 */
} tee_overhead_t;

/**
 * @brief TEE metrics for CSV output
 * 
 * Comprehensive structure for all TEE-specific metrics to be written to CSV.
 * These are the 8 new TEE columns added to the benchmark output.
 */
typedef struct {
    // Identification (2 columns)
    tee_mode_t mode;                   /**< TEE_Mode: 0=none, 1=RNG, 2=full, etc. */
    tee_provider_t provider;           /**< TEE_Provider: TF-M, Keystone, SGX, etc. */
    
    // Timing breakdown (6 columns)
    uint64_t world_switch_cycles;      /**< TEE_World_Switch_Cycles */
    uint64_t context_save_cycles;      /**< TEE_Context_Save_Cycles */
    uint64_t context_restore_cycles;   /**< TEE_Context_Restore_Cycles */
    uint64_t rng_overhead_cycles;      /**< TEE_RNG_Overhead_Cycles */
    uint64_t ipc_overhead_cycles;      /**< TEE_IPC_Overhead_Cycles */
    double total_overhead_percent;     /**< TEE_Total_Overhead_Percent */
    
    // Baseline comparison
    uint64_t baseline_cycles;          /**< Baseline execution (no TEE) */
    uint64_t tee_cycles;               /**< TEE execution (with overhead) */
} tee_metrics_t;

// ========================================================================
// TEE ABSTRACTION LAYER API
// ========================================================================

/**
 * @brief Initialize TEE context
 * 
 * Must be called before any TEE operations. Performs:
 * - TEE capability detection
 * - Backend initialization (TF-M IPC, Keystone driver, SGX loader)
 * - Secure partition setup (if applicable)
 * 
 * @param ctx Pointer to TEE context to initialize
 * @return 0 on success, negative errno on failure
 */
int tee_init(tee_context_t *ctx);

/**
 * @brief Deinitialize TEE context
 * 
 * Releases TEE resources, closes secure sessions, cleans up state.
 * 
 * @param ctx Pointer to TEE context to deinitialize
 * @return 0 on success, negative errno on failure
 */
int tee_deinit(tee_context_t *ctx);

/**
 * @brief Generate KEM keypair through TEE boundary
 * 
 * Routes keypair generation through the configured TEE backend.
 * For TEE_MODE_NONE, directly calls PQClean API.
 * For TEE_MODE_TFM_FULL_KEM, invokes TF-M secure partition via IPC.
 * 
 * @param ctx TEE context
 * @param pk Output buffer for public key
 * @param sk Output buffer for secret key
 * @param pk_len Public key length in bytes
 * @param sk_len Secret key length in bytes
 * @param overhead Optional pointer to receive overhead metrics (can be NULL)
 * @return 0 on success, negative errno on failure
 */
int tee_kem_keygen(tee_context_t *ctx, 
                   uint8_t *pk, uint8_t *sk,
                   uint32_t pk_len, uint32_t sk_len,
                   tee_overhead_t *overhead);

/**
 * @brief Encapsulate shared secret through TEE boundary
 * 
 * Routes encapsulation through the configured TEE backend.
 * 
 * @param ctx TEE context
 * @param ct Output buffer for ciphertext
 * @param ss Output buffer for shared secret
 * @param pk Input public key
 * @param ct_len Ciphertext length in bytes
 * @param ss_len Shared secret length in bytes
 * @param pk_len Public key length in bytes
 * @param overhead Optional pointer to receive overhead metrics (can be NULL)
 * @return 0 on success, negative errno on failure
 */
int tee_kem_encaps(tee_context_t *ctx,
                   uint8_t *ct, uint8_t *ss,
                   const uint8_t *pk,
                   uint32_t ct_len, uint32_t ss_len, uint32_t pk_len,
                   tee_overhead_t *overhead);

/**
 * @brief Decapsulate shared secret through TEE boundary
 * 
 * Routes decapsulation through the configured TEE backend.
 * 
 * @param ctx TEE context
 * @param ss Output buffer for shared secret
 * @param sk Input secret key
 * @param ct Input ciphertext
 * @param ss_len Shared secret length in bytes
 * @param sk_len Secret key length in bytes
 * @param ct_len Ciphertext length in bytes
 * @param overhead Optional pointer to receive overhead metrics (can be NULL)
 * @return 0 on success, negative errno on failure
 */
int tee_kem_decaps(tee_context_t *ctx,
                   uint8_t *ss, const uint8_t *sk, const uint8_t *ct,
                   uint32_t ss_len, uint32_t sk_len, uint32_t ct_len,
                   tee_overhead_t *overhead);

/**
 * @brief Get random bytes through TEE boundary
 * 
 * For TEE_MODE_TFM_RNG_ONLY: routes to psa_generate_random()
 * For TEE_MODE_TFM_FULL_KEM: routes to TF-M crypto partition
 * For TEE_MODE_NONE: routes to sys_csrand_get()
 * 
 * This function is used to intercept randombytes() calls during KEM operations.
 * 
 * @param ctx TEE context
 * @param buf Output buffer for random bytes
 * @param len Number of random bytes to generate
 * @return 0 on success, negative errno on failure
 */
int tee_rng_get_bytes(tee_context_t *ctx, uint8_t *buf, size_t len);

// ========================================================================
// DSA (DIGITAL SIGNATURE) TEE OPERATIONS - FIPS 204/205/206
// ========================================================================

/**
 * @brief Generate DSA keypair through TEE boundary
 * 
 * Routes keypair generation through the configured TEE backend.
 * Supports ML-DSA (FIPS 204), SLH-DSA/SPHINCS+ (FIPS 205), FN-DSA/Falcon (FIPS 206).
 * 
 * @param ctx TEE context
 * @param pk Output buffer for public key
 * @param sk Output buffer for secret key
 * @param pk_len Public key length in bytes
 * @param sk_len Secret key length in bytes
 * @param overhead Optional pointer to receive overhead metrics (can be NULL)
 * @return 0 on success, negative errno on failure
 */
int tee_dsa_keygen(tee_context_t *ctx,
                   uint8_t *pk, uint8_t *sk,
                   uint32_t pk_len, uint32_t sk_len,
                   tee_overhead_t *overhead);

/**
 * @brief Sign message through TEE boundary
 * 
 * Routes signing operation through the configured TEE backend.
 * The signature is computed over the message using the secret key.
 * 
 * @param ctx TEE context
 * @param sig Output buffer for signature
 * @param siglen Pointer to receive actual signature length
 * @param msg Input message to sign
 * @param msglen Message length in bytes
 * @param sk Input secret key
 * @param sk_len Secret key length in bytes
 * @param sig_max_len Maximum signature buffer size
 * @param overhead Optional pointer to receive overhead metrics (can be NULL)
 * @return 0 on success, negative errno on failure
 */
int tee_dsa_sign(tee_context_t *ctx,
                 uint8_t *sig, size_t *siglen,
                 const uint8_t *msg, size_t msglen,
                 const uint8_t *sk, uint32_t sk_len,
                 uint32_t sig_max_len,
                 tee_overhead_t *overhead);

/**
 * @brief Verify signature through TEE boundary
 * 
 * Routes verification operation through the configured TEE backend.
 * Verifies that the signature is valid for the message and public key.
 * 
 * @param ctx TEE context
 * @param sig Input signature to verify
 * @param siglen Signature length in bytes
 * @param msg Input message that was signed
 * @param msglen Message length in bytes
 * @param pk Input public key
 * @param pk_len Public key length in bytes
 * @param overhead Optional pointer to receive overhead metrics (can be NULL)
 * @return 0 if signature is valid, negative errno on failure or invalid signature
 */
int tee_dsa_verify(tee_context_t *ctx,
                   const uint8_t *sig, size_t siglen,
                   const uint8_t *msg, size_t msglen,
                   const uint8_t *pk, uint32_t pk_len,
                   tee_overhead_t *overhead);

// ========================================================================
// TEE QUERY AND UTILITY FUNCTIONS
// ========================================================================

/**
 * @brief Convert TEE mode enum to string
 * 
 * @param mode TEE mode enum
 * @return String representation (e.g., "TFM_RNG_ONLY")
 */
const char* tee_mode_to_string(tee_mode_t mode);

/**
 * @brief Convert TEE provider enum to string
 * 
 * @param provider TEE provider enum
 * @return String representation (e.g., "TF-M")
 */
const char* tee_provider_to_string(tee_provider_t provider);

/**
 * @brief Check if TEE provider is available on current platform
 * 
 * Performs runtime detection:
 * - TF-M: checks CONFIG_BUILD_WITH_TFM and TF-M API availability
 * - Keystone: checks for Keystone driver (/dev/keystone)
 * - SGX/TDX: checks CPUID flags and SGX/TDX driver
 * 
 * @param provider TEE provider to check
 * @return true if available, false otherwise
 */
bool tee_is_available(tee_provider_t provider);

/**
 * @brief Get default TEE context for current platform
 * 
 * Auto-detects available TEE and returns initialized context.
 * Priority order: TF-M > Keystone > SGX > TDX > None
 * 
 * @return Initialized TEE context (mode may be TEE_MODE_NONE if no TEE available)
 */
tee_context_t tee_get_default_context(void);

/**
 * @brief Initialize overhead structure to zero
 * 
 * @param overhead Pointer to overhead structure to initialize
 */
static inline void tee_overhead_init(tee_overhead_t *overhead) {
    if (overhead) {
        overhead->world_switch_cycles = 0;
        overhead->context_save_cycles = 0;
        overhead->context_restore_cycles = 0;
        overhead->ipc_overhead_cycles = 0;
        overhead->secure_exec_cycles = 0;
        overhead->param_marshal_cycles = 0;
        overhead->rng_overhead_cycles = 0;
        overhead->rng_bytes_requested = 0;
        overhead->rng_calls_count = 0;
        overhead->attestation_cycles = 0;
        overhead->key_storage_cycles = 0;
        overhead->encrypted_mem_slowdown = 1.0;
        overhead->total_overhead_cycles = 0;
        overhead->overhead_percent = 0.0;
    }
}

/**
 * @brief Compute aggregate overhead metrics
 * 
 * Calculates total_overhead_cycles and overhead_percent from component metrics.
 * 
 * @param overhead Pointer to overhead structure to update
 * @param baseline_cycles Baseline execution time (without TEE)
 */
static inline void tee_overhead_compute(tee_overhead_t *overhead, uint64_t baseline_cycles) {
    if (overhead) {
        // Sum all overhead components
        overhead->total_overhead_cycles = 
            overhead->world_switch_cycles +
            overhead->context_save_cycles +
            overhead->context_restore_cycles +
            overhead->ipc_overhead_cycles +
            overhead->param_marshal_cycles +
            overhead->rng_overhead_cycles;
        
        // Calculate percentage overhead
        if (baseline_cycles > 0) {
            overhead->overhead_percent = 
                ((double)overhead->total_overhead_cycles / (double)baseline_cycles) * 100.0;
        } else {
            overhead->overhead_percent = 0.0;
        }
    }
}

/**
 * @brief Convert overhead structure to CSV metrics
 * 
 * @param overhead Source overhead structure
 * @param ctx TEE context for mode/provider
 * @param baseline_cycles Baseline execution cycles
 * @param tee_cycles TEE execution cycles
 * @param metrics Output metrics structure
 */
static inline void tee_overhead_to_metrics(const tee_overhead_t *overhead,
                                            const tee_context_t *ctx,
                                            uint64_t baseline_cycles,
                                            uint64_t tee_cycles,
                                            tee_metrics_t *metrics) {
    if (metrics) {
        metrics->mode = ctx ? ctx->mode : TEE_MODE_NONE;
        metrics->provider = ctx ? ctx->provider : TEE_PROVIDER_NONE;
        
        if (overhead) {
            metrics->world_switch_cycles = overhead->world_switch_cycles;
            metrics->context_save_cycles = overhead->context_save_cycles;
            metrics->context_restore_cycles = overhead->context_restore_cycles;
            metrics->rng_overhead_cycles = overhead->rng_overhead_cycles;
            metrics->ipc_overhead_cycles = overhead->ipc_overhead_cycles;
            metrics->total_overhead_percent = overhead->overhead_percent;
        } else {
            metrics->world_switch_cycles = 0;
            metrics->context_save_cycles = 0;
            metrics->context_restore_cycles = 0;
            metrics->rng_overhead_cycles = 0;
            metrics->ipc_overhead_cycles = 0;
            metrics->total_overhead_percent = 0.0;
        }
        
        metrics->baseline_cycles = baseline_cycles;
        metrics->tee_cycles = tee_cycles;
    }
}

/**
 * @brief Get CSV header for TEE metrics
 * 
 * Returns the column names for TEE metrics in CSV format.
 * 
 * @return Comma-separated header string
 */
static inline const char* tee_metrics_csv_header(void) {
    return "TEE_Mode,TEE_Provider,TEE_World_Switch_Cycles,TEE_Context_Save_Cycles,"
           "TEE_Context_Restore_Cycles,TEE_RNG_Overhead_Cycles,TEE_IPC_Overhead_Cycles,"
           "TEE_Total_Overhead_Percent";
}

// ========================================================================
// COMPILE-TIME CONFIGURATION MACROS
// ========================================================================

/**
 * @def CONFIG_TEE_ENABLED
 * @brief Master switch for TEE integration
 * 
 * When undefined, all TEE functions become no-ops or direct passthroughs.
 * Set via CMake: -DENABLE_TEE=ON
 */
#ifdef ENABLE_TEE
    #define CONFIG_TEE_ENABLED 1
#else
    #define CONFIG_TEE_ENABLED 0
#endif

/**
 * @def CONFIG_TEE_TFM_ENABLED
 * @brief Enable ARM TF-M backend
 * 
 * Requires: CONFIG_BUILD_WITH_TFM=y in Zephyr config
 * Set via CMake: -DTEE_PROVIDER=tfm
 */
#if defined(CONFIG_BUILD_WITH_TFM) && CONFIG_TEE_ENABLED
    #define CONFIG_TEE_TFM_ENABLED 1
#else
    #define CONFIG_TEE_TFM_ENABLED 0
#endif

/**
 * @def CONFIG_TEE_SIMULATED
 * @brief Enable software-simulated TEE
 * 
 * For testing TEE abstraction layer without real hardware.
 * Set via CMake: -DTEE_PROVIDER=simulated
 */
#ifdef TEE_PROVIDER_SIMULATED
    #define CONFIG_TEE_SIMULATED 1
#else
    #define CONFIG_TEE_SIMULATED 0
#endif

#ifdef __cplusplus
}
#endif

#endif /* TEE_ABSTRACTION_H */

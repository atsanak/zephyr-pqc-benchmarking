#ifndef ENTROPY_CONSUMPTION_H
#define ENTROPY_CONSUMPTION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "kem_registry.h"  // For MAX_KEMS definition

// Maximum operations we support
#define MAX_OPS 3

// Maximum sample buffer size for Shannon entropy calculation (4KB)
#define ENTROPY_SAMPLE_BUFFER_SIZE 4096

/**
 * Per-(KEM, operation) entropy consumption tracking state
 * Tracks RNG usage patterns for scientific analysis
 */
typedef struct {
    uint64_t total_bytes;           // Total RNG bytes consumed
    uint32_t call_count;            // Number of randombytes() calls
    uint32_t failure_count;         // RNG failures (sys_csrand_get != 0)
    uint8_t sample_buffer[ENTROPY_SAMPLE_BUFFER_SIZE];  // For Shannon calculation
    uint32_t sample_bytes_collected;  // Bytes currently in buffer
    bool sample_complete;           // Buffer full?
} entropy_consumption_state_t;

/**
 * Set the current tracking context (KEM ID, operation type)
 * Must be called before each benchmark run to set proper attribution
 * 
 * @param kem_id Index of the KEM being benchmarked (0-15)
 * @param op_type Operation type (0=KeyPair, 1=Encaps, 2=Decaps)
 */
void entropy_tracking_set_context(uint32_t kem_id, uint32_t op_type);

/**
 * Disable tracking context without emitting invalid-context errors
 * Used after per-operation attribution is complete to prevent contamination.
 */
void entropy_tracking_clear_context(void);

/**
 * Reset tracking state for the current context
 * Call before starting a new benchmark run
 */
void entropy_tracking_reset(void);

/**
 * Get the current tracking state pointer
 * Used internally for instrumentation
 * 
 * @return Pointer to current state, or NULL if no context set
 */
entropy_consumption_state_t* entropy_tracking_get_current(void);

/**
 * Record an RNG consumption event (called by randombytes.c)
 * This is the core instrumentation hook
 * 
 * @param buf Buffer that was filled with random bytes
 * @param len Number of bytes requested
 * @param result Return code from sys_csrand_get (0 = success)
 */
void entropy_tracking_record(const uint8_t *buf, size_t len, int result);

/**
 * Calculate Shannon entropy from a byte buffer
 * Returns value in [0, 8] bits per byte, where 8 = perfect uniform
 * 
 * H(X) = -Σ p(x) log₂ p(x)
 * 
 * @param data Buffer of bytes to analyze
 * @param len Number of bytes in buffer
 * @return Shannon entropy in bits per byte (0-8)
 */
double calculate_shannon_entropy(const uint8_t *data, size_t len);

/**
 * Calculate Min-entropy (H∞) from a byte buffer
 * Returns worst-case entropy: H∞ = -log₂(max pᵢ)
 * This is the conservative estimate used in NIST SP 800-90B
 * 
 * @param data Buffer of bytes to analyze
 * @param len Number of bytes in buffer
 * @return Min-entropy in bits per byte (0-8)
 */
double calculate_min_entropy(const uint8_t *data, size_t len);

#endif // ENTROPY_CONSUMPTION_H

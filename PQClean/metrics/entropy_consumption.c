#include "entropy_consumption.h"
#include "metric.h"
#include <string.h>
#include <math.h>

#ifdef __ZEPHYR__
#include <zephyr/sys/printk.h>
#else
#include <stdio.h>
#define printk printf
#endif

// Global tracking state for all (KEM, operation) pairs
static entropy_consumption_state_t tracking_state[MAX_KEMS][MAX_OPS];

// Current tracking context
static uint32_t current_kem_id = 0;
static uint32_t current_op_type = 0;
static bool context_valid = false;

/**
 * Set the current tracking context
 */
void entropy_tracking_set_context(uint32_t kem_id, uint32_t op_type) {
    if (kem_id >= MAX_KEMS || op_type >= MAX_OPS) {
        printk("ERROR: Invalid entropy tracking context: KEM=%u, OP=%u (MAX_KEMS=%d, MAX_OPS=%d)\n", 
               kem_id, op_type, MAX_KEMS, MAX_OPS);
        context_valid = false;
        return;
    }
    
    current_kem_id = kem_id;
    current_op_type = op_type;
    context_valid = true;
    
    printk("*** ENTROPY TRACKING: Set context KEM=%u, OP=%u (context_valid=%d)\n",
           current_kem_id, current_op_type, context_valid);
}

/**
 * Clear current context explicitly (no error logging).
 */
void entropy_tracking_clear_context(void) {
    context_valid = false;
    current_kem_id = 0;
    current_op_type = 0;
}

/**
 * Reset tracking state for current context
 */
void entropy_tracking_reset(void) {
    if (!context_valid) {
        printk("WARNING: Entropy tracking reset called but context_valid=false\n");
        return;
    }
    
    entropy_consumption_state_t *state = &tracking_state[current_kem_id][current_op_type];
    memset(state, 0, sizeof(entropy_consumption_state_t));
    
    printk("*** ENTROPY TRACKING: Reset state for KEM=%u, OP=%u\n", current_kem_id, current_op_type);
}

/**
 * Get current tracking state
 */
entropy_consumption_state_t* entropy_tracking_get_current(void) {
    if (!context_valid) {
        return NULL;
    }
    
    return &tracking_state[current_kem_id][current_op_type];
}

/**
 * Record an RNG consumption event
 * This is the instrumentation hook called by randombytes.c
 */
void entropy_tracking_record(const uint8_t *buf, size_t len, int result) {
    if (!context_valid || buf == NULL) {
        return;  // Silently ignore if no context set
    }
    
    entropy_consumption_state_t *state = &tracking_state[current_kem_id][current_op_type];
    
    // Count every RNG API call (success or failure)
    state->call_count++;
    
    // Failed calls are counted, but do not contribute consumed bytes or entropy samples.
    if (result != 0) {
        state->failure_count++;
        return;
    }

    // Successful call: account consumed bytes.
    state->total_bytes += (uint64_t)len;
    
    // Collect samples for Shannon entropy calculation (if buffer not full)
    if (!state->sample_complete && len > 0) {
        uint32_t space_remaining = ENTROPY_SAMPLE_BUFFER_SIZE - state->sample_bytes_collected;
        uint32_t bytes_to_copy = (len < space_remaining) ? len : space_remaining;
        
        if (bytes_to_copy > 0) {
            memcpy(state->sample_buffer + state->sample_bytes_collected, buf, bytes_to_copy);
            state->sample_bytes_collected += bytes_to_copy;
            
            if (state->sample_bytes_collected >= ENTROPY_SAMPLE_BUFFER_SIZE) {
                state->sample_complete = true;
            }
        }
    }
}

/**
 * Calculate Shannon entropy from byte buffer
 * H(X) = -Σ p(x) log₂ p(x)
 * Returns value in [0, 8] bits per byte
 */
double calculate_shannon_entropy(const uint8_t *data, size_t len) {
    if (data == NULL || len == 0) {
        return 0.0;
    }
    
    // Count frequency of each byte value (0-255)
    uint32_t freq[256] = {0};
    for (size_t i = 0; i < len; i++) {
        freq[data[i]]++;
    }
    
    // Calculate Shannon entropy
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) {
            continue;  // log(0) is undefined, skip
        }
        
        double p = (double)freq[i] / (double)len;
        entropy -= p * log2(p);
    }
    
    return entropy;
}

/**
 * Calculate Min-entropy (H∞) from byte buffer
 * H∞ = -log₂(max pᵢ) where max pᵢ is the highest probability
 * This is the worst-case entropy measure used in NIST SP 800-90B
 * Returns value in [0, 8] bits per byte
 */
double calculate_min_entropy(const uint8_t *data, size_t len) {
    if (data == NULL || len == 0) {
        return 0.0;
    }
    
    // Count frequency of each byte value (0-255)
    uint32_t freq[256] = {0};
    uint32_t max_freq = 0;
    
    for (size_t i = 0; i < len; i++) {
        freq[data[i]]++;
        if (freq[data[i]] > max_freq) {
            max_freq = freq[data[i]];
        }
    }
    
    // Calculate min-entropy: H∞ = -log₂(p_max)
    if (max_freq == 0 || max_freq > len) {
        return 0.0;  // Safety check
    }
    
    double p_max = (double)max_freq / (double)len;
    double min_entropy = -log2(p_max);
    
    return min_entropy;
}

/**
 * Populate benchmark results with entropy consumption data
 * Called after each benchmark run to transfer stats
 */
void populate_entropy_consumption_results(int kem_id, int op_id, benchmark_results_t *result) {
    if (kem_id < 0 || kem_id >= MAX_KEMS || op_id < 0 || op_id >= MAX_OPS || result == NULL) {
        printk("ERROR: populate_entropy_consumption_results invalid params: KEM=%d, OP=%d\n", kem_id, op_id);
        return;
    }
    
    entropy_consumption_state_t *state = &tracking_state[kem_id][op_id];
    
    // Transfer basic counters
    result->rng_bytes_consumed = state->total_bytes;
    result->rng_call_count = state->call_count;
    result->rng_failure_count = state->failure_count;
    
    // Calculate bytes per call
    if (state->call_count > 0) {
        result->rng_bytes_per_call = (double)state->total_bytes / (double)state->call_count;
    } else {
        result->rng_bytes_per_call = 0.0;
    }
    
    // Calculate Shannon entropy and Min-entropy if we have samples
    if (state->sample_bytes_collected > 0) {
        result->rng_shannon_entropy = calculate_shannon_entropy(
            state->sample_buffer, state->sample_bytes_collected);
        result->rng_min_entropy = calculate_min_entropy(
            state->sample_buffer, state->sample_bytes_collected);
    } else {
        result->rng_shannon_entropy = 0.0;
        result->rng_min_entropy = 0.0;
    }
    
    printk("*** ENTROPY TRACKING: Populated results for KEM=%d, OP=%d: %llu bytes, %u calls, Shannon=%.4f, MinEnt=%.4f\n",
           kem_id, op_id, state->total_bytes, state->call_count, result->rng_shannon_entropy, result->rng_min_entropy);
}

/**
 * Populate benchmark results with entropy consumption data for DSA/Sign algorithms
 * Uses the same tracking state array with sign_id as the index
 * Called after each DSA benchmark run to transfer stats
 */
void populate_entropy_consumption_results_for_sign(int sign_id, int op_id, benchmark_results_t *result) {
    // DSA operations: 0=KeyPair, 1=Sign, 2=Verify (maps to MAX_OPS)
    if (sign_id < 0 || sign_id >= MAX_KEMS || op_id < 0 || op_id >= MAX_OPS || result == NULL) {
        printk("ERROR: populate_entropy_consumption_results_for_sign invalid params: SIGN=%d, OP=%d\n", sign_id, op_id);
        return;
    }
    
    entropy_consumption_state_t *state = &tracking_state[sign_id][op_id];
    
    // Transfer basic counters
    result->rng_bytes_consumed = state->total_bytes;
    result->rng_call_count = state->call_count;
    result->rng_failure_count = state->failure_count;
    
    // Calculate bytes per call
    if (state->call_count > 0) {
        result->rng_bytes_per_call = (double)state->total_bytes / (double)state->call_count;
    } else {
        result->rng_bytes_per_call = 0.0;
    }
    
    // Calculate Shannon entropy and Min-entropy if we have samples
    if (state->sample_bytes_collected > 0) {
        result->rng_shannon_entropy = calculate_shannon_entropy(
            state->sample_buffer, state->sample_bytes_collected);
        result->rng_min_entropy = calculate_min_entropy(
            state->sample_buffer, state->sample_bytes_collected);
    } else {
        result->rng_shannon_entropy = 0.0;
        result->rng_min_entropy = 0.0;
    }
    
    printk("*** ENTROPY TRACKING: Populated DSA results for SIGN=%d, OP=%d: %llu bytes, %u calls, Shannon=%.4f, MinEnt=%.4f\n",
           sign_id, op_id, state->total_bytes, state->call_count, result->rng_shannon_entropy, result->rng_min_entropy);
}

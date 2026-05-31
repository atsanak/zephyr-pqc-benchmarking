#ifndef METRIC_H
#define METRIC_H

#include <stdint.h>
#include <stdbool.h>
#include "utils.h"

// Forward declarations for KEM and DSA registries
typedef struct kem_info kem_info_t;
typedef struct sign_info sign_info_t;

// Note: operation_type_t and benchmark_results_t are defined in utils.h to avoid circular dependency

// Entropy consumption tracking (Tier 2)
typedef struct {
    uint64_t total_bytes_consumed;      // Total RNG bytes used
    uint32_t rng_call_count;            // Number of randombytes() calls
    uint32_t rng_failure_count;         // RNG failures during operation
    double shannon_entropy_bits;        // Shannon entropy of consumed bytes (0-8)
    bool shannon_valid;                 // Whether Shannon was successfully computed
} entropy_consumption_t;

// ========================================================================
// KEM Metric Functions
// ========================================================================

// Cycle measurement functions
void calculate_baseline_stats(uint64_t *samples, uint32_t n, benchmark_results_t *result);

// Energy measurement functions
void measure_energy_consumption(operation_type_t op_type, benchmark_results_t *result);
void recalculate_energy_with_memory_intensity(benchmark_results_t *result);

// Robust energy model functions
bool energy_estimate_uJ(uint64_t avg_cycles,
                        double stddev_cycles,     // in cycles
                        double f_hz,
                        const char *board_tag,
                        double *mean_uJ,
                        double *stddev_uJ,
                        const char **model_tag_out);

// Jitter measurement functions
void measure_timing_jitter(operation_type_t op_type, benchmark_results_t *result);

// Entropy testing functions
void test_entropy_starvation(operation_type_t op_type, benchmark_results_t *result);

// Entropy consumption tracking (Tier 2)
void populate_entropy_consumption_results(int kem_id, int op_id, benchmark_results_t *result);

// Memory constraint testing functions
void test_memory_constraints(operation_type_t op_type, benchmark_results_t *result);

// Throttled performance testing functions
void test_throttled_performance(operation_type_t op_type, benchmark_results_t *result);

// Instruction profiling functions
void profile_instruction_level(operation_type_t op_type, benchmark_results_t *result);

// ========================================================================
// DSA/Signature Metric Functions (Full 49-metric support)
// ========================================================================

// Jitter measurement for DSA
void measure_timing_jitter_for_sign(sign_info_t* sign, operation_type_t op_type, benchmark_results_t *result);

// Entropy testing for DSA
void test_entropy_starvation_for_sign(sign_info_t* sign, operation_type_t op_type, benchmark_results_t *result);

// Entropy consumption tracking for DSA (Tier 2)
void populate_entropy_consumption_results_for_sign(int sign_id, int op_id, benchmark_results_t *result);

// Memory constraint testing for DSA
void test_memory_constraints_for_sign(sign_info_t* sign, operation_type_t op_type, benchmark_results_t *result);

// Throttled performance testing for DSA
void test_throttled_performance_for_sign(sign_info_t* sign, operation_type_t op_type, benchmark_results_t *result);

// Energy measurement for DSA (uses same model as KEM, but needs DSA context)
void measure_energy_consumption_for_sign(sign_info_t* sign, operation_type_t op_type, benchmark_results_t *result);

// Instruction profiling for DSA
void profile_instruction_level_for_sign(sign_info_t* sign, operation_type_t op_type, benchmark_results_t *result);

#endif // METRIC_H

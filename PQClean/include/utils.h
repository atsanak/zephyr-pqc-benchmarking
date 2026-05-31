#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>  // For size_t

#include "benchmark_alloc.h"

// Batch timing constants for publication-grade measurements
#define MIN_WINDOW_CYCLES   (100000ULL)   // ~0.1–1 ms depending on board clock
#define MAX_INNER           (1u<<20)      // Maximum inner loop iterations

// Forward declarations to avoid circular dependency
typedef enum {
    OP_KEYPAIR,
    OP_ENCAPS, 
    OP_DECAPS,
    // DSA operations (for signature benchmarking)
    OP_SIGN,
    OP_VERIFY
} operation_type_t;

// Algorithm family type for distinguishing KEM vs DSA benchmarks
typedef enum {
    ALG_FAMILY_KEM,
    ALG_FAMILY_DSA
} algorithm_family_t;

// Forward declaration for KEM info structure
typedef struct kem_info kem_info_t;

// Forward declaration for DSA/Signature info structure
typedef struct sign_info sign_info_t;

typedef struct {
    // Step 2: Baseline cycle counts
    uint32_t iterations;
    uint64_t avg_cycles;
    uint64_t min_cycles;
    uint64_t max_cycles;
    uint64_t stddev_cycles;
    
    // Step 3: Energy consumption
    double energy_uj;
    double stddev_energy_uj;
    
    // Step 4: Timing stability (jitter) - publication-grade metrics
    uint64_t jitter_cycles;      // max - min from N=1000 samples
    double coefficient_variation_pct;  // CV for publication-grade reporting
    uint64_t p50_cycles;         // median (50th percentile)
    uint64_t p95_cycles;         // 95th percentile  
    uint64_t p99_cycles;         // 99th percentile
    uint64_t q1_cycles;          // 25th percentile (SUPERCOP-style quartile)
    uint64_t q3_cycles;          // 75th percentile (SUPERCOP-style quartile)
    uint64_t iqr_cycles;         // Interquartile range (Q3-Q1)
    double quartile_coeff_dispersion_pct; // 100 * (Q3-Q1)/(Q3+Q1)
    uint64_t mad_cycles;         // Median Absolute Deviation
    
    // Step 5: Entropy starvation stress
    double entropy_success_pct;
    double avg_latency_entropy_ms;
    
    // Step 5b: Per-KEM entropy consumption tracking (Tier 2)
    uint64_t rng_bytes_consumed;        // Total RNG bytes used by this operation
    uint32_t rng_call_count;            // Number of randombytes() calls
    uint32_t rng_failure_count;         // RNG failures during operation
    double rng_shannon_entropy;         // Shannon entropy of consumed bytes (0-8 bits/byte)
    double rng_min_entropy;             // Min-entropy H∞ (worst-case, 0-8 bits/byte)
    double rng_bytes_per_call;          // Average bytes per RNG call

    // Step 5c: Primitive/session byte-efficiency metrics
    uint32_t session_crypto_bytes;      // KEM: pk+ct, DSA: pk+sig
    uint32_t operation_io_bytes;        // Keypair: pk, Enc/Dec: ct, Sign/Verify: sig
    double cycles_per_session_crypto_byte;
    double energy_per_session_crypto_byte_uj;
    double cycles_per_op_io_byte;
    
    // Step 6: Memory constraint testing
    uint64_t cycles_at_128kb_ram_cap;
    double failure_128kb_pct;
    uint64_t cycles_at_64kb_ram_cap;
    double failure_64kb_pct;
    
    // Step 7: Throttled CPU performance (dynamic 50% frequency scaling)
    uint64_t cycles_throttled_50pct;
    double latency_throttled_50pct_ms;
    uint64_t jitter_adder_throttled_cycles;  // Additional jitter under throttling
    
    // Step 7b: Enhanced throttling profiles - make 450 lines earn their keep!
    double throttle_slowdown_pct;           // Percentage slowdown from baseline
    uint64_t cycles_cache_tlb_stress;       // Cycles under cache/TLB pressure
    uint64_t cycles_memory_bw_stress;       // Cycles under memory bandwidth pressure
    uint64_t cycles_branch_stress;          // Cycles under branch mispredict pressure
    double tail_amplification_factor;       // (p99/p50)_stressed / (p99/p50)_baseline
    const char* throttle_profile_used;      // Profile name for CSV identification
    
    // Auditability fields for throttling verification (publication-ready)
    uint64_t p50_stress_cycles;             // Stressed p50 for TailAmp verification
    uint64_t p99_stress_cycles;             // Stressed p99 for TailAmp verification
    uint64_t jitter_stress_cycles;          // Stressed jitter for JitterAdder verification
    uint64_t min_stress_cycles;             // Stressed min for auditability
    uint64_t max_stress_cycles;             // Stressed max for auditability

    // Step 7c: RTOS scheduler-stress profiling
    // Models a periodic higher-priority worker interfering with the benchmarked task.
    uint64_t rtos_stress_avg_cycles;        // Average cycles under scheduler stress
    double rtos_stress_slowdown_pct;        // Slowdown vs matched unstressed window
    uint32_t rtos_stress_activations;       // Number of stress-thread activations observed
    uint64_t rtos_stress_jitter_cycles;     // Peak-to-peak spread under RTOS stress
    uint64_t rtos_stress_p50_cycles;        // Median of stressed samples
    uint64_t rtos_stress_p95_cycles;        // 95th percentile of stressed samples
    uint64_t rtos_stress_p99_cycles;        // 99th percentile of stressed samples
    double rtos_tail_amplification_factor;  // (p99/p50)_stress / (p99/p50)_baseline_window

    // Step 7c-CI: Statistical inference over the matched baseline/stressed windows.
    // Seed = FNV-1a(algo || '|' || op || '|' || isa); reproducibility: same (algo,op,isa)
    // always yields identical CI bounds and permutation p-value across re-runs.
    double   rtos_slowdown_ci_lo_pct;       // Bootstrap 95% CI lower bound on slowdown_pct
    double   rtos_slowdown_ci_hi_pct;       // Bootstrap 95% CI upper bound on slowdown_pct
    double   rtos_tail_amp_ci_lo;           // Bootstrap 95% CI lower bound on tail-amplification
    double   rtos_tail_amp_ci_hi;           // Bootstrap 95% CI upper bound on tail-amplification
    double   rtos_stress_perm_p;            // One-sided permutation p-value, H0: mean(stress) <= mean(baseline)
    uint32_t rtos_n_baseline;               // Baseline-window sample count behind the CI
    uint32_t rtos_n_stress;                 // Stressed-window sample count behind the CI

    /* Deadline-slack analysis (primitive_rtos).
     * Budget from PQC_DEADLINE_BUDGET_US (default 10000 us = 10 ms).
     * Slack = budget - latency_at_quantile; negative = deadline miss.
     * Miss-risk is a piecewise-linear CDF interpolation over {p50, p95, p99}. */
    double   deadline_budget_us;
    double   deadline_slack_p50_us;
    double   deadline_slack_p99_us;
    double   deadline_miss_risk_pct;

    /* ISR-Injection Tax Profile (IITP).
     * Matched-window k_timer probe: a kernel-scheduled ISR-context callback
     * fires at PQC_ISR_TAX_PERIOD_US (default 100 us) during a second bench
     * pass, and we report the observed dispatch tax. Isolates the ISR-only
     * component of tail latency — orthogonal to thread-level RTOS_Stress_*. */
    uint32_t isr_injection_rate_hz;        // ISRs/sec actually delivered
    uint64_t isr_injected_cycles_avg;      // mean cycles/op under injection
    double   isr_injection_slowdown_pct;   // 100 * (inj - base) / base
    double   isr_dispatch_tax_cycles;      // per-ISR dispatch cost

    /* Cooperative Fairness to Co-Runners (CFCR).
     * Matched-window probe: a higher-priority victim thread is released by a
     * k_timer ISR at PQC_COOP_VICTIM_PERIOD_US. We count wake-completions
     * during an idle window vs a PQC-op window; the drop measures the cost
     * that PQC execution imposes on concurrently-scheduled system work. */
    uint64_t coop_victim_idle_ticks;       // wakes during idle baseline
    uint64_t coop_victim_op_ticks;         // wakes during PQC-op window
    double   coop_starvation_pct;          // 100 * (1 - op/idle), clamped
    double   coop_fairness_index;          // op/idle ratio, clamped [0,1]

    /* Periodic Release Jitter Profile (PRJP).
     * k_timer at PQC_PRJP_PERIOD_US wakes a k_sem; we measure the cycles
     * between ISR expiry and k_sem_take completion while PQC ops run in
     * the consumer loop. Characterises scheduler release precision under
     * PQC load — a dimension absent from pqm4/SUPERCOP/PQC-LEO. */
    uint32_t release_period_us;            // configured release period
    uint64_t release_latency_p50_cycles;   // 50th pct release latency
    uint64_t release_latency_p99_cycles;   // 99th pct release latency
    uint64_t release_jitter_cycles;        // p99 - p50
    uint32_t release_overruns;             // ISR re-fired before take

    // Step 8: Instruction-level & memory access profiling
    uint64_t instr_count;
    uint32_t cache_misses;
    uint32_t branch_mispredictions;
    
    // Step 9: Stack usage monitoring per operation
    size_t stack_used_bytes;                // Stack usage for this specific operation
    size_t stack_peak_bytes;                // Peak stack usage detected
    size_t stack_available_bytes;           // Available stack space remaining

    // Step 9b: Heap / working-set footprint for the measured operation path
    size_t heap_peak_bytes;                 // Peak tracked heap outstanding bytes
    uint64_t heap_alloc_total_bytes;        // Total tracked heap bytes allocated
    uint32_t heap_alloc_calls;              // Number of tracked heap allocations
    size_t working_set_peak_bytes;          // Peak heap + peak stack working set
    double peak_memory_per_session_crypto_byte; // Working-set peak normalized by session bytes
    double peak_memory_per_op_io_byte;      // Working-set peak normalized by operation I/O bytes

    // Step 9c: Symmetric primitive attribution (pqm4-style)
    uint64_t cycles_sha2;                   // Average SHA-2 cycles per operation
    uint64_t cycles_sha3_keccak;            // Average SHA3/SHAKE/Keccak cycles per operation
    uint64_t cycles_aes;                    // Average AES cycles per operation
    uint64_t cycles_symmetric_total;        // Sum of tracked symmetric primitive cycles
    double symmetric_cycles_pct;            // cycles_symmetric_total / avg_cycles * 100
    double sha2_share_pct;                  // SHA-2 share of symmetric subtotal
    double sha3_keccak_share_pct;           // SHA3/Keccak share of symmetric subtotal
    double aes_share_pct;                   // AES share of symmetric subtotal
    const char *dominant_symmetric_primitive; // Dominant symmetric cost driver

    // Step 9d: Microarchitectural profiling export
    double cache_misses_per_kinstr;         // Cache misses per 1k instructions
    double branch_mispredictions_per_kinstr;// Branch misses per 1k instructions

    // Step 10: TEE integration (Chapter 7 - TrustZone-M security)
    int tee_mode;                           // 0=none, 1=rng_only, 2=kem_full, 3=storage_enc
    const char* tee_provider;               // "none", "tfm", "optee", etc.
    uint64_t tee_overhead_cycles;           // Total world-switching overhead in cycles
    double tee_overhead_pct;                // TEE overhead as percentage of total
    
    // Step 10b: Detailed TEE metrics breakdown (for Chapter 7 Table 7.1)
    uint64_t tee_world_switch_cycles;       // SMC instruction overhead (~50 cycles)
    uint64_t tee_context_save_cycles;       // Register save before switch (~300 cycles)
    uint64_t tee_context_restore_cycles;    // Register restore after return (~300 cycles)
    uint64_t tee_rng_overhead_cycles;       // psa_generate_random() vs sys_csrand_get()
    uint64_t tee_ipc_overhead_cycles;       // TF-M IPC/SPM handling (~500-1000 cycles)
    uint32_t tee_rng_calls;                 // Number of RNG calls during operation
    uint32_t tee_rng_bytes;                 // Total RNG bytes requested
} benchmark_results_t;

// Runtime KEM configuration variables (updated by select_kem function)
extern uint32_t PK_BYTES;
extern uint32_t SK_BYTES;
extern uint32_t CT_BYTES;
extern uint32_t SS_BYTES;

// DSA-specific runtime configuration variables (for signature algorithms)
extern uint32_t SIG_PK_BYTES;
extern uint32_t SIG_SK_BYTES;
extern uint32_t SIG_BYTES;

// Architecture and configuration constants
extern const char* ARCH_NAME;
extern const char* ARCH_FAMILY;
extern const char* BOARD_STR;
extern const char* ALGORITHM_NAME;

// Benchmark configuration constants
extern const uint32_t MIN_ITERS;
extern const uint32_t MAX_ITERS;
extern const uint32_t WARMUP_ITERS;
extern const uint32_t ENERGY_SAMPLES;
extern const uint32_t JITTER_SAMPLES;
extern const uint32_t ENTROPY_STRESS_ITERATIONS;
extern const double TARGET_PRECISION_PCT;
extern const uint32_t MIN_WALL_TIME_MS;
extern const uint64_t CYCLES_PER_UJ;

// CSV output functions
void print_csv_header(void);
void print_csv_results(benchmark_results_t results[3]);
void print_csv_results_for_kem(kem_info_t* kem, benchmark_results_t results[3]);
void print_csv_header_for_sign(void);
void print_csv_results_for_sign(sign_info_t* sign, benchmark_results_t results[3]);
void print_csv_data_header_for_family(algorithm_family_t family);
const char *benchmark_csv_schema_version(void);
void print_stack_usage(void);
void measure_stack_usage(benchmark_results_t *result);  // Measure stack usage per operation
void measure_stack_for_op(benchmark_results_t *result); // Per-operation stack attribution
void compute_deadline_metrics(benchmark_results_t *r);  // Deadline-slack analysis
void zero_isr_tax_metrics(benchmark_results_t *r);      // IITP sentinel init
void measure_isr_tax_for_kem(kem_info_t *kem,
                             operation_type_t op_type,
                             benchmark_results_t *result,
                             uint8_t *pk, uint8_t *sk,
                             uint8_t *ct, uint8_t *ss1, uint8_t *ss2);
void measure_isr_tax_for_sign(sign_info_t *sign,
                              operation_type_t op_type,
                              benchmark_results_t *result,
                              uint8_t *pk, uint8_t *sk,
                              uint8_t *signature, size_t *sig_len,
                              uint8_t *message, size_t message_len);

void zero_fairness_metrics(benchmark_results_t *r);      // CFCR sentinel init
void measure_fairness_for_kem(kem_info_t *kem,
                              operation_type_t op_type,
                              benchmark_results_t *result,
                              uint8_t *pk, uint8_t *sk,
                              uint8_t *ct, uint8_t *ss1, uint8_t *ss2);
void measure_fairness_for_sign(sign_info_t *sign,
                               operation_type_t op_type,
                               benchmark_results_t *result,
                               uint8_t *pk, uint8_t *sk,
                               uint8_t *signature, size_t *sig_len,
                               uint8_t *message, size_t message_len);

void zero_release_jitter_metrics(benchmark_results_t *r);  // PRJP sentinel init
void measure_release_jitter_for_kem(kem_info_t *kem,
                                    operation_type_t op_type,
                                    benchmark_results_t *result,
                                    uint8_t *pk, uint8_t *sk,
                                    uint8_t *ct, uint8_t *ss1, uint8_t *ss2);
void measure_release_jitter_for_sign(sign_info_t *sign,
                                     operation_type_t op_type,
                                     benchmark_results_t *result,
                                     uint8_t *pk, uint8_t *sk,
                                     uint8_t *signature, size_t *sig_len,
                                     uint8_t *message, size_t message_len);

// Environment and system info functions
void print_system_info(void);

// KEM configuration functions
void select_kem(const kem_info_t *kem);
void select_sign(const sign_info_t *sign);
void init_default_kem(void);

// Benchmark validation functions  
bool validate_measurement_authenticity(benchmark_results_t *result, const char *op_name);

#endif // UTILS_H

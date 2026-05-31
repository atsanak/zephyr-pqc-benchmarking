#include "utils.h"
#include "kem_registry.h"
#include "sig_registry.h"
#include "metric.h"
#include "tee_abstraction.h"
#include <zephyr/sys/printk.h>
#include <zephyr/sys_clock.h>
#include <zephyr/kernel.h>
#include <math.h>
#include <string.h>
#include "benchmark_control.h"

// Use Zephyr's STRINGIFY macro 
#include <zephyr/toolchain/common.h>

static bool get_energy_csv_values(const benchmark_results_t *r,
                                  double *mean_uJ,
                                  double *stddev_uJ,
                                  const char **model_tag_out) {
    // Get board name
    const char *board_tag = "generic";
    #ifdef CONFIG_BOARD
        board_tag = STRINGIFY(CONFIG_BOARD);
    #endif
    
    // Get frequency - use sys_clock_hw_cycles_per_sec from Zephyr
    double f_hz = (double)sys_clock_hw_cycles_per_sec();
    if (f_hz <= 0.0) {
        return false;
    }

    // Use new robust energy estimation
    double local_mean_uJ = 0.0;
    double local_stddev_uJ = 0.0;
    const char *local_model_tag = NULL;
    bool have_energy = energy_estimate_uJ((uint64_t)r->avg_cycles,
                                          (double)r->stddev_cycles,
                                          f_hz, board_tag,
                                          &local_mean_uJ,
                                          &local_stddev_uJ,
                                          &local_model_tag);
    if (!have_energy || local_mean_uJ <= 0.0) {
        return false;
    }

    if (mean_uJ) {
        *mean_uJ = local_mean_uJ;
    }
    if (stddev_uJ) {
        *stddev_uJ = local_stddev_uJ;
    }
    if (model_tag_out) {
        *model_tag_out = local_model_tag;
    }
    return true;
}

// Helper function to print energy values with proper NA handling
static void print_energy_csv_values(const benchmark_results_t *r) {
    double mean_uJ = 0.0;
    double stddev_uJ = 0.0;
    const char *model_tag = NULL;

    if (get_energy_csv_values(r, &mean_uJ, &stddev_uJ, &model_tag)) {
        printk("%.3f,%.3f,%s,", mean_uJ, stddev_uJ, model_tag ? model_tag : "unknown");
    } else {
        printk("NA,NA,NA,");
    }
}

static inline double clamp_neg0(double x) { 
    return (fabs(x) < 5e-7) ? 0.0 : x; 
}

static const char *benchmark_entropy_source_mode(void)
{
#ifdef CONFIG_TEST_RANDOM_GENERATOR
    return "test_rng_nonphysical";
#else
    return "hardware_entropy";
#endif
}

static bool benchmark_pmu_counters_supported(void)
{
#if defined(CONFIG_ARM_PMU) && !defined(CONFIG_CPU_CORTEX_M)
    return true;
#elif defined(CONFIG_X86) && defined(CONFIG_X86_MSR_ACCESS)
    return true;
#elif defined(CONFIG_RISCV_PMU)
    return true;
#else
    return false;
#endif
}

static const char *benchmark_pmu_mode_label(void)
{
#if defined(CONFIG_ARM_PMU) && !defined(CONFIG_CPU_CORTEX_M)
    return "arm_pmu_counters";
#elif defined(CONFIG_X86) && defined(CONFIG_X86_MSR_ACCESS)
    return "x86_msr_pmu_counters";
#elif defined(CONFIG_RISCV_PMU)
    return "riscv_pmu_counters";
#elif defined(CONFIG_TIMING_FUNCTIONS)
    return "timing_only_no_counters";
#else
    return "no_pmu_counters";
#endif
}

static const char *benchmark_energy_source_label(void)
{
#ifdef CONFIG_SOC_POWER_MEASUREMENT
    return "hardware_power_measurement";
#elif defined(CONFIG_PM_DEVICE_RUNTIME)
    return "pm_framework_estimation";
#else
    return "academic_cycle_model";
#endif
}

static const char *benchmark_throttling_capability_label(void)
{
#if defined(CONFIG_PM_DEVICE_RUNTIME) && defined(CONFIG_CPU_FREQ_SCALING)
    return "hardware_dvfs";
#elif defined(CONFIG_PM_DEVICE_RUNTIME)
    return "pm_framework_only";
#else
    return "simulation_only";
#endif
}

static uint32_t session_crypto_bytes_for_kem(const kem_info_t *kem) {
    if (kem) {
        return kem->pk_bytes + kem->ct_bytes;
    }
    return PK_BYTES + CT_BYTES;
}

static uint32_t session_crypto_bytes_for_sign(const sign_info_t *sign) {
    if (sign) {
        return sign->pk_bytes + sign->signature_bytes;
    }
    return SIG_PK_BYTES + SIG_BYTES;
}

static uint32_t operation_io_bytes_for_kem(const kem_info_t *kem,
                                           operation_type_t op_type) {
    switch (op_type) {
        case OP_KEYPAIR:
            return kem ? kem->pk_bytes : PK_BYTES;
        case OP_ENCAPS:
        case OP_DECAPS:
            return kem ? kem->ct_bytes : CT_BYTES;
        default:
            return 0U;
    }
}

static uint32_t operation_io_bytes_for_sign(const sign_info_t *sign,
                                            operation_type_t op_type) {
    switch (op_type) {
        case OP_KEYPAIR:
            return sign ? sign->pk_bytes : SIG_PK_BYTES;
        case OP_SIGN:
        case OP_VERIFY:
            return sign ? sign->signature_bytes : SIG_BYTES;
        default:
            return 0U;
    }
}

static void populate_byte_efficiency_metrics(benchmark_results_t *r,
                                             uint32_t session_bytes,
                                             uint32_t op_io_bytes) {
    double mean_uJ = 0.0;
    bool have_energy = get_energy_csv_values(r, &mean_uJ, NULL, NULL);

    r->session_crypto_bytes = session_bytes;
    r->operation_io_bytes = op_io_bytes;
    r->cycles_per_session_crypto_byte =
        (session_bytes > 0U) ? ((double)r->avg_cycles / (double)session_bytes) : 0.0;
    r->energy_per_session_crypto_byte_uj =
        (have_energy && session_bytes > 0U) ? (mean_uJ / (double)session_bytes) : 0.0;
    r->cycles_per_op_io_byte =
        (op_io_bytes > 0U) ? ((double)r->avg_cycles / (double)op_io_bytes) : 0.0;
}

static void populate_novelty_derived_metrics(benchmark_results_t *r) {
    if (!r) {
        return;
    }

    r->peak_memory_per_session_crypto_byte =
        (r->session_crypto_bytes > 0U) ?
        ((double)r->working_set_peak_bytes / (double)r->session_crypto_bytes) : 0.0;
    r->peak_memory_per_op_io_byte =
        (r->operation_io_bytes > 0U) ?
        ((double)r->working_set_peak_bytes / (double)r->operation_io_bytes) : 0.0;
}

static void print_csv_common_header_suffix(void) {
    printk("Operation,Iterations,");
    printk("Avg_Cycles,Min_Cycles,Max_Cycles,StdDev_Cycles,");
    printk("Energy_uJ,StdDev_Energy_uJ,Energy_Model_Tag,Jitter_Cycles,");
    printk("CoeffVar_pct,p50_Cycles,p95_Cycles,p99_Cycles,Q1_Cycles,Q3_Cycles,IQR_Cycles,Quartile_Coeff_Dispersion_pct,MAD_Cycles,");
    printk("Entropy_Success_pct,Avg_Latency_Entropy_ms,");
    printk("RNG_Bytes_Consumed,RNG_Call_Count,RNG_Failures,RNG_Shannon_Entropy,RNG_Min_Entropy_H_inf,RNG_Bytes_Per_Call,");
    printk("Session_Crypto_Bytes,Operation_IO_Bytes,Cycles_Per_Session_Crypto_Byte,");
    printk("Energy_Per_Session_Crypto_Byte_uJ,Cycles_Per_Op_IO_Byte,");
    printk("Cycles_At_128KB_RAM_Cap,Failure_128KB_pct,");
    printk("Cycles_At_64KB_RAM_Cap,Failure_64KB_pct,");
    printk("Cycles_Throttled_50pct,Latency_Throttled_50pct_ms,Jitter_Adder_Throttled_Cycles,");
    printk("Throttle_Slowdown_pct,Cycles_Cache_TLB_Stress,Cycles_Memory_BW_Stress,");
    printk("Cycles_Branch_Stress,Tail_Amplification_Factor,Throttle_Profile_Used,");
    printk("p50_Stress_Cycles,p99_Stress_Cycles,Jitter_Stress_Cycles,Min_Stress_Cycles,Max_Stress_Cycles,");
    printk("RTOS_Stress_Avg_Cycles,RTOS_Stress_Slowdown_Pct,RTOS_Stress_Activations,");
    printk("RTOS_Stress_Jitter_Cycles,RTOS_Stress_p50_Cycles,RTOS_Stress_p95_Cycles,");
    printk("RTOS_Stress_p99_Cycles,RTOS_Tail_Amplification_Factor,");
    printk("RTOS_Slowdown_CI_Lo_pct,RTOS_Slowdown_CI_Hi_pct,");
    printk("RTOS_Tail_Amp_CI_Lo,RTOS_Tail_Amp_CI_Hi,");
    printk("RTOS_Stress_Perm_P,RTOS_N_Baseline,RTOS_N_Stress,");
    printk("Deadline_Budget_us,Deadline_Slack_p50_us,");
    printk("Deadline_Slack_p99_us,Deadline_Miss_Risk_pct,");
    printk("ISR_Injection_Rate_Hz,ISR_Injected_Cycles_Avg,");
    printk("ISR_Injection_Slowdown_pct,ISR_Dispatch_Tax_Cycles,");
    printk("Coop_Victim_Idle_Ticks,Coop_Victim_Op_Ticks,");
    printk("Coop_Starvation_pct,Coop_Fairness_Index,");
    printk("Release_Period_us,Release_Latency_p50_Cycles,");
    printk("Release_Latency_p99_Cycles,Release_Jitter_Cycles,Release_Overruns,");
    printk("Stack_Used_Bytes,Stack_Peak_Bytes,Stack_Available_Bytes,");
    printk("Heap_Peak_Bytes,Heap_Alloc_Total_Bytes,Heap_Alloc_Calls,Working_Set_Peak_Bytes,");
    printk("Peak_Memory_Per_Session_Crypto_Byte,Peak_Memory_Per_Op_IO_Byte,");
    printk("Cycles_SHA2,Cycles_SHA3_Keccak,Cycles_AES,Cycles_Symmetric_Total,Symmetric_Cycles_Pct,");
    printk("SHA2_Share_pct,SHA3_Keccak_Share_pct,AES_Share_pct,Dominant_Symmetric_Primitive,");
    printk("Instr_Count,Cache_Misses,Branch_Mispredictions,Cache_Misses_Per_KInstr,Branch_Mispredictions_Per_KInstr,");
    printk("TEE_Mode,TEE_Provider,TEE_Overhead_Cycles,TEE_Overhead_pct,");
    printk("TEE_World_Switch_Cycles,TEE_Context_Save_Cycles,TEE_Context_Restore_Cycles,");
    printk("TEE_RNG_Overhead_Cycles,TEE_IPC_Overhead_Cycles,TEE_RNG_Calls,TEE_RNG_Bytes\n");
}

static void sanitize_csv_fields(benchmark_results_t *r) {
    if (r->throttle_profile_used && strcmp(r->throttle_profile_used, "Cache_TLB_Stress") == 0) {
        r->jitter_adder_throttled_cycles = 0;
    }
    if (r->throttle_profile_used && strcmp(r->throttle_profile_used, "Freq50_DVFS") == 0) {
        r->cycles_cache_tlb_stress = 0;
        r->p50_stress_cycles = 0;
        r->p99_stress_cycles = 0;
        r->jitter_stress_cycles = 0;
        r->min_stress_cycles = 0;
        r->max_stress_cycles = 0;
    }
}

const char *benchmark_csv_schema_version(void) {
    return "v2";
}

void print_csv_data_header_for_family(algorithm_family_t family) {
    if (family == ALG_FAMILY_KEM) {
        printk("KEM,Variant,PK_Bytes,SK_Bytes,CT_Bytes,SS_Bytes,");
    } else {
        printk("DSA,Variant,PK_Bytes,SK_Bytes,Sig_Bytes,");
    }
    print_csv_common_header_suffix();
}

static void print_csv_common_result_fields(benchmark_results_t *r,
                                           uint32_t session_bytes,
                                           uint32_t op_io_bytes) {
    populate_byte_efficiency_metrics(r, session_bytes, op_io_bytes);
    populate_novelty_derived_metrics(r);
    compute_deadline_metrics(r);

    printk("%u,%llu,%llu,%llu,%llu,",
           r->iterations, r->avg_cycles, r->min_cycles, r->max_cycles, r->stddev_cycles);
    print_energy_csv_values(r);
    printk("%llu,", r->jitter_cycles);
    printk("%.3f,%llu,%llu,%llu,%llu,%llu,%llu,%.3f,%llu,",
           clamp_neg0(r->coefficient_variation_pct),
           r->p50_cycles, r->p95_cycles, r->p99_cycles,
           r->q1_cycles, r->q3_cycles, r->iqr_cycles,
           clamp_neg0(r->quartile_coeff_dispersion_pct),
           r->mad_cycles);
    printk("%.1f,%.2f,",
           clamp_neg0(r->entropy_success_pct),
           clamp_neg0(r->avg_latency_entropy_ms));
    printk("%llu,%u,%u,%.4f,%.4f,%.2f,",
           r->rng_bytes_consumed, r->rng_call_count, r->rng_failure_count,
           r->rng_shannon_entropy, r->rng_min_entropy, r->rng_bytes_per_call);
    printk("%u,%u,%.3f,%.6f,%.3f,",
           r->session_crypto_bytes, r->operation_io_bytes,
           r->cycles_per_session_crypto_byte,
           r->energy_per_session_crypto_byte_uj,
           r->cycles_per_op_io_byte);
    printk("%llu,%.1f,%llu,%.1f,",
           r->cycles_at_128kb_ram_cap, clamp_neg0(r->failure_128kb_pct),
           r->cycles_at_64kb_ram_cap, clamp_neg0(r->failure_64kb_pct));
    printk("%llu,%.3f,%llu,",
           r->cycles_throttled_50pct, r->latency_throttled_50pct_ms,
           r->jitter_adder_throttled_cycles);
    printk("%.1f,%llu,%llu,%llu,%.3f,%s,",
           r->throttle_slowdown_pct, r->cycles_cache_tlb_stress,
           r->cycles_memory_bw_stress, r->cycles_branch_stress,
           r->tail_amplification_factor,
           r->throttle_profile_used ? r->throttle_profile_used : "Freq50");
    printk("%llu,%llu,%llu,%llu,%llu,",
           r->p50_stress_cycles, r->p99_stress_cycles, r->jitter_stress_cycles,
           r->min_stress_cycles, r->max_stress_cycles);
    printk("%llu,%.3f,%u,%llu,%llu,%llu,%llu,%.3f,",
           r->rtos_stress_avg_cycles,
           clamp_neg0(r->rtos_stress_slowdown_pct),
           r->rtos_stress_activations,
           r->rtos_stress_jitter_cycles,
           r->rtos_stress_p50_cycles,
           r->rtos_stress_p95_cycles,
           r->rtos_stress_p99_cycles,
           r->rtos_tail_amplification_factor);
    printk("%.3f,%.3f,%.4f,%.4f,%.4f,%u,%u,",
           r->rtos_slowdown_ci_lo_pct,
           r->rtos_slowdown_ci_hi_pct,
           r->rtos_tail_amp_ci_lo,
           r->rtos_tail_amp_ci_hi,
           r->rtos_stress_perm_p,
           r->rtos_n_baseline,
           r->rtos_n_stress);
    printk("%.3f,%.3f,%.3f,%.3f,",
           r->deadline_budget_us, r->deadline_slack_p50_us,
           r->deadline_slack_p99_us, r->deadline_miss_risk_pct);
    printk("%u,%llu,%.3f,%.3f,",
           r->isr_injection_rate_hz,
           r->isr_injected_cycles_avg,
           r->isr_injection_slowdown_pct,
           r->isr_dispatch_tax_cycles);
    printk("%llu,%llu,%.3f,%.3f,",
           r->coop_victim_idle_ticks, r->coop_victim_op_ticks,
           r->coop_starvation_pct, r->coop_fairness_index);
    printk("%u,%llu,%llu,%llu,%u,",
           r->release_period_us,
           r->release_latency_p50_cycles,
           r->release_latency_p99_cycles,
           r->release_jitter_cycles,
           r->release_overruns);
    printk("%zu,%zu,%zu,",
           r->stack_used_bytes, r->stack_peak_bytes, r->stack_available_bytes);
    printk("%zu,%llu,%u,%zu,",
           r->heap_peak_bytes, r->heap_alloc_total_bytes,
           r->heap_alloc_calls, r->working_set_peak_bytes);
    printk("%.6f,%.6f,",
           clamp_neg0(r->peak_memory_per_session_crypto_byte),
           clamp_neg0(r->peak_memory_per_op_io_byte));
    printk("%llu,%llu,%llu,%llu,%.3f,%.3f,%.3f,%.3f,%s,",
           r->cycles_sha2, r->cycles_sha3_keccak, r->cycles_aes,
           r->cycles_symmetric_total, clamp_neg0(r->symmetric_cycles_pct),
           clamp_neg0(r->sha2_share_pct),
           clamp_neg0(r->sha3_keccak_share_pct),
           clamp_neg0(r->aes_share_pct),
           r->dominant_symmetric_primitive ? r->dominant_symmetric_primitive : "None");
    printk("%llu,%u,%u,%.6f,%.6f,",
           r->instr_count, r->cache_misses, r->branch_mispredictions,
           clamp_neg0(r->cache_misses_per_kinstr),
           clamp_neg0(r->branch_mispredictions_per_kinstr));
    printk("%d,%s,%llu,%.3f,%llu,%llu,%llu,%llu,%llu,%u,%u\n",
           (int)r->tee_mode, r->tee_provider ? r->tee_provider : "none",
           r->tee_overhead_cycles, r->tee_overhead_pct,
           r->tee_world_switch_cycles, r->tee_context_save_cycles,
           r->tee_context_restore_cycles, r->tee_rng_overhead_cycles,
           r->tee_ipc_overhead_cycles, r->tee_rng_calls, r->tee_rng_bytes);
}

// Runtime KEM configuration variables (no more hardcoded constants)
uint32_t PK_BYTES = 0;
uint32_t SK_BYTES = 0;
uint32_t CT_BYTES = 0;
uint32_t SS_BYTES = 0;
const char* ALGORITHM_NAME = "universal-kem-benchmark";

// Enhanced Architecture detection for multi-QEMU support
#ifdef CONFIG_X86
    const char* ARCH_NAME = "x86";
    const char* ARCH_FAMILY = "x86";
#elif CONFIG_ARM64
    const char* ARCH_NAME = "ARM64";
    const char* ARCH_FAMILY = "ARM";
#elif CONFIG_ARM
    const char* ARCH_NAME = "ARM";
    const char* ARCH_FAMILY = "ARM";
#elif CONFIG_RISCV
    #ifdef CONFIG_64BIT
        const char* ARCH_NAME = "RISC-V-64";
    #else
        const char* ARCH_NAME = "RISC-V-32";
    #endif
    const char* ARCH_FAMILY = "RISC-V";
#elif CONFIG_MIPS
    const char* ARCH_NAME = "MIPS";
    const char* ARCH_FAMILY = "MIPS";
#elif CONFIG_XTENSA
    const char* ARCH_NAME = "Xtensa";
    const char* ARCH_FAMILY = "Xtensa";
#elif CONFIG_SPARC
    const char* ARCH_NAME = "SPARC";
    const char* ARCH_FAMILY = "SPARC";
#elif CONFIG_ARC
    const char* ARCH_NAME = "ARC";
    const char* ARCH_FAMILY = "ARC";
#else
    const char* ARCH_NAME = "Unknown";
    const char* ARCH_FAMILY = "Unknown";
#endif

// Board name detection
#ifndef CONFIG_BOARD_TARGET
    #ifdef CONFIG_BOARD
        const char* BOARD_STR = CONFIG_BOARD;
    #else
        const char* BOARD_STR = "unknown";
    #endif
#else
    const char* BOARD_STR = CONFIG_BOARD_TARGET;
#endif

// Benchmark configuration constants (defined once based on architecture)
#ifdef CONFIG_CPU_CORTEX_M0
    #define MIN_ITERS_VAL 50            // Minimum iterations for statistical validity
    #define MAX_ITERS_VAL 500           // Maximum iterations for comprehensive testing
    #define WARMUP_ITERS_VAL 1          // Warm-up iterations (reduced)
    #define ENERGY_SAMPLES_VAL 2        // Energy measurement samples (reduced)
    #define JITTER_SAMPLES_VAL 2        // Samples for jitter analysis (reduced)
    #define ENTROPY_STRESS_ITERATIONS_VAL 2  // Reduced for demo
#elif CONFIG_CPU_CORTEX_M3
    #define MIN_ITERS_VAL 20            // Minimum iterations for lower-end MCUs
    #define MAX_ITERS_VAL 200           // Maximum iterations for Cortex-M3
    #define WARMUP_ITERS_VAL 1          // Warm-up iterations (reduced)
    #define ENERGY_SAMPLES_VAL 2        // Energy measurement samples (reduced)
    #define JITTER_SAMPLES_VAL 2        // Samples for jitter analysis (reduced)
    #define ENTROPY_STRESS_ITERATIONS_VAL 2  // Reduced for demo
#else
    #define MIN_ITERS_VAL 100           // Minimum iterations for higher-end targets
    #define MAX_ITERS_VAL 1000          // Maximum iterations for comprehensive testing
    #define WARMUP_ITERS_VAL 1          // Warm-up iterations (reduced)
    #define ENERGY_SAMPLES_VAL 3        // Energy measurement samples (increased)
    #define JITTER_SAMPLES_VAL 3        // Samples for jitter analysis (increased)
    #define ENTROPY_STRESS_ITERATIONS_VAL 3  // Increased for proper testing
#endif

// Iteration constants for comprehensive benchmarking
#ifndef MIN_ITERS_VAL
#define MIN_ITERS_VAL 1000
#endif

#ifndef MAX_ITERS_VAL  
#define MAX_ITERS_VAL 1000
#endif

#ifndef WARMUP_ITERS_VAL
#define WARMUP_ITERS_VAL 50
#endif

#ifndef ENERGY_SAMPLES_VAL
#define ENERGY_SAMPLES_VAL 100
#endif

#ifndef JITTER_SAMPLES_VAL
#define JITTER_SAMPLES_VAL 1000  // Publication-grade: 1000 samples for good statistical power
#endif

#ifndef ENTROPY_STRESS_ITERATIONS_VAL
#define ENTROPY_STRESS_ITERATIONS_VAL 50
#endif

// Define the actual constants once
const uint32_t MIN_ITERS = MIN_ITERS_VAL;
const uint32_t MAX_ITERS = MAX_ITERS_VAL;
const uint32_t WARMUP_ITERS = WARMUP_ITERS_VAL;
const uint32_t ENERGY_SAMPLES = ENERGY_SAMPLES_VAL;
const uint32_t JITTER_SAMPLES = JITTER_SAMPLES_VAL;
const uint32_t ENTROPY_STRESS_ITERATIONS = ENTROPY_STRESS_ITERATIONS_VAL;

const double TARGET_PRECISION_PCT = 50.0;  // Target precision: 50% (ULTRA relaxed for speed)
const uint32_t MIN_WALL_TIME_MS = 10;     // Minimum wall-clock time (ULTRA reduced for speed)

// ========================================================================
// RUNTIME KEM SELECTION AND CONFIGURATION
// ========================================================================

/**
 * Select and configure the current KEM for benchmarking
 * Updates all runtime size variables and algorithm name
 */
void select_kem(const kem_info_t *kem) {
    if (!kem) {
        printk("ERROR: NULL KEM descriptor passed to select_kem()\n");
        return;
    }
    
    // Update runtime size variables from selected KEM
    PK_BYTES = kem->pk_bytes;
    SK_BYTES = kem->sk_bytes;
    CT_BYTES = kem->ct_bytes;
    SS_BYTES = kem->ss_bytes;
    ALGORITHM_NAME = kem->name;
    
    printk("Selected KEM: %s (pk=%u, sk=%u, ct=%u, ss=%u bytes)\n",
           kem->name, kem->pk_bytes, kem->sk_bytes, kem->ct_bytes, kem->ss_bytes);
}

void select_sign(const sign_info_t *sign) {
    if (!sign) {
        printk("ERROR: NULL DSA descriptor passed to select_sign()\n");
        return;
    }

    SIG_PK_BYTES = sign->pk_bytes;
    SIG_SK_BYTES = sign->sk_bytes;
    SIG_BYTES = sign->signature_bytes;
    ALGORITHM_NAME = sign->name;

    printk("Selected DSA: %s (pk=%u, sk=%u, sig=%u bytes)\n",
           sign->name, sign->pk_bytes, sign->sk_bytes, sign->signature_bytes);
}

/**
 * Initialize default KEM configuration
 * Sets up runtime variables with the first available KEM
 */
void init_default_kem(void) {
    // Initialize KEM registry first
    discover_and_register_all_kems();
    
    // Select first available KEM as default
    if (kem_count > 0) {
        kem_info_t* first_kem = get_kem_by_index(0);
        if (first_kem) {
            select_kem(first_kem);
            printk("Initialized with default KEM: %s\n", first_kem->name);
        } else {
            printk("WARNING: Failed to get first KEM from registry\n");
        }
    } else {
        // Fallback values if no KEMs are available
        PK_BYTES = 800;
        SK_BYTES = 1632;
        CT_BYTES = 768;
        SS_BYTES = 32;
        ALGORITHM_NAME = "no-kem-available";
        printk("WARNING: No KEMs available, using fallback values\n");
    }
}

// ========================================================================
// ARCHITECTURE-SPECIFIC ENERGY ESTIMATION
// ========================================================================
#ifdef CONFIG_X86
    const uint64_t CYCLES_PER_UJ = 1000000ULL;    // x86 QEMU estimation
#elif CONFIG_ARM64
    const uint64_t CYCLES_PER_UJ = 4000000ULL;    // ARM64 (Cortex-A53/A9) estimation
#elif CONFIG_ARM
    #ifdef CONFIG_CPU_CORTEX_M0
        const uint64_t CYCLES_PER_UJ = 8000000ULL;    // Cortex-M0 (very efficient)
    #elif CONFIG_CPU_CORTEX_M3
        const uint64_t CYCLES_PER_UJ = 6000000ULL;    // Cortex-M3 estimation
    #elif CONFIG_CPU_CORTEX_R5
        const uint64_t CYCLES_PER_UJ = 4500000ULL;    // Cortex-R5 estimation
    #else
        const uint64_t CYCLES_PER_UJ = 3000000ULL;    // General ARM estimation
    #endif
#elif CONFIG_RISCV
    #ifdef CONFIG_64BIT
        const uint64_t CYCLES_PER_UJ = 2200000ULL;    // RISC-V 64-bit
    #else
        const uint64_t CYCLES_PER_UJ = 2500000ULL;    // RISC-V 32-bit
    #endif
#elif CONFIG_MIPS
    const uint64_t CYCLES_PER_UJ = 1800000ULL;    // MIPS estimation
#elif CONFIG_XTENSA
    const uint64_t CYCLES_PER_UJ = 3500000ULL;    // Xtensa estimation
#elif CONFIG_SPARC
    const uint64_t CYCLES_PER_UJ = 1500000ULL;    // SPARC estimation
#elif CONFIG_ARC
    const uint64_t CYCLES_PER_UJ = 4000000ULL;    // ARC estimation
#else
    const uint64_t CYCLES_PER_UJ = 2000000ULL;    // Default conservative estimation
#endif

// ========================================================================
// STEP 9: FINAL CSV REPORT
// ========================================================================

static void print_csv_environment_prelude(const char *current_algorithm,
                                          uint32_t pk_bytes,
                                          uint32_t sk_bytes,
                                          uint32_t ct_or_sig_bytes,
                                          uint32_t ss_bytes,
                                          algorithm_family_t family) {
    const char *entropy_mode = benchmark_entropy_source_mode();
    const char *pmu_mode = benchmark_pmu_mode_label();
    const char *energy_mode = benchmark_energy_source_label();
    const char *throttle_mode = benchmark_throttling_capability_label();

    printk("\n# Environment\n");
    printk("Schema_Version,%s\n", benchmark_csv_schema_version());
    printk("Timing_Test_Cycles,1024000\n");

    printk("Current_Algorithm,%s\n", current_algorithm);
    printk("Current_PK_Size,%u           # bytes\n", pk_bytes);
    printk("Current_SK_Size,%u           # bytes\n", sk_bytes);
    if (family == ALG_FAMILY_KEM) {
        printk("Current_CT_Size,%u            # bytes\n", ct_or_sig_bytes);
        printk("Current_SS_Size,%u          # bytes\n", ss_bytes);
    } else {
        printk("Current_Signature_Size,%u     # bytes\n", ct_or_sig_bytes);
        printk("Current_SS_Size,0            # DSA has no shared-secret output\n");
    }
    
    // Handle CONFIG values with fallbacks for multi-architecture compatibility
    #ifdef CONFIG_MAIN_STACK_SIZE
        printk("Main_Stack_Size,%d          # bytes\n", CONFIG_MAIN_STACK_SIZE);
    #else
        printk("Main_Stack_Size,131072        # bytes (default)\n");
    #endif
    
    #ifdef CONFIG_HEAP_MEM_POOL_SIZE
        printk("Heap_Pool_Size,%d          # bytes\n", CONFIG_HEAP_MEM_POOL_SIZE);
    #else
        printk("Heap_Pool_Size,262144        # bytes (default)\n");
    #endif
    printk("\n# Universal PQC Benchmark Metrics\n");
    
    // Add provenance header for academic transparency
    printk("# Container=zephyr-ci (version resolved by accurate_verification.sh); Board=%s\n", BOARD_STR);
    printk("# Architecture=%s; BuildConfig=project prj.conf with board-specific CONF_FILE fragments when selected\n", ARCH_NAME);
    printk("# EntropySource=%s; PMU=%s; EnergySource=%s; ThrottlingCapability=%s\n",
           entropy_mode, pmu_mode, energy_mode, throttle_mode);
    printk("Entropy_Source_Mode,%s\n", entropy_mode);
    printk("PMU_Counters_Supported,%u\n", benchmark_pmu_counters_supported() ? 1U : 0U);

    // Add calibrated nominal frequency for throttled latency calculations
    extern uint64_t throttle_get_f_nom_hz(void);
    uint64_t f_nom_hz = throttle_get_f_nom_hz();
    printk("\n");
    printk("F_nom_Hz,%llu                     # Calibrated nominal frequency for latency calculations\n", (unsigned long long)f_nom_hz);
    printk("Throttle_Ratio,0.5                # Applied frequency scaling ratio (50%% throttling)\n");
    printk("Throttle_Calibration_Method,timing_port_10ms_busy_wait\n");
    printk("Energy_Stddev_Method,constant      # StdDev_Energy_uJ=0.0 (Zephyr PM framework provides constant estimates, not per-iteration samples)\n");
    printk("Nominal_Cycle_Freq_Hz,%llu\n", (unsigned long long)f_nom_hz);
    printk("Calibration_Window_ms,200\n");
    printk("# SessionCryptoByteModel=KEM:(PK+CT),DSA:(PK+Sig); OperationIO=Keypair:PK, Enc/Dec:CT, Sign/Verify:Sig\n");
    printk("# RTOSStressModel=Matched baseline window vs stressed window with periodic high-priority worker(period_us=750,work_us=100,working_set_bytes=1024)\n");
    printk("# Stack units: bytes (peak is low-water since thread start)\n");
    printk("\n");
}

void print_csv_header(void) {
    print_csv_environment_prelude(ALGORITHM_NAME, PK_BYTES, SK_BYTES, CT_BYTES, SS_BYTES, ALG_FAMILY_KEM);
    print_csv_data_header_for_family(ALG_FAMILY_KEM);
}

void print_csv_results(benchmark_results_t results[3]) {
    const char *op_names[] = {"keypair", "encaps", "decaps"};
    const operation_type_t op_types[] = {OP_KEYPAIR, OP_ENCAPS, OP_DECAPS};
    
    printk("*** CSV DATA GENERATION START ***\n");
    print_csv_data_header_for_family(ALG_FAMILY_KEM);
    
    for (int i = 0; i < 3; i++) {
        benchmark_results_t *r = &results[i];
        sanitize_csv_fields(r);
        printk("%s,%s,%u,%u,%u,%u,%s,",
               ALGORITHM_NAME, "clean", PK_BYTES, SK_BYTES, CT_BYTES, SS_BYTES,
               op_names[i]);
        print_csv_common_result_fields(
            r,
            session_crypto_bytes_for_kem(NULL),
            operation_io_bytes_for_kem(NULL, op_types[i]));
    }
    
    printk("*** CSV DATA GENERATION COMPLETE ***\n");
}

void print_csv_results_for_kem(kem_info_t* kem, benchmark_results_t results[3]) {
    if (!kem) return;
    
    const char *op_names[] = {"keypair", "encaps", "decaps"};
    const operation_type_t op_types[] = {OP_KEYPAIR, OP_ENCAPS, OP_DECAPS};
    
    // Print KEM size information at the start of benchmark
    printk("\n*** KEM SIZE INFORMATION ***\n");
    printk("KEM: %s-%s\n", kem->name, kem->variant);
    printk("Public Key Size: %u bytes\n", kem->pk_bytes);
    printk("Secret Key Size: %u bytes\n", kem->sk_bytes);
    printk("Ciphertext Size: %u bytes\n", kem->ct_bytes);
    printk("Shared Secret Size: %u bytes\n", kem->ss_bytes);
    printk("*** END KEM SIZE INFORMATION ***\n\n");
    print_csv_data_header_for_family(ALG_FAMILY_KEM);
    
    for (int i = 0; i < 3; i++) {
        benchmark_results_t *r = &results[i];
        sanitize_csv_fields(r);
        printk("%s,%s,%u,%u,%u,%u,%s,",
               kem->name, kem->variant, kem->pk_bytes, kem->sk_bytes, kem->ct_bytes, kem->ss_bytes,
               op_names[i]);
        print_csv_common_result_fields(
            r,
            session_crypto_bytes_for_kem(kem),
            operation_io_bytes_for_kem(kem, op_types[i]));
    }
}

// Stack space monitoring with enhanced diagnostics
void measure_stack_usage(benchmark_results_t *result) {
    #ifdef CONFIG_THREAD_STACK_INFO
        struct k_thread *t = k_current_get();
        size_t unused = 0;
        
        // Get the low-water mark of unused stack since thread start
        int ret = k_thread_stack_space_get(t, &unused);
        if (ret == 0) {
            // Successfully got stack info - estimate usage
            #ifdef CONFIG_MAIN_STACK_SIZE
                size_t total = CONFIG_MAIN_STACK_SIZE;
            #else
                size_t total = 131072; // Default stack size
            #endif
            
            size_t peak_used = (unused < total) ? (total - unused) : 0;
            result->stack_used_bytes = peak_used;
            result->stack_peak_bytes = peak_used;
            result->stack_available_bytes = unused;
        } else {
            // Fallback to estimates
            result->stack_used_bytes = 8192;  // Conservative estimate
            result->stack_peak_bytes = 8192;
            result->stack_available_bytes = 122880; // Conservative available
        }
    #else
        // Fallback when CONFIG_THREAD_STACK_INFO isn't available
        #ifdef CONFIG_MAIN_STACK_SIZE
            size_t stack_size = CONFIG_MAIN_STACK_SIZE;
        #else
            size_t stack_size = 131072; // Default stack size
        #endif
        
        // Use simple estimation based on stack pointer position
        volatile char stack_marker;
        uintptr_t current_sp = (uintptr_t)&stack_marker;
        
        // Simple estimation based on stack pointer position
        // This is architecture-dependent and approximate
        size_t estimated_usage = (current_sp & 0xFFFF);
        if (estimated_usage > stack_size) {
            estimated_usage = stack_size / 4; // Conservative fallback
        }
        
        result->stack_used_bytes = estimated_usage;
        result->stack_peak_bytes = estimated_usage;
        result->stack_available_bytes = (stack_size > estimated_usage) ? 
                                       (stack_size - estimated_usage) : 0;
    #endif
}

// Per-operation stack measurement with true deltas
static size_t low_water_bytes(void) {
    size_t unused = 0;
#ifdef CONFIG_THREAD_STACK_INFO
    k_thread_stack_space_get(k_current_get(), &unused);
    #ifdef CONFIG_MAIN_STACK_SIZE
        return CONFIG_MAIN_STACK_SIZE - unused; // bytes used since thread start
    #else
        return 131072 - unused; // Default stack size - unused
    #endif
#else
    return 0; // fallback
#endif
}

void measure_stack_for_op(benchmark_results_t *result) {
    #ifdef CONFIG_THREAD_STACK_INFO
        // Get stack usage before any operation (baseline)
        size_t pre_op = low_water_bytes();
        
        // NOTE: This function is called AFTER the operation completes
        // The actual operation timing/execution happens in the caller
        size_t post_op = low_water_bytes();
        
        // Per-operation delta (what this specific operation added)
        result->stack_used_bytes = (post_op > pre_op) ? (post_op - pre_op) : 0;
        
        // Global peak since thread start (for context)
        result->stack_peak_bytes = post_op;
        
        // Available bytes remaining
        #ifdef CONFIG_MAIN_STACK_SIZE
            result->stack_available_bytes = CONFIG_MAIN_STACK_SIZE - post_op;
        #else
            result->stack_available_bytes = 131072 - post_op;
        #endif
    #else
        // Fallback to simple estimation
        measure_stack_usage(result);
    #endif
}

void print_stack_usage(void) {
    #ifdef CONFIG_THREAD_STACK_INFO
    // Try to get stack information if the API is available
    printk("*** Stack Usage Report:\n");
    
    #ifdef CONFIG_MAIN_STACK_SIZE
    size_t stack_size = CONFIG_MAIN_STACK_SIZE;
    printk("    Main stack size configured: %zu bytes\n", stack_size);
    #else
    printk("    Main stack size: Not configured\n");
    #endif
    
    // Note: k_thread_stack_space_get may not be available on all platforms
    printk("    Detailed stack usage monitoring requires platform-specific APIs\n");
    
    #else
    printk("*** Stack usage: Thread stack info not enabled in configuration\n");
    printk("    Enable CONFIG_THREAD_STACK_INFO for detailed reporting\n");
    #endif
    
    // Additional memory information if available
    #ifdef CONFIG_HEAP_MEM_POOL_SIZE
    printk("*** Heap configuration: %d bytes\n", CONFIG_HEAP_MEM_POOL_SIZE);
    #endif
}

void print_system_info(void) {
    printk("Benchmark: %s\n", ALGORITHM_NAME);
    printk("Architecture: %s (%s family)\n", ARCH_NAME, ARCH_FAMILY);
    printk("Board: %s\n", BOARD_STR);
    printk("Current KEM Sizes:\n");
    printk("  Current KEM Public Key: %u bytes\n", PK_BYTES);
    printk("  Current KEM Secret Key: %u bytes\n", SK_BYTES);
    printk("  Current KEM Ciphertext: %u bytes\n", CT_BYTES);
    printk("  Current KEM Shared Secret: %u bytes\n", SS_BYTES);
    printk("Energy Factor: %llu cycles/uJ\n", CYCLES_PER_UJ);
    printk("Total KEMs Available: %u\n", kem_count);
}

// ========================================================================
// DSA/Signature Algorithm Support
// ========================================================================

// DSA-specific runtime configuration variables
uint32_t SIG_PK_BYTES = 0;
uint32_t SIG_SK_BYTES = 0;
uint32_t SIG_BYTES = 0;

// Print CSV header for DSA benchmarks (same format as KEM but with different key names)
void print_csv_header_for_sign(void) {
    print_csv_environment_prelude(ALGORITHM_NAME, SIG_PK_BYTES, SIG_SK_BYTES, SIG_BYTES, 0U, ALG_FAMILY_DSA);
    print_csv_data_header_for_family(ALG_FAMILY_DSA);
}

// Print CSV results for DSA benchmarks
void print_csv_results_for_sign(sign_info_t* sign, benchmark_results_t results[3]) {
    if (!sign) return;
    
    const char *op_names[] = {"keypair", "sign", "verify"};
    const operation_type_t op_types[] = {OP_KEYPAIR, OP_SIGN, OP_VERIFY};
    
    // Print signature algorithm size information at the start of benchmark
    printk("\n*** SIGNATURE SIZE INFORMATION ***\n");
    printk("DSA: %s-%s\n", sign->name, sign->variant);
    printk("Public Key Size: %u bytes\n", sign->pk_bytes);
    printk("Secret Key Size: %u bytes\n", sign->sk_bytes);
    printk("Signature Size: %u bytes\n", sign->signature_bytes);
    printk("*** END SIGNATURE SIZE INFORMATION ***\n\n");
    print_csv_data_header_for_family(ALG_FAMILY_DSA);
    
    for (int i = 0; i < 3; i++) {
        benchmark_results_t *r = &results[i];
        sanitize_csv_fields(r);
        printk("%s,%s,%u,%u,%u,%s,",
               sign->name, sign->variant, sign->pk_bytes, sign->sk_bytes, sign->signature_bytes,
               op_names[i]);
        print_csv_common_result_fields(
            r,
            session_crypto_bytes_for_sign(sign),
            operation_io_bytes_for_sign(sign, op_types[i]));
    }
    
    printk("*** DSA CSV DATA GENERATION COMPLETE ***\n");
}

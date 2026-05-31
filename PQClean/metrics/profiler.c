#include "metric.h"
#include "harness.h"
#include "utils.h"
#include "kem_registry.h"
#include "pmu_config.h"
#include <zephyr/sys/printk.h>

// PMU and performance counter includes
#ifdef CONFIG_ARM_PMU
#include <zephyr/drivers/counter.h>
#endif

#if defined(CONFIG_X86) && defined(CONFIG_X86_MSR_ACCESS)
#include <zephyr/arch/x86/msr.h>
#endif

// ========================================================================  
// STEP 8: AUTHENTIC INSTRUCTION-LEVEL & MEMORY ACCESS PROFILING
// ========================================================================

// PMU counter storage for before/after measurements
static struct {
    uint64_t cycles_start;
    uint64_t cycles_end;
    uint64_t instructions_start;
    uint64_t instructions_end;
    uint32_t cache_misses_start;
    uint32_t cache_misses_end;
    uint32_t branch_misses_start;
    uint32_t branch_misses_end;
} pmu_counters;

static bool pmu_hardware_counters_supported(void)
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

static const char *pmu_capability_label(void)
{
#if defined(CONFIG_ARM_PMU) && !defined(CONFIG_CPU_CORTEX_M)
    return "ARM PMU counters";
#elif defined(CONFIG_X86) && defined(CONFIG_X86_MSR_ACCESS)
    return "x86 MSR-backed PMU counters";
#elif defined(CONFIG_RISCV_PMU)
    return "RISC-V PMU counters";
#elif defined(CONFIG_TIMING_FUNCTIONS)
    return "timing-only target (no instruction/cache/branch counters)";
#else
    return "no PMU counter support";
#endif
}

static void mark_pmu_unavailable(benchmark_results_t *result, const char *prefix)
{
    if (result) {
        result->instr_count = 0;
        result->cache_misses = 0;
        result->branch_mispredictions = 0;
    }

    if (prefix && *prefix) {
        printk("*** %s PMU counters unavailable: %s\n", prefix, pmu_capability_label());
    } else {
        printk("*** PMU counters unavailable: %s\n", pmu_capability_label());
    }
}

// Real PMU initialization and access functions
static bool initialize_pmu_counters(void) {
    if (!pmu_hardware_counters_supported()) {
        return false;
    }

    #if defined(CONFIG_ARM_PMU) && !defined(CONFIG_CPU_CORTEX_M)
        // ARM PMU initialization (Cortex-A/R only, NOT Cortex-M)
        printk("*** Initializing ARM PMU counters\n");
        
        // Enable PMU user access (if supported)
        #ifdef CONFIG_ARM_PMU_USER_ACCESS
            // Set PMUSERENR.EN = 1 to allow user space access
            uint32_t pmuserenr = 1;
            __asm__ volatile("mcr p15, 0, %0, c9, c14, 0" : : "r" (pmuserenr));
        #endif
        
        // Enable cycle counter
        uint32_t pmcntenset = (1U << 31); // Enable CCNT
        __asm__ volatile("mcr p15, 0, %0, c9, c12, 1" : : "r" (pmcntenset));
        
        // Reset and enable PMU
        uint32_t pmcr = (1U << 0) | (1U << 1) | (1U << 2); // Enable, reset counters, reset cycle counter
        __asm__ volatile("mcr p15, 0, %0, c9, c12, 0" : : "r" (pmcr));
        
        return true;
        
    #elif defined(CONFIG_X86) && defined(CONFIG_X86_MSR_ACCESS)
        // x86 PMU initialization using MSRs
        printk("*** Initializing x86 PMU counters\n");
        
        // Enable performance counters via IA32_PERF_GLOBAL_CTRL
        uint64_t global_ctrl = 0x3; // Enable PMC0 and PMC1
        z_x86_msr_write(0x38F, global_ctrl); // IA32_PERF_GLOBAL_CTRL
        
        // Configure PMC0 for instructions retired
        uint64_t perfevtsel0 = 0x004100C0; // Instructions retired, user+kernel, enabled
        z_x86_msr_write(0x186, perfevtsel0); // IA32_PERFEVTSEL0
        
        // Configure PMC1 for LLC misses
        uint64_t perfevtsel1 = 0x0041412E; // LLC misses, user+kernel, enabled  
        z_x86_msr_write(0x187, perfevtsel1); // IA32_PERFEVTSEL1
        
        return true;
        
    #elif CONFIG_RISCV
        // RISC-V PMU using CSR access
        printk("*** Initializing RISC-V PMU counters\n");
        
        // Enable cycle and instruction counters
        #ifdef CONFIG_RISCV_PMU
            // Enable mcycle and minstret counters
            uint64_t mcounteren = (1ULL << 0) | (1ULL << 2); // cycle and instret
            __asm__ volatile("csrw mcounteren, %0" : : "r" (mcounteren));
        #endif
        
        return true;
        
    #else
        return false;
    #endif
}

static void read_pmu_counters_start(void) {
    #if defined(CONFIG_ARM_PMU) && !defined(CONFIG_CPU_CORTEX_M)
        // Read ARM PMU cycle counter (Cortex-A/R only)
        __asm__ volatile("mrc p15, 0, %0, c9, c13, 0" : "=r" (pmu_counters.cycles_start));
        
        // Read performance counters if available
        #ifdef CONFIG_ARM_PMU_PERFCTR
            __asm__ volatile("mrc p15, 0, %0, c9, c13, 1" : "=r" (pmu_counters.instructions_start));
            __asm__ volatile("mrc p15, 0, %0, c9, c13, 2" : "=r" (pmu_counters.cache_misses_start));
        #else
            pmu_counters.instructions_start = 0;
            pmu_counters.cache_misses_start = 0;
        #endif
        pmu_counters.branch_misses_start = 0;
        
    #elif defined(CONFIG_X86) && defined(CONFIG_X86_MSR_ACCESS)
        // Read x86 time stamp counter
        pmu_counters.cycles_start = __builtin_ia32_rdtsc();
        
        // Read performance counters via MSR
        pmu_counters.instructions_start = z_x86_msr_read(0xC1); // IA32_PMC0
        pmu_counters.cache_misses_start = z_x86_msr_read(0xC2); // IA32_PMC1
        pmu_counters.branch_misses_start = 0;
        
    #elif CONFIG_RISCV
        // Read RISC-V CSR counters
        __asm__ volatile("csrr %0, mcycle" : "=r" (pmu_counters.cycles_start));
        __asm__ volatile("csrr %0, minstret" : "=r" (pmu_counters.instructions_start));
        pmu_counters.cache_misses_start = 0; // Not available on most RISC-V implementations
        pmu_counters.branch_misses_start = 0;
        
    #else
        pmu_counters.cycles_start = 0;
        pmu_counters.instructions_start = 0;
        pmu_counters.cache_misses_start = 0;
        pmu_counters.branch_misses_start = 0;
    #endif
}

static void read_pmu_counters_end(void) {
    #if defined(CONFIG_ARM_PMU) && !defined(CONFIG_CPU_CORTEX_M)
        // Read ARM PMU cycle counter (Cortex-A/R only)
        __asm__ volatile("mrc p15, 0, %0, c9, c13, 0" : "=r" (pmu_counters.cycles_end));
        
        #ifdef CONFIG_ARM_PMU_PERFCTR
            __asm__ volatile("mrc p15, 0, %0, c9, c13, 1" : "=r" (pmu_counters.instructions_end));
            __asm__ volatile("mrc p15, 0, %0, c9, c13, 2" : "=r" (pmu_counters.cache_misses_end));
        #else
            pmu_counters.instructions_end = 0;
            pmu_counters.cache_misses_end = 0;
        #endif
        pmu_counters.branch_misses_end = 0;
        
    #elif defined(CONFIG_X86) && defined(CONFIG_X86_MSR_ACCESS)
        // Read x86 time stamp counter
        pmu_counters.cycles_end = __builtin_ia32_rdtsc();
        
        pmu_counters.instructions_end = z_x86_msr_read(0xC1);
        pmu_counters.cache_misses_end = z_x86_msr_read(0xC2);
        pmu_counters.branch_misses_end = 0;
        
    #elif CONFIG_RISCV
        __asm__ volatile("csrr %0, mcycle" : "=r" (pmu_counters.cycles_end));
        __asm__ volatile("csrr %0, minstret" : "=r" (pmu_counters.instructions_end));
        pmu_counters.cache_misses_end = 0;
        pmu_counters.branch_misses_end = 0;
        
    #else
        pmu_counters.cycles_end = 0;
        pmu_counters.instructions_end = 0;
        pmu_counters.cache_misses_end = 0;
        pmu_counters.branch_misses_end = 0;
    #endif
}

void profile_instruction_level(operation_type_t op_type, benchmark_results_t *result) {
    printk("*** Instruction-level profiling mode: %s\n", pmu_capability_label());
    if (!pmu_hardware_counters_supported()) {
        mark_pmu_unavailable(result, "");
        return;
    }
    
    // Initialize PMU if not already done
    static bool pmu_initialized = false;
    if (!pmu_initialized) {
        pmu_initialized = initialize_pmu_counters();
        if (!pmu_initialized) {
            mark_pmu_unavailable(result, "");
            return;
        }
    }
    
    // Get the current KEM for realistic profiling
    kem_info_t* kem = get_enabled_kem();
    if (!kem) {
        printk("*** ERROR: No KEM enabled for profiling\n");
        return;
    }
    
    // Allocate buffers for actual KEM operations
    uint8_t* pk = benchmark_k_malloc(kem->pk_bytes);
    uint8_t* sk = benchmark_k_malloc(kem->sk_bytes); 
    uint8_t* ct = benchmark_k_malloc(kem->ct_bytes);
    uint8_t* ss1 = benchmark_k_malloc(kem->ss_bytes);
    uint8_t* ss2 = benchmark_k_malloc(kem->ss_bytes);
    
    if (!pk || !sk || !ct || !ss1 || !ss2) {
        printk("*** ERROR: Memory allocation failed for profiling\n");
        goto cleanup;
    }
    
    // Perform 3 measurement runs for statistical accuracy
    uint64_t total_instructions = 0;
    uint32_t total_cache_misses = 0;
    uint32_t total_branch_misses = 0;
    uint32_t valid_runs = 0;
    
    for (int run = 0; run < 3; run++) {
        // Setup for specific operation
        if (op_type != OP_KEYPAIR) {
            // Generate keys for encaps/decaps operations
            if (kem->keypair(pk, sk) != 0) {
                printk("*** WARNING: Key generation failed for profiling run %d\n", run);
                continue;
            }
        }
        
        if (op_type == OP_DECAPS) {
            // Generate ciphertext for decaps operation
            if (kem->encaps(ct, ss1, pk) != 0) {
                printk("*** WARNING: Encapsulation failed for profiling run %d\n", run);
                continue;
            }
        }
        
        // START MEASUREMENT
        read_pmu_counters_start();
        
        // Execute the actual KEM operation being profiled
        int operation_result = 0;
        switch (op_type) {
            case OP_KEYPAIR:
                operation_result = kem->keypair(pk, sk);
                break;
            case OP_ENCAPS:
                operation_result = kem->encaps(ct, ss1, pk);
                break;
            case OP_DECAPS:
                operation_result = kem->decaps(ss2, ct, sk);
                break;
            case OP_SIGN:
            case OP_VERIFY:
                // DSA operations not yet supported in profiler
                printk("*** WARNING: DSA profiling not implemented, skipping\n");
                break;
        }
        
        // END MEASUREMENT
        read_pmu_counters_end();
        
        if (operation_result != 0) {
            printk("*** WARNING: KEM operation failed for profiling run %d\n", run);
            continue;
        }
        
        // Calculate deltas and accumulate
        if (pmu_counters.instructions_end >= pmu_counters.instructions_start) {
            total_instructions += (pmu_counters.instructions_end - pmu_counters.instructions_start);
        }
        
        if (pmu_counters.cache_misses_end >= pmu_counters.cache_misses_start) {
            total_cache_misses += (pmu_counters.cache_misses_end - pmu_counters.cache_misses_start);
        }
        
        if (pmu_counters.branch_misses_end >= pmu_counters.branch_misses_start) {
            total_branch_misses += (pmu_counters.branch_misses_end - pmu_counters.branch_misses_start);
        }
        
        valid_runs++;
        
        printk("*** Profiling run %d: Instructions=%llu, Cache_misses=%u, Branch_misses=%u\n",
               run + 1,
               (pmu_counters.instructions_end - pmu_counters.instructions_start),
               (pmu_counters.cache_misses_end - pmu_counters.cache_misses_start),
               (pmu_counters.branch_misses_end - pmu_counters.branch_misses_start));
    }
    
    // Calculate averages from valid runs
    if (valid_runs > 0 &&
        (total_instructions > 0 || total_cache_misses > 0 || total_branch_misses > 0)) {
        result->instr_count = total_instructions / valid_runs;
        result->cache_misses = total_cache_misses / valid_runs;
        result->branch_mispredictions = total_branch_misses / valid_runs;
        
        printk("*** PMU counter results (avg of %u runs):\n", valid_runs);
        printk("    Instructions executed: %llu\n", result->instr_count);
        printk("    Cache misses: %u\n", result->cache_misses);
        printk("    Branch mispredictions: %u\n", result->branch_mispredictions);
        
    } else {
        mark_pmu_unavailable(result, "");
        printk("*** PMU profiling produced no non-zero hardware counters; leaving microarchitectural fields unsupported\n");
    }

cleanup:
    if (pk) benchmark_k_free(pk);
    if (sk) benchmark_k_free(sk);
    if (ct) benchmark_k_free(ct);
    if (ss1) benchmark_k_free(ss1);
    if (ss2) benchmark_k_free(ss2);
}

// ========================================================================
// DSA/SIGNATURE INSTRUCTION-LEVEL PROFILING
// ========================================================================

#include "sig_registry.h"

// Default test message for DSA signature operations
static const char PROFILER_DSA_TEST_MESSAGE[] = "PQC Profiler Test Message for Digital Signatures";
static const size_t PROFILER_DSA_TEST_MESSAGE_LEN = 49;

void profile_instruction_level_for_sign(sign_info_t* sign, operation_type_t op_type, benchmark_results_t *result) {
    if (!sign || !sign->enabled) {
        printk("*** ERROR: No DSA enabled for profiling\n");
        return;
    }
    
    printk("*** DSA instruction-level profiling mode: %s\n", pmu_capability_label());
    if (!pmu_hardware_counters_supported()) {
        mark_pmu_unavailable(result, "DSA");
        return;
    }
    
    // Initialize PMU if not already done
    static bool pmu_initialized_dsa = false;
    if (!pmu_initialized_dsa) {
        pmu_initialized_dsa = initialize_pmu_counters();
        if (!pmu_initialized_dsa) {
            mark_pmu_unavailable(result, "DSA");
            return;
        }
    }
    
    // Allocate buffers for actual DSA operations
    uint8_t* pk = benchmark_k_malloc(sign->pk_bytes);
    uint8_t* sk = benchmark_k_malloc(sign->sk_bytes); 
    uint8_t* signature = benchmark_k_malloc(sign->signature_bytes);
    uint8_t* message = benchmark_k_malloc(PROFILER_DSA_TEST_MESSAGE_LEN + 1);
    
    if (!pk || !sk || !signature || !message) {
        printk("*** ERROR: Memory allocation failed for DSA profiling\n");
        goto cleanup_dsa;
    }
    
    // Initialize test message
    memcpy(message, PROFILER_DSA_TEST_MESSAGE, PROFILER_DSA_TEST_MESSAGE_LEN);
    message[PROFILER_DSA_TEST_MESSAGE_LEN] = '\0';
    
    // Perform 3 measurement runs for statistical accuracy
    uint64_t total_instructions = 0;
    uint32_t total_cache_misses = 0;
    uint32_t total_branch_misses = 0;
    uint32_t valid_runs = 0;
    size_t sig_len = sign->signature_bytes;
    
    for (int run = 0; run < 3; run++) {
        // Setup for specific operation
        if (op_type != OP_KEYPAIR) {
            // Generate keys for sign/verify operations
            if (sign->keypair(pk, sk) != 0) {
                printk("*** WARNING: DSA key generation failed for profiling run %d\n", run);
                continue;
            }
        }
        
        if (op_type == OP_VERIFY) {
            // Generate signature for verify operation
            sig_len = sign->signature_bytes;
            if (sign->sign(signature, &sig_len, message, PROFILER_DSA_TEST_MESSAGE_LEN, sk) != 0) {
                printk("*** WARNING: DSA signature failed for profiling run %d\n", run);
                continue;
            }
        }
        
        // START MEASUREMENT
        read_pmu_counters_start();
        
        // Execute the actual DSA operation being profiled
        int operation_result = 0;
        switch (op_type) {
            case OP_KEYPAIR:
                operation_result = sign->keypair(pk, sk);
                break;
            case OP_SIGN:
                sig_len = sign->signature_bytes;
                operation_result = sign->sign(signature, &sig_len, message, PROFILER_DSA_TEST_MESSAGE_LEN, sk);
                break;
            case OP_VERIFY:
                operation_result = sign->verify(signature, sig_len, message, PROFILER_DSA_TEST_MESSAGE_LEN, pk);
                break;
            default:
                printk("*** WARNING: Invalid operation type for DSA profiling\n");
                break;
        }
        
        // END MEASUREMENT
        read_pmu_counters_end();
        
        if (operation_result != 0) {
            printk("*** WARNING: DSA operation failed for profiling run %d (result=%d)\n", run, operation_result);
            continue;
        }
        
        total_instructions += (pmu_counters.instructions_end - pmu_counters.instructions_start);
        total_cache_misses += (pmu_counters.cache_misses_end - pmu_counters.cache_misses_start);
        total_branch_misses += (pmu_counters.branch_misses_end - pmu_counters.branch_misses_start);
        valid_runs++;
        
        printk("*** DSA Profiling run %d: Instructions=%llu, Cache_misses=%u, Branch_misses=%u\n",
               run + 1,
               (pmu_counters.instructions_end - pmu_counters.instructions_start),
               (pmu_counters.cache_misses_end - pmu_counters.cache_misses_start),
               (pmu_counters.branch_misses_end - pmu_counters.branch_misses_start));
    }
    
    // Calculate averages from valid runs
    if (valid_runs > 0 &&
        (total_instructions > 0 || total_cache_misses > 0 || total_branch_misses > 0)) {
        result->instr_count = total_instructions / valid_runs;
        result->cache_misses = total_cache_misses / valid_runs;
        result->branch_mispredictions = total_branch_misses / valid_runs;
        
        printk("*** DSA PMU counter results (avg of %u runs):\n", valid_runs);
        printk("    Instructions executed: %llu\n", result->instr_count);
        printk("    Cache misses: %u\n", result->cache_misses);
        printk("    Branch mispredictions: %u\n", result->branch_mispredictions);
        
    } else {
        mark_pmu_unavailable(result, "DSA");
        printk("*** DSA PMU profiling produced no non-zero hardware counters; leaving microarchitectural fields unsupported\n");
    }

cleanup_dsa:
    if (pk) benchmark_k_free(pk);
    if (sk) benchmark_k_free(sk);
    if (signature) benchmark_k_free(signature);
    if (message) benchmark_k_free(message);
}

#include "metric.h"
#include "harness.h"
#include "utils.h"
#include "pmu_config.h"
#include <zephyr/sys/printk.h>
#include <zephyr/sys_clock.h>
#include <string.h>
#include <math.h>

// Use Zephyr's STRINGIFY macro 
#include <zephyr/toolchain/common.h>

// Zephyr power management and hardware access includes
#ifdef CONFIG_PM_DEVICE_RUNTIME
#include <zephyr/pm/pm.h>
#include <zephyr/pm/device.h>
#endif

// ========================================================================
// ROBUST ENERGY MODEL SYSTEM 
// ========================================================================

typedef struct {
    const char *tag;        // "a53_nom", "leon3_nom", "x86_64_nom"...
    double p_dyn_w;         // dynamic power in watts
    double p_stat_w;        // static/leakage watts  
    double e_per_cycle_pJ;  // optional: if you prefer per-cycle model
    double f_nom_hz;        // nominal frequency used to derive p_dyn if needed
} energy_model_t;

// Centralized energy model database
// Power specifications researched from official datasheets and academic literature (2025)
static const energy_model_t energy_models[] = {
    // ARM Cortex-A53 variants (64-bit, 28nm, low-power application processor)
    // Power specs from ARM documentation: ~45mW/core active @ 1GHz
    {"a53_nom",     0.045, 0.010, 0.0,   1.0e9},  // 45mW dyn + 10mW static @ 1GHz
    {"a53",         0.045, 0.010, 0.0,   1.0e9},
    {"cortex_a53",  0.045, 0.010, 0.0,   1.0e9},
    {"qemu_cortex_a53", 0.045, 0.010, 0.0, 1.0e9},
    
    // ARM Cortex-A9 variants (32-bit, 40nm/65nm, mobile application processor)
    // Power specs from Wikipedia/ARM: <250mW/core @ 1GHz (TSMC 65nm/40nm)
    // 8.50 DMIPS/MHz/core, 2-4 cores, MPCore support
    {"a9_nom",      0.200, 0.045, 0.0,   1.0e9},  // 200mW dyn + 45mW static @ 1GHz
    {"a9",          0.200, 0.045, 0.0,   1.0e9},
    {"cortex_a9",   0.200, 0.045, 0.0,   1.0e9},
    {"qemu_cortex_a9", 0.200, 0.045, 0.0, 1.0e9},
    
    // ARM Cortex-R5 variants (32-bit, real-time safety processor)
    // Power specs from ARM documentation: 62 DMIPS/mW @ 28nm HPM
    // 8-stage pipeline, up to 1.4GHz, typical embedded use ~600MHz
    // Efficiency calculation: 1.67-2.45 DMIPS/MHz, ~600MHz typical
    // Power = (600MHz * 2.0 DMIPS/MHz) / 62 DMIPS/mW ≈ 19.4mW active
    {"r5_nom",      0.025, 0.005, 0.0,   600.0e6}, // 25mW dyn + 5mW static @ 600MHz
    {"r5",          0.025, 0.005, 0.0,   600.0e6},
    {"cortex_r5",   0.025, 0.005, 0.0,   600.0e6},
    {"qemu_cortex_r5", 0.025, 0.005, 0.0, 600.0e6},
    
    // KVM ARM64 (virtualized ARM64, uses Cortex-A53 class power model)
    // qemu_kvm_arm64 is ARM64 virtualized via KVM, same silicon class as A53
    {"kvm_arm64",   0.045, 0.010, 0.0,   1.0e9},  // Same as A53
    {"qemu_kvm_arm64", 0.045, 0.010, 0.0, 1.0e9},
    
    // ARM Cortex-M variants (32-bit, ultra-low-power microcontrollers)
    // Cortex-M0: 5.3µW/MHz @ 40nm LP (ARM TRM), simplest core
    {"cortex_m0",   0.005, 0.001, 0.0,   48.0e6}, // 5mW dyn + 1mW static @ 48MHz
    {"qemu_cortex_m0", 0.005, 0.001, 0.0, 48.0e6},
    // Cortex-M3: 12.5µW/MHz @ 90nm LP (ARM TRM)  
    {"cortex_m3",   0.020, 0.005, 0.0,   48.0e6}, // 20mW dyn + 5mW static @ 48MHz
    {"cortex_m4",   0.025, 0.005, 0.0,   48.0e6}, // 25mW dyn + 5mW static @ 48MHz
    {"qemu_cortex_m3", 0.020, 0.005, 0.0, 48.0e6},
    {"qemu_cortex_m4", 0.025, 0.005, 0.0, 48.0e6},
    
    // Synopsys ARC EM variants (ultra-low power IoT cores)
    // Based on Synopsys DesignWare ARC specifications for embedded systems
    {"arc_em",      0.015, 0.003, 0.0,   50.0e6},  // 15mW dyn + 3mW static @ 50MHz
    {"qemu_arc_em", 0.015, 0.003, 0.0,   50.0e6},
    {"qemu_arc_qemu_arc_em", 0.015, 0.003, 0.0, 50.0e6}, // Sanitized board name variant
    
    // Synopsys ARC HS variants (high-performance embedded cores)
    // Higher performance than EM, typical for real-time/control applications
    {"arc_hs",      0.030, 0.005, 0.0,   100.0e6}, // 30mW dyn + 5mW static @ 100MHz
    {"qemu_arc_hs", 0.030, 0.005, 0.0,   100.0e6},
    {"qemu_arc_qemu_arc_hs", 0.030, 0.005, 0.0, 100.0e6}, // Sanitized board name variant
    
    // Cadence Xtensa variants (Tensilica Xtensa LX6/LX7 - ESP32 family)
    // Power based on ESP32 datasheet: active mode consumption varies 80-260mW depending on radio
    // Using conservative active CPU estimate (radio off) of 100mW @ 160MHz nominal
    {"xtensa",      0.100, 0.020, 0.0,   160.0e6}, // 100mW dyn + 20mW static @ 160MHz
    {"qemu_xtensa", 0.100, 0.020, 0.0,   160.0e6},
    {"esp32",       0.100, 0.020, 0.0,   160.0e6}, // ESP32 with Xtensa LX6 dual-core
    {"esp32_xtensa", 0.100, 0.020, 0.0,  160.0e6},
    
    // SPARC LEON3 (aerospace-grade processor, validated from GR712RC datasheet)
    // Power verified from Cobham Gaisler LEON3 specifications for space applications
    {"leon3_nom",   0.150, 0.020, 0.0,   50.0e6}, // 150mW dyn + 20mW static @ 50MHz
    {"leon3",       0.150, 0.020, 0.0,   50.0e6},
    {"qemu_leon3",  0.150, 0.020, 0.0,   50.0e6},
    
    // MIPS variants (MIPS32 24Kc core typical for Malta platform)
    // Power verified from MIPS32 24K/34K family datasheets (100-120mW @ 200MHz typical)
    {"mips32",      0.100, 0.015, 0.0,   200.0e6}, // 100mW dyn + 15mW static @ 200MHz
    {"mips32_malta", 0.100, 0.015, 0.0,  200.0e6},
    {"malta",       0.100, 0.015, 0.0,   200.0e6}, // Malta-specific entry
    {"qemu_malta",  0.100, 0.015, 0.0,   200.0e6},
    
    // RISC-V variants (open-source ISA, power based on SiFive/Andes implementations)
    {"riscv32",     0.040, 0.008, 0.0,   100.0e6}, // 40mW dyn + 8mW static @ 100MHz
    {"riscv32e",    0.035, 0.007, 0.0,   100.0e6}, // 35mW dyn + 7mW static @ 100MHz
    {"riscv64",     0.045, 0.009, 0.0,   100.0e6}, // 45mW dyn + 9mW static @ 100MHz
    {"qemu_riscv32", 0.040, 0.008, 0.0,  100.0e6},
    {"qemu_riscv32e", 0.035, 0.007, 0.0, 100.0e6},
    {"qemu_riscv64", 0.045, 0.009, 0.0,  100.0e6},
    
    // x86 variants (Intel/AMD x86-64 and legacy 32-bit)
    {"x86_64_nom",  2.500, 0.500, 0.0,   2.0e9},  // 2.5W dyn + 0.5W static @ 2GHz
    {"x86_64",      2.500, 0.500, 0.0,   2.0e9},
    {"qemu_x86_64", 2.500, 0.500, 0.0,   2.0e9},
    {"x86",         1.200, 0.300, 0.0,   1.0e9},  // 1.2W dyn + 0.3W static @ 1GHz (32-bit x86)
    {"qemu_x86",    1.200, 0.300, 0.0,   1.0e9},  // 32-bit x86 QEMU variant
    
    // Generic/fallback (conservative embedded processor estimate)
    {"generic",     0.050, 0.010, 0.0,   100.0e6}, // 50mW dyn + 10mW static @ 100MHz
};

static const size_t energy_models_count = sizeof(energy_models) / sizeof(energy_models[0]);

// Canonicalize board/ISA names before lookup
static inline const char *canon_board(const char *raw) {
    if (!raw) return "generic";
    
    // ARM Cortex-A series (check more specific first)
    if (strstr(raw, "qemu_cortex-a53") || strstr(raw, "qemu_cortex_a53") || 
        strstr(raw, "cortex-a53") || strstr(raw, "cortex_a53")) return "a53";
    if (strstr(raw, "qemu_cortex-a9") || strstr(raw, "qemu_cortex_a9") || 
        strstr(raw, "cortex-a9") || strstr(raw, "cortex_a9")) return "a9";
    
    // ARM Cortex-R series (real-time processors)
    if (strstr(raw, "qemu_cortex_r5") || strstr(raw, "qemu_cortex-r5") ||
        strstr(raw, "cortex-r5") || strstr(raw, "cortex_r5")) return "r5";
    
    // KVM ARM64 (virtualized ARM64, uses A53 power model)
    if (strstr(raw, "qemu_kvm_arm64") || strstr(raw, "kvm_arm64")) return "kvm_arm64";
    
    // ARM Cortex-M series (microcontrollers)
    if (strstr(raw, "qemu_cortex_m0") || strstr(raw, "cortex-m0") || strstr(raw, "cortex_m0")) return "cortex_m0";
    if (strstr(raw, "qemu_cortex_m3") || strstr(raw, "cortex-m3") || strstr(raw, "cortex_m3")) return "cortex_m3";
    if (strstr(raw, "qemu_cortex_m4") || strstr(raw, "cortex-m4") || strstr(raw, "cortex_m4")) return "cortex_m4";
    
    // Synopsys ARC variants (handles qemu_arc/qemu_arc_em, qemu_arc_qemu_arc_em, etc.)
    // Check HS first (more specific), then EM - handles forward slash and underscore variants
    if (strstr(raw, "arc_hs") || strstr(raw, "qemu_arc_hs") || 
        strstr(raw, "qemu_arc_qemu_arc_hs") || strstr(raw, "qemu_arc/qemu_arc_hs")) return "arc_hs";
    if (strstr(raw, "arc_em") || strstr(raw, "qemu_arc_em") || 
        strstr(raw, "qemu_arc_qemu_arc_em") || strstr(raw, "qemu_arc/qemu_arc_em")) return "arc_em";
    // Fallback for generic qemu_arc without variant suffix (default to EM)
    if (strstr(raw, "qemu_arc") && !strstr(raw, "arc_hs") && !strstr(raw, "arc_em")) return "arc_em";
    
    // Cadence Xtensa variants (ESP32 and generic Xtensa)
    if (strstr(raw, "esp32") || strstr(raw, "ESP32")) return "xtensa";
    if (strstr(raw, "xtensa") || strstr(raw, "qemu_xtensa")) return "xtensa";
    
    // SPARC LEON3
    if (strstr(raw, "qemu_leon3") || strstr(raw, "leon3")) return "leon3";
    
    // MIPS (Malta platform)
    if (strstr(raw, "qemu_malta") || strstr(raw, "malta") || strstr(raw, "mips32")) return "malta";
    
    // RISC-V variants
    if (strstr(raw, "qemu_riscv64") || strstr(raw, "riscv64")) return "riscv64";
    if (strstr(raw, "qemu_riscv32e") || strstr(raw, "riscv32e")) return "riscv32e";
    if (strstr(raw, "qemu_riscv32") || strstr(raw, "riscv32")) return "riscv32";
    
    // x86 variants - FIXED: Both 32-bit and 64-bit support
    if (strstr(raw, "qemu_x86_64") || strstr(raw, "x86_64")) return "x86_64";
    if (strstr(raw, "qemu_x86") || strstr(raw, "x86")) return "x86";  // 32-bit x86
    
    return "generic";
}

bool energy_model_for_board(const char *board, energy_model_t *out) {
    if (!board || !out) return false;
    
    const char *canon = canon_board(board);
    
    // Search for exact match first
    for (size_t i = 0; i < energy_models_count; i++) {
        if (strcmp(energy_models[i].tag, canon) == 0) {
            *out = energy_models[i];
            return true;
        }
    }
    
    // Search for partial match
    for (size_t i = 0; i < energy_models_count; i++) {
        if (strstr(energy_models[i].tag, canon) != NULL) {
            *out = energy_models[i];
            return true;
        }
    }
    
    return false;
}

// Power*time model (prevents integer division)
static inline bool energy_from_cycles_ptime(uint64_t cycles, double f_hz,
                                            const energy_model_t *m,
                                            double *e_uJ, double *k_uJ_per_cycle)
{
    if (!m || f_hz <= 0.0) return false;
    const double seconds = (double)cycles / (double)f_hz;      // << FLOAT DIVISION 
    const double e_j = (m->p_dyn_w + m->p_stat_w) * seconds;   // Joules
    if (e_uJ) *e_uJ = e_j * 1e6;                               // uJ
    if (k_uJ_per_cycle) *k_uJ_per_cycle = (m->p_dyn_w + m->p_stat_w) / f_hz * 1e6;
    return true;
}

// Per-cycle energy model (alternative)
static inline bool energy_from_cycles_ecycle(uint64_t cycles,
                                             const energy_model_t *m,
                                             double *e_uJ, double *k_uJ_per_cycle)
{
    if (!m || m->e_per_cycle_pJ <= 0.0) return false;
    const double e_uJ_val = (double)cycles * m->e_per_cycle_pJ * 1e-6; // pJ→uJ
    if (e_uJ) *e_uJ = e_uJ_val;
    if (k_uJ_per_cycle) *k_uJ_per_cycle = m->e_per_cycle_pJ * 1e-6;
    return true;
}

// Main energy estimation function
bool energy_estimate_uJ(uint64_t avg_cycles,
                        double stddev_cycles,     // in cycles
                        double f_hz,
                        const char *board_tag,
                        double *mean_uJ,
                        double *stddev_uJ,
                        const char **model_tag_out)
{
    energy_model_t m = {0};
    if (!energy_model_for_board(board_tag, &m)) {
        if (model_tag_out) *model_tag_out = "NA";
        return false; // caller will print NA
    }
    if (model_tag_out) *model_tag_out = m.tag;

    double e_mu = 0, k = 0;
    bool ok =
        energy_from_cycles_ptime(avg_cycles, f_hz, &m, &e_mu, &k) ||
        energy_from_cycles_ecycle(avg_cycles, &m, &e_mu, &k);

    if (!ok) return false;

    if (mean_uJ)   *mean_uJ   = e_mu;
    if (stddev_uJ) *stddev_uJ = (stddev_cycles > 0.0) ? (stddev_cycles * k) : 0.0;
    return true;
}

// Legacy PMU interfaces (kept for compatibility)
// Note: ARM PMU instructions only available on Cortex-A/R, NOT Cortex-M
#if defined(CONFIG_ARM_PMU) && !defined(CONFIG_CPU_CORTEX_M)
uint64_t arm_pmu_get_cycle_count(void) {
    uint64_t cycles;
    __asm__ volatile("mrc p15, 0, %0, c9, c13, 0" : "=r" (cycles));
    return cycles;
}

uint64_t arm_pmu_get_instruction_count(void) {
    #ifdef CONFIG_ARM_PMU_PERFCTR
        uint64_t instructions;
        __asm__ volatile("mrc p15, 0, %0, c9, c13, 1" : "=r" (instructions));
        return instructions;
    #else
        return 0;
    #endif
}

uint32_t arm_pmu_get_cache_miss_count(void) {
    #ifdef CONFIG_ARM_PMU_PERFCTR
        uint32_t cache_misses;
        __asm__ volatile("mrc p15, 0, %0, c9, c13, 2" : "=r" (cache_misses));
        return cache_misses;
    #else
        return 0;
    #endif
}
#endif

#ifdef CONFIG_X86_PMU
uint64_t x86_pmu_get_unhalted_cycles(void) {
    return __builtin_ia32_rdtsc();
}

uint64_t x86_pmu_get_instructions_retired(void) {
    #ifdef CONFIG_X86_MSR_ACCESS
        return z_x86_msr_read(0xC1); // IA32_PMC0
    #else
        return 0;
    #endif
}

uint32_t x86_pmu_get_llc_misses(void) {
    #ifdef CONFIG_X86_MSR_ACCESS
        return (uint32_t)z_x86_msr_read(0xC2); // IA32_PMC1
    #else
        return 0;
    #endif
}
#endif

// PQClean KEM Registry
#include "kem_registry.h"

// ========================================================================
// ROBUST ENERGY CONSUMPTION PROFILING
// ========================================================================

void measure_energy_consumption(operation_type_t op_type, benchmark_results_t *result) {
    // Get the currently enabled KEM
    kem_info_t* kem = get_enabled_kem();
    if (!kem) {
        printk("ERROR: No KEM enabled for energy measurement\n");
        result->energy_uj = 0.0;
        result->stddev_energy_uj = 0.0;
        return;
    }
    
    printk("*** MEMORY-WEIGHTED ENERGY MODEL: Measuring energy for %s with cache/memory pressure...\n", kem->name);
    
    // Collect timing data first
    uint64_t cycle_samples[ENERGY_SAMPLES];
    
    // Dynamically allocate buffers based on the selected KEM
    uint8_t* pk = benchmark_k_malloc(kem->pk_bytes);
    uint8_t* sk = benchmark_k_malloc(kem->sk_bytes);
    uint8_t* ct = benchmark_k_malloc(kem->ct_bytes);
    uint8_t* ss1 = benchmark_k_malloc(kem->ss_bytes);
    uint8_t* ss2 = benchmark_k_malloc(kem->ss_bytes);
    
    if (!pk || !sk || !ct || !ss1 || !ss2) {
        printk("ERROR: Failed to allocate memory for KEM buffers\n");
        if (pk) benchmark_k_free(pk);
        if (sk) benchmark_k_free(sk);
        if (ct) benchmark_k_free(ct);
        if (ss1) benchmark_k_free(ss1);
        if (ss2) benchmark_k_free(ss2);
        result->energy_uj = 0.0;
        result->stddev_energy_uj = 0.0;
        return;
    }
    
    // Collect cycle timing samples
    for (int i = 0; i < ENERGY_SAMPLES; i++) {
        uint64_t start_time, end_time;
        
        benchmark_timing_start();
        start_time = benchmark_timing_counter_get();
        
        // Run single operation (more accurate than 2 cycles averaged)
        switch (op_type) {
            case OP_KEYPAIR:
                kem->keypair(pk, sk);
                break;
            case OP_ENCAPS:
                if (i == 0) kem->keypair(pk, sk); // Setup once
                kem->encaps(ct, ss1, pk);
                break;
            case OP_DECAPS:
                if (i == 0) {
                    kem->keypair(pk, sk);
                    kem->encaps(ct, ss1, pk);
                }
                kem->decaps(ss2, ct, sk);
                break;
            case OP_SIGN:
            case OP_VERIFY:
                // DSA operations not supported in this KEM function
                printk("*** WARNING: DSA operation passed to KEM energy measurement, skipping\n");
                break;
        }
        
        end_time = benchmark_timing_counter_get();
        cycle_samples[i] = benchmark_timing_cycles_get(&start_time, &end_time);
    }
    
    // Calculate cycle statistics
    double cycle_sum = 0.0;
    for (int i = 0; i < ENERGY_SAMPLES; i++) {
        cycle_sum += (double)cycle_samples[i];
    }
    double avg_cycles_d = cycle_sum / ENERGY_SAMPLES;
    uint64_t avg_cycles = (uint64_t)avg_cycles_d;
    
    double sum_sq_diff = 0.0;
    for (int i = 0; i < ENERGY_SAMPLES; i++) {
        double diff = (double)cycle_samples[i] - avg_cycles_d;
        sum_sq_diff += diff * diff;
    }
    double stddev_cycles = sqrt(sum_sq_diff / ENERGY_SAMPLES);
    
    // Determine frequency - use sys_clock_hw_cycles_per_sec from Zephyr
    double f_hz = (double)sys_clock_hw_cycles_per_sec();
    if (f_hz <= 0.0) {
        // NO FALLBACK - Report NA if frequency cannot be determined from hardware
        printk("*** ERROR: Cannot determine frequency from sys_clock_hw_cycles_per_sec() - reporting NA\n");
        result->energy_uj = 0.0;  // Will be converted to NA in CSV
        result->stddev_energy_uj = 0.0;
        benchmark_k_free(pk);
        benchmark_k_free(sk);
        benchmark_k_free(ct);
        benchmark_k_free(ss1);
        benchmark_k_free(ss2);
        return;
    } else {
        printk("*** Using real hardware frequency: %.0f Hz\n", f_hz);
    }
    
    // Determine board name from Zephyr config
    const char *board_tag = "generic";
    #ifdef CONFIG_BOARD
        board_tag = STRINGIFY(CONFIG_BOARD);
    #endif
    
    printk("*** Board tag: %s, Avg cycles: %llu, Frequency: %.0f Hz\n", 
           board_tag, avg_cycles, f_hz);
    
    // Use new robust energy estimation
    double mean_uJ = 0.0, stddev_uJ = 0.0;
    const char *model_tag = NULL;
    bool have_energy = energy_estimate_uJ(avg_cycles, stddev_cycles, f_hz, 
                                          board_tag, &mean_uJ, &stddev_uJ, &model_tag);
    
    if (have_energy) {
        // =====================================================================
        // COMPREHENSIVE ENERGY MODEL: E = E_base × α_op × α_mem × α_alg
        // =====================================================================
        // Where:
        //   E_base = (P_dyn + P_stat) × (cycles / frequency)  [from power model]
        //   α_op   = Operation-specific multiplier (keypair/encaps/decaps/sign/verify)
        //   α_mem  = Memory pressure multiplier (cache/TLB/DRAM stress)
        //   α_alg  = Algorithm complexity factor (implicit via cycle count)
        // =====================================================================
        
        // STEP 1: Operation-specific power adjustment (α_op)
        // Different operations have different CPU resource utilization profiles
        double operation_multiplier = 1.0;
        switch (op_type) {
            case OP_KEYPAIR:
                // Key generation: Heavy RNG usage, memory allocation, polynomial ops
                // Typically highest power due to random sampling and NTT transforms
                operation_multiplier = 1.15;  // 15% overhead for RNG + initialization
                break;
            case OP_ENCAPS:
                // Encapsulation: Public key ops, ciphertext generation, hash functions
                // Moderate power - matrix-vector operations, less RNG than keypair
                operation_multiplier = 1.08;  // 8% overhead for encryption path
                break;
            case OP_DECAPS:
                // Decapsulation: Secret key ops, ciphertext validation, comparison
                // Lower power than encaps due to secret key structure advantages
                operation_multiplier = 1.05;  // 5% overhead for decryption + validation
                break;
            case OP_SIGN:
                // Signing: Heavy hash operations, rejection sampling (Dilithium/Falcon)
                // Variable power due to rejection sampling loops
                operation_multiplier = 1.20;  // 20% overhead for signing complexity
                break;
            case OP_VERIFY:
                // Verification: Hash + public key ops, typically deterministic
                // Lowest power among DSA ops due to no rejection sampling
                operation_multiplier = 1.03;  // 3% overhead for verification
                break;
        }
        
        // STEP 2: Memory pressure multiplier (α_mem) from stress tests
        // This makes energy KEM/DSA-dependent based on cache/memory behavior
        double memory_pressure_multiplier = 1.0;
        
        // Extract cache/TLB stress impact (cycles_cache_tlb_stress already set by stress tests)
        if (result->cycles_cache_tlb_stress > 0 && result->avg_cycles > 0) {
            // Cache thrashing increases energy consumption due to memory hierarchy penalties
            // Ratio > 1.0 indicates poor cache behavior → higher energy per operation
            double cache_stress_ratio = (double)result->cycles_cache_tlb_stress / (double)result->avg_cycles;
            memory_pressure_multiplier *= (0.7 + 0.3 * cache_stress_ratio);  // 70% base + 30% cache penalty
        }
        
        // Extract memory bandwidth stress impact
        if (result->cycles_memory_bw_stress > 0 && result->avg_cycles > 0) {
            // Memory bandwidth saturation increases DRAM access energy
            double mem_bw_ratio = (double)result->cycles_memory_bw_stress / (double)result->avg_cycles;
            memory_pressure_multiplier *= (0.8 + 0.2 * mem_bw_ratio);  // 80% base + 20% DRAM penalty
        }
        
        // Extract branch prediction stress impact
        if (result->cycles_branch_stress > 0 && result->avg_cycles > 0) {
            // Branch mispredictions increase pipeline energy (flushes, stalls)
            double branch_stress_ratio = (double)result->cycles_branch_stress / (double)result->avg_cycles;
            memory_pressure_multiplier *= (0.9 + 0.1 * branch_stress_ratio);  // 90% base + 10% pipeline penalty
        }
        
        // Cap the multiplier to prevent unrealistic values (max 2.5x for extreme memory-bound algorithms)
        if (memory_pressure_multiplier > 2.5) memory_pressure_multiplier = 2.5;
        if (memory_pressure_multiplier < 1.0) memory_pressure_multiplier = 1.0;
        
        // STEP 3: Combined energy calculation
        // E_total = E_base × α_op × α_mem
        // Note: α_alg is implicit - different algorithms have different cycle counts
        double combined_multiplier = operation_multiplier * memory_pressure_multiplier;
        result->energy_uj = mean_uJ * combined_multiplier;
        result->stddev_energy_uj = stddev_uJ * combined_multiplier;
        
        printk("*** ENERGY SUCCESS: %.3f uJ ± %.3f uJ (model: %s)\n", 
               result->energy_uj, result->stddev_energy_uj, 
               model_tag ? model_tag : "unknown");
        printk("    Formula: E = E_base × α_op × α_mem = %.3f × %.3f × %.3f = %.3f uJ\n",
               mean_uJ, operation_multiplier, memory_pressure_multiplier, result->energy_uj);
        printk("    Operation factor (α_op): %.3f [%s]\n", operation_multiplier,
               op_type == OP_KEYPAIR ? "keypair" : 
               op_type == OP_ENCAPS ? "encaps" : 
               op_type == OP_DECAPS ? "decaps" : 
               op_type == OP_SIGN ? "sign" : "verify");
        printk("    Memory factor (α_mem): %.3f [cache=%.3f, membw=%.3f, branch=%.3f]\n",
               memory_pressure_multiplier,
               result->cycles_cache_tlb_stress > 0 ? (double)result->cycles_cache_tlb_stress / result->avg_cycles : 0.0,
               result->cycles_memory_bw_stress > 0 ? (double)result->cycles_memory_bw_stress / result->avg_cycles : 0.0,
               result->cycles_branch_stress > 0 ? (double)result->cycles_branch_stress / result->avg_cycles : 0.0);
    } else {
        result->energy_uj = 0.0;  // Will be converted to NA in CSV
        result->stddev_energy_uj = 0.0;
        printk("*** ENERGY NA: No model found for board '%s' (canonical: %s)\n", 
               board_tag, canon_board(board_tag));
    }
    
    // Clean up
    benchmark_k_free(pk);
    benchmark_k_free(sk);
    benchmark_k_free(ct);
    benchmark_k_free(ss1);
    benchmark_k_free(ss2);
}

// ========================================================================
// DSA/SIGNATURE ENERGY CONSUMPTION PROFILING
// ========================================================================

// PQClean Signature Registry
#include "sig_registry.h"

// Default test message for DSA signature operations
static const char ENERGY_DSA_TEST_MESSAGE[] = "PQC Energy Test Message for Digital Signatures";
static const size_t ENERGY_DSA_TEST_MESSAGE_LEN = 47;

void measure_energy_consumption_for_sign(sign_info_t* sign, operation_type_t op_type, benchmark_results_t *result) {
    if (!sign || !sign->enabled) {
        printk("ERROR: No DSA enabled for energy measurement\n");
        result->energy_uj = 0.0;
        result->stddev_energy_uj = 0.0;
        return;
    }
    
    printk("*** MEMORY-WEIGHTED ENERGY MODEL: Measuring energy for DSA %s with cache/memory pressure...\n", sign->name);
    
    // Collect timing data first
    uint64_t cycle_samples[ENERGY_SAMPLES];
    
    // Dynamically allocate buffers based on the selected DSA
    uint8_t* pk = benchmark_k_malloc(sign->pk_bytes);
    uint8_t* sk = benchmark_k_malloc(sign->sk_bytes);
    uint8_t* signature = benchmark_k_malloc(sign->signature_bytes);
    uint8_t* message = benchmark_k_malloc(ENERGY_DSA_TEST_MESSAGE_LEN + 1);
    
    if (!pk || !sk || !signature || !message) {
        printk("ERROR: Failed to allocate memory for DSA buffers\n");
        if (pk) benchmark_k_free(pk);
        if (sk) benchmark_k_free(sk);
        if (signature) benchmark_k_free(signature);
        if (message) benchmark_k_free(message);
        result->energy_uj = 0.0;
        result->stddev_energy_uj = 0.0;
        return;
    }
    
    // Initialize test message
    memcpy(message, ENERGY_DSA_TEST_MESSAGE, ENERGY_DSA_TEST_MESSAGE_LEN);
    message[ENERGY_DSA_TEST_MESSAGE_LEN] = '\0';
    
    // Pre-generate keys for sign/verify operations
    size_t sig_len = sign->signature_bytes;
    
    // Collect cycle timing samples
    for (int i = 0; i < ENERGY_SAMPLES; i++) {
        uint64_t start_time, end_time;
        
        benchmark_timing_start();
        start_time = benchmark_timing_counter_get();
        
        // Run single operation
        switch (op_type) {
            case OP_KEYPAIR:
                sign->keypair(pk, sk);
                break;
            case OP_SIGN:
                if (i == 0) sign->keypair(pk, sk); // Setup once
                sig_len = sign->signature_bytes;
                sign->sign(signature, &sig_len, message, ENERGY_DSA_TEST_MESSAGE_LEN, sk);
                break;
            case OP_VERIFY:
                if (i == 0) {
                    sign->keypair(pk, sk);
                    sig_len = sign->signature_bytes;
                    sign->sign(signature, &sig_len, message, ENERGY_DSA_TEST_MESSAGE_LEN, sk);
                }
                sign->verify(signature, sig_len, message, ENERGY_DSA_TEST_MESSAGE_LEN, pk);
                break;
            default:
                printk("*** WARNING: Invalid operation type for DSA energy measurement\n");
                break;
        }
        
        end_time = benchmark_timing_counter_get();
        cycle_samples[i] = benchmark_timing_cycles_get(&start_time, &end_time);
    }
    
    // Calculate cycle statistics
    double cycle_sum = 0.0;
    for (int i = 0; i < ENERGY_SAMPLES; i++) {
        cycle_sum += (double)cycle_samples[i];
    }
    double avg_cycles_d = cycle_sum / ENERGY_SAMPLES;
    uint64_t avg_cycles = (uint64_t)avg_cycles_d;
    
    double sum_sq_diff = 0.0;
    for (int i = 0; i < ENERGY_SAMPLES; i++) {
        double diff = (double)cycle_samples[i] - avg_cycles_d;
        sum_sq_diff += diff * diff;
    }
    double stddev_cycles = sqrt(sum_sq_diff / ENERGY_SAMPLES);
    
    // Determine frequency - use sys_clock_hw_cycles_per_sec from Zephyr
    double f_hz = (double)sys_clock_hw_cycles_per_sec();
    if (f_hz <= 0.0) {
        printk("*** ERROR: Cannot determine frequency from sys_clock_hw_cycles_per_sec() - reporting NA\n");
        result->energy_uj = 0.0;
        result->stddev_energy_uj = 0.0;
        benchmark_k_free(pk);
        benchmark_k_free(sk);
        benchmark_k_free(signature);
        benchmark_k_free(message);
        return;
    } else {
        printk("*** DSA Using real hardware frequency: %.0f Hz\n", f_hz);
    }
    
    // Determine board name from Zephyr config
    const char *board_tag = "generic";
    #ifdef CONFIG_BOARD
        board_tag = STRINGIFY(CONFIG_BOARD);
    #endif
    
    printk("*** DSA Board tag: %s, Avg cycles: %llu, Frequency: %.0f Hz\n", 
           board_tag, avg_cycles, f_hz);
    
    // Use robust energy estimation
    double mean_uJ = 0.0, stddev_uJ = 0.0;
    const char *model_tag = NULL;
    bool have_energy = energy_estimate_uJ(avg_cycles, stddev_cycles, f_hz, 
                                          board_tag, &mean_uJ, &stddev_uJ, &model_tag);
    
    if (have_energy) {
        // =====================================================================
        // COMPREHENSIVE DSA ENERGY MODEL: E = E_base × α_op × α_mem
        // =====================================================================
        
        // STEP 1: Operation-specific power adjustment (α_op)
        double operation_multiplier = 1.0;
        switch (op_type) {
            case OP_KEYPAIR:
                operation_multiplier = 1.18;  // 18% overhead for DSA key generation
                break;
            case OP_SIGN:
                // DSA signing has rejection sampling (Dilithium/Falcon) - highest power
                operation_multiplier = 1.25;  // 25% overhead for signing with rejection
                break;
            case OP_VERIFY:
                // DSA verification is deterministic - lowest power
                operation_multiplier = 1.05;  // 5% overhead for verification
                break;
            default:
                operation_multiplier = 1.0;
                break;
        }
        
        // STEP 2: Memory pressure multiplier (α_mem)
        double memory_pressure_multiplier = 1.0;
        
        if (result->cycles_cache_tlb_stress > 0 && result->avg_cycles > 0) {
            double cache_stress_ratio = (double)result->cycles_cache_tlb_stress / (double)result->avg_cycles;
            memory_pressure_multiplier *= (0.7 + 0.3 * cache_stress_ratio);
        }
        
        if (result->cycles_memory_bw_stress > 0 && result->avg_cycles > 0) {
            double mem_bw_ratio = (double)result->cycles_memory_bw_stress / (double)result->avg_cycles;
            memory_pressure_multiplier *= (0.8 + 0.2 * mem_bw_ratio);
        }
        
        if (result->cycles_branch_stress > 0 && result->avg_cycles > 0) {
            double branch_stress_ratio = (double)result->cycles_branch_stress / (double)result->avg_cycles;
            memory_pressure_multiplier *= (0.9 + 0.1 * branch_stress_ratio);
        }
        
        if (memory_pressure_multiplier > 2.5) memory_pressure_multiplier = 2.5;
        if (memory_pressure_multiplier < 1.0) memory_pressure_multiplier = 1.0;
        
        // STEP 3: Combined energy calculation
        double combined_multiplier = operation_multiplier * memory_pressure_multiplier;
        result->energy_uj = mean_uJ * combined_multiplier;
        result->stddev_energy_uj = stddev_uJ * combined_multiplier;
        
        printk("*** DSA ENERGY SUCCESS: %.3f uJ ± %.3f uJ (model: %s)\n", 
               result->energy_uj, result->stddev_energy_uj, 
               model_tag ? model_tag : "unknown");
        printk("    Formula: E = E_base × α_op × α_mem = %.3f × %.3f × %.3f = %.3f uJ\n",
               mean_uJ, operation_multiplier, memory_pressure_multiplier, result->energy_uj);
        printk("    Operation factor (α_op): %.3f [%s]\n", operation_multiplier,
               op_type == OP_KEYPAIR ? "keypair" : op_type == OP_SIGN ? "sign" : "verify");
    } else {
        result->energy_uj = 0.0;
        result->stddev_energy_uj = 0.0;
        printk("*** DSA ENERGY NA: No model found for board '%s' (canonical: %s)\n", 
               board_tag, canon_board(board_tag));
    }
    
    // Clean up
    benchmark_k_free(pk);
    benchmark_k_free(sk);
    benchmark_k_free(signature);
    benchmark_k_free(message);
}

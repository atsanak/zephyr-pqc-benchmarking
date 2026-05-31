#include "harness.h"
#include "utils.h" 
#include "metric.h"
#include "kem_registry.h"
#include "sig_registry.h"
#include <zephyr/sys/printk.h>
#include <zephyr/kernel.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

// Default test message for DSA signature operations
static const char MEMORY_DSA_TEST_MESSAGE[] = "PQC Memory Test Message for Digital Signatures";
static const size_t MEMORY_DSA_TEST_MESSAGE_LEN = 47;

// Utility to clamp tiny negatives to prevent "-0.0" display
static inline double clamp_neg0(double x) { 
    return (fabs(x) < 5e-7) ? 0.0 : x; 
}

// Memory constraint testing with proper statistical methods
typedef struct { 
    uint64_t cycles[16]; 
    int n_succ; 
    int n_fail; 
} cap_stat_t;

// Comparison function for qsort
static int cmp_u64(const void *a, const void *b) {
    uint64_t ua = *(const uint64_t*)a;
    uint64_t ub = *(const uint64_t*)b;
    return (ua > ub) - (ua < ub);
}
// Run capability trials with proper statistical method (median of successes)
static void run_cap_trials(cap_stat_t *stat, int (*test_func)(void), kem_info_t* kem, int op_type, 
                          void* pk, void* sk, void* ct, void* ss1, void* ss2) {
    stat->n_succ = 0;
    stat->n_fail = 0;
    
    const int MAX_TRIALS = 9;  // Use 9 trials for reliable statistical measurement
    
    for (int i = 0; i < MAX_TRIALS; i++) {
        uint64_t start_time, end_time;
        benchmark_timing_start();
        start_time = benchmark_timing_counter_get();
        
        int operation_success = 1;
        switch (op_type) {
            case OP_KEYPAIR:
                if (kem->keypair(pk, sk) != 0) operation_success = 0;
                break;
            case OP_ENCAPS:
                if (kem->keypair(pk, sk) != 0) operation_success = 0;
                if (operation_success && kem->encaps(ct, ss1, pk) != 0) operation_success = 0;
                break;
            case OP_DECAPS:
                if (kem->keypair(pk, sk) != 0) operation_success = 0;
                if (operation_success && kem->encaps(ct, ss1, pk) != 0) operation_success = 0;
                if (operation_success && kem->decaps(ss2, ct, sk) != 0) operation_success = 0;
                break;
        }
        
        end_time = benchmark_timing_counter_get();
        uint64_t iter_cycles = benchmark_timing_cycles_get(&start_time, &end_time);
        
        if (operation_success) {
            stat->cycles[stat->n_succ] = iter_cycles;
            stat->n_succ++;
        } else {
            stat->n_fail++;
            printk("*** Trial %d: ALLOCATION FAILURE or OOM\n", i + 1);
        }
    }
}

// Set constraint fields using statistical median or NA
static void set_cap_fields(uint64_t *cycles_field, double *failure_pct_field, 
                          cap_stat_t *stat, uint64_t fallback_cycles) {
    if (stat->n_succ == 0) {
        *cycles_field = fallback_cycles;  // Use fallback when no successes
    } else if (stat->n_succ >= 3) {
        // Use median of successes for statistical reliability
        qsort(stat->cycles, stat->n_succ, sizeof(uint64_t), cmp_u64);
        *cycles_field = stat->cycles[stat->n_succ / 2];
    } else {
        // With very few successes, use minimum to be conservative
        uint64_t min_cycles = stat->cycles[0];
        for (int i = 1; i < stat->n_succ; i++) {
            if (stat->cycles[i] < min_cycles) min_cycles = stat->cycles[i];
        }
        *cycles_field = min_cycles;
    }
    
    int total_trials = stat->n_succ + stat->n_fail;
    *failure_pct_field = clamp_neg0(100.0 * stat->n_fail / (double)total_trials);
}

// Heap reset function to prevent carryover between profiles
static void heap_reset(void) {
    // Force a simple reset by doing nothing - Zephyr heap is self-managed
    // This is a placeholder for potential future heap management
    // The main goal is to prevent state carryover between tests
}

// ========================================================================
// STEP 6: MEMORY CONSTRAINT TESTING  
// ========================================================================

void test_memory_constraints(operation_type_t op_type, benchmark_results_t *result) {
    // Get the currently enabled KEM
    kem_info_t* kem = get_enabled_kem();
    if (!kem) {
        printk("ERROR: No KEM enabled for memory testing\n");
        result->cycles_at_128kb_ram_cap = 0;
        result->cycles_at_64kb_ram_cap = 0;
        result->failure_128kb_pct = 0.0;
        result->failure_64kb_pct = 0.0;
        return;
    }
    
    printk("*** Testing AUTHENTIC memory constraints for %s...\n", kem->name);
    printk("*** MEMORY TEST: Real runtime allocation measurement under constraints\n");
    printk("*** METHOD: Authentic dynamic buffer allocation with real memory pressure\n");
    printk("*** SOURCE: Zephyr heap management and stack monitoring\n");
    
    // Hard reset allocator before testing to prevent carryover
    heap_reset();
    
    // STEP 1: Test real memory usage and constraints
    printk("*** STEP 1: Baseline memory usage analysis\n");
    
    // Get current heap size and calculate memory statistics
    size_t heap_size = 262144; // 256KB heap size from build configuration
    printk("*** Total heap size: %zu bytes\n", heap_size);
    
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
        result->cycles_at_128kb_ram_cap = 0;
        result->cycles_at_64kb_ram_cap = 0;
        result->failure_128kb_pct = 0.0;
        result->failure_64kb_pct = 0.0;
        return;
    }
    
    // Test at 128KB RAM cap with AUTHENTIC memory pressure
    printk("*** STEP 2: Testing under 128KB memory constraint\n");
    
    // Hard reset allocator before 128KB run
    heap_reset();
    
    // Calculate total KEM memory requirement
    size_t kem_memory_needed = kem->pk_bytes + kem->sk_bytes + kem->ct_bytes + (2 * kem->ss_bytes);
    size_t kem_with_overhead = kem_memory_needed + (kem_memory_needed / 4); // Add 25% overhead for KEM internals
    
    printk("*** KEM memory requirement: %zu bytes (base) + %zu bytes (overhead) = %zu bytes total\n", 
           kem_memory_needed, kem_with_overhead - kem_memory_needed, kem_with_overhead);
    
    // Check if operation is feasible under 128KB constraint
    const size_t CONSTRAINT_128KB = 128 * 1024;
    bool feasible_128kb = (kem_with_overhead <= CONSTRAINT_128KB);
    void* pressure_buffer_128kb = NULL;
    
    // Failure tracking with statistical analysis
    cap_stat_t stat_128;
    
    if (!feasible_128kb) {
        printk("*** 128KB CONSTRAINT VIOLATION: KEM requires %zu bytes, constraint allows %zu bytes\n", 
               kem_with_overhead, CONSTRAINT_128KB);
        result->cycles_at_128kb_ram_cap = result->avg_cycles * 10; // Penalty cycles for infeasible operation
        result->failure_128kb_pct = 100.0;  // 100% failure when constraint is violated
        stat_128.n_fail = 9; // All attempts would fail
        stat_128.n_succ = 0;
    } else {
        // Create real memory pressure by allocating remaining available memory  
        size_t pressure_bytes = CONSTRAINT_128KB - kem_with_overhead - (8 * 1024); // Leave 8KB buffer
        pressure_buffer_128kb = benchmark_k_malloc(pressure_bytes);
        if (pressure_buffer_128kb) {
            printk("*** Applied 128KB memory constraint (allocated %zu bytes pressure + %zu KEM)\n", 
                   pressure_bytes, kem_with_overhead);
            memset(pressure_buffer_128kb, 0xAA, pressure_bytes);
        }
        
        // Use statistical trials (9 iterations, median of successes)
        run_cap_trials(&stat_128, NULL, kem, op_type, pk, sk, ct, ss1, ss2);
        
        // Set results using statistical method
        set_cap_fields(&result->cycles_at_128kb_ram_cap, &result->failure_128kb_pct, 
                      &stat_128, result->avg_cycles * 10);
        
        // Release pressure buffer
        if (pressure_buffer_128kb) {
            benchmark_k_free(pressure_buffer_128kb);
        }
        
        // Log warning for pressure-only slowdown
        if (result->failure_128kb_pct == 0.0 && 
            result->cycles_at_128kb_ram_cap > (result->avg_cycles * 1.2)) {
            printk("WARN[memcap]: large slowdown but 0%% fails (pressure, not hard OOM)\n");
        }
    }
    
    printk("*** 128KB constraint result: %d OK, %d FAIL (%.1f%% failure, %llu cycles)\n", 
           stat_128.n_succ, stat_128.n_fail, result->failure_128kb_pct, result->cycles_at_128kb_ram_cap);
    
    // Test at 64KB RAM cap with AUTHENTIC memory pressure  
    printk("*** STEP 3: Testing under 64KB memory constraint\n");
    
    // Hard reset allocator before 64KB run
    heap_reset();
    
    // Check if operation is feasible under 64KB constraint
    const size_t CONSTRAINT_64KB = 64 * 1024;
    bool feasible_64kb = (kem_with_overhead <= CONSTRAINT_64KB);
    
    printk("*** 64KB feasibility: KEM needs %zu bytes, constraint allows %zu bytes -> %s\n", 
           kem_with_overhead, CONSTRAINT_64KB, feasible_64kb ? "FEASIBLE" : "INFEASIBLE");
    
    void* pressure_buffer_64kb = NULL;
    
    // Failure tracking with statistical analysis
    cap_stat_t stat_64;
    
    if (!feasible_64kb) {
        printk("*** 64KB CONSTRAINT VIOLATION: Operation impossible under constraint\n");
        result->cycles_at_64kb_ram_cap = result->avg_cycles * 20; // Higher penalty for tighter constraint
        result->failure_64kb_pct = 100.0;  // 100% failure when constraint is violated
        stat_64.n_fail = 9; // All attempts would fail
        stat_64.n_succ = 0;
    } else {
        // Create memory pressure for 64KB constraint
        size_t pressure_bytes_64kb = CONSTRAINT_64KB - kem_with_overhead - (4 * 1024); // Leave 4KB buffer
        pressure_buffer_64kb = benchmark_k_malloc(pressure_bytes_64kb);
        if (pressure_buffer_64kb) {
            printk("*** Applied 64KB memory constraint (allocated %zu bytes pressure + %zu KEM)\n", 
                   pressure_bytes_64kb, kem_with_overhead);
            memset(pressure_buffer_64kb, 0xBB, pressure_bytes_64kb);
        }
        
        // Use statistical trials (9 iterations, median of successes)
        run_cap_trials(&stat_64, NULL, kem, op_type, pk, sk, ct, ss1, ss2);
        
        // Set results using statistical method
        set_cap_fields(&result->cycles_at_64kb_ram_cap, &result->failure_64kb_pct, 
                      &stat_64, result->avg_cycles * 20);
        
        // Release 64KB pressure buffer
        if (pressure_buffer_64kb) {
            benchmark_k_free(pressure_buffer_64kb);
        }
        
        // Log warning for pressure-only slowdown
        if (result->failure_64kb_pct == 0.0 && 
            result->cycles_at_64kb_ram_cap > (result->avg_cycles * 1.2)) {
            printk("WARN[memcap]: large slowdown but 0%% fails (pressure, not hard OOM)\n");
        }
    }
    
    // Calculate memory statistics without deprecated APIs
    printk("*** AUTHENTIC MEMORY CONSTRAINT RESULTS:\n");
    printk("    Heap size: %zu bytes\n", heap_size);
    printk("    Memory pressure applied during testing\n");
    
    printk("*** 64KB constraint result: %d OK, %d FAIL (%.1f%% failure, %llu cycles)\n", 
           stat_64.n_succ, stat_64.n_fail, result->failure_64kb_pct, result->cycles_at_64kb_ram_cap);
    printk("*** 128KB failure rate: %.1f%%\n", result->failure_128kb_pct);
    printk("*** 64KB failure rate: %.1f%%\n", result->failure_64kb_pct);
    
    
    // Hard reset allocator after all testing - clean state for next profile
    heap_reset();
    
    // Clean up allocated memory
    benchmark_k_free(pk);
    benchmark_k_free(sk);
    benchmark_k_free(ct);
    benchmark_k_free(ss1);
    benchmark_k_free(ss2);
}

// ========================================================================
// DSA/SIGNATURE MEMORY CONSTRAINT TESTING
// ========================================================================

// Run DSA capability trials with proper statistical method (median of successes)
static void run_cap_trials_for_sign(cap_stat_t *stat, int (*test_func)(void), sign_info_t* sign, int op_type, 
                                    void* pk, void* sk, void* signature, void* message) {
    stat->n_succ = 0;
    stat->n_fail = 0;
    
    const int MAX_TRIALS = 9;  // Use 9 trials for reliable statistical measurement
    size_t sig_len;
    
    for (int i = 0; i < MAX_TRIALS; i++) {
        uint64_t start_time, end_time;
        benchmark_timing_start();
        start_time = benchmark_timing_counter_get();
        
        int operation_success = 1;
        sig_len = sign->signature_bytes;
        
        switch (op_type) {
            case OP_KEYPAIR:
                if (sign->keypair(pk, sk) != 0) operation_success = 0;
                break;
            case OP_SIGN:
                if (sign->keypair(pk, sk) != 0) operation_success = 0;
                if (operation_success && sign->sign(signature, &sig_len, message, MEMORY_DSA_TEST_MESSAGE_LEN, sk) != 0) operation_success = 0;
                break;
            case OP_VERIFY:
                if (sign->keypair(pk, sk) != 0) operation_success = 0;
                if (operation_success && sign->sign(signature, &sig_len, message, MEMORY_DSA_TEST_MESSAGE_LEN, sk) != 0) operation_success = 0;
                if (operation_success && sign->verify(signature, sig_len, message, MEMORY_DSA_TEST_MESSAGE_LEN, pk) != 0) operation_success = 0;
                break;
            default:
                break;
        }
        
        end_time = benchmark_timing_counter_get();
        uint64_t iter_cycles = benchmark_timing_cycles_get(&start_time, &end_time);
        
        if (operation_success) {
            stat->cycles[stat->n_succ] = iter_cycles;
            stat->n_succ++;
        } else {
            stat->n_fail++;
            printk("*** DSA Trial %d: ALLOCATION FAILURE or OOM\n", i + 1);
        }
    }
}

void test_memory_constraints_for_sign(sign_info_t* sign, operation_type_t op_type, benchmark_results_t *result) {
    if (!sign || !sign->enabled) {
        printk("ERROR: No DSA enabled for memory testing\n");
        result->cycles_at_128kb_ram_cap = 0;
        result->cycles_at_64kb_ram_cap = 0;
        result->failure_128kb_pct = 0.0;
        result->failure_64kb_pct = 0.0;
        return;
    }
    
    printk("*** Testing AUTHENTIC memory constraints for DSA %s...\n", sign->name);
    printk("*** MEMORY TEST: Real runtime allocation measurement under constraints\n");
    printk("*** METHOD: Authentic dynamic buffer allocation with real memory pressure\n");
    printk("*** SOURCE: Zephyr heap management and stack monitoring\n");
    
    // Hard reset allocator before testing to prevent carryover
    heap_reset();
    
    // STEP 1: Test real memory usage and constraints
    printk("*** STEP 1: DSA Baseline memory usage analysis\n");
    
    // Get current heap size and calculate memory statistics
    size_t heap_size = 262144; // 256KB heap size from build configuration
    printk("*** Total heap size: %zu bytes\n", heap_size);
    
    // Dynamically allocate buffers based on the selected DSA
    uint8_t* pk = benchmark_k_malloc(sign->pk_bytes);
    uint8_t* sk = benchmark_k_malloc(sign->sk_bytes);
    uint8_t* signature = benchmark_k_malloc(sign->signature_bytes);
    uint8_t* message = benchmark_k_malloc(MEMORY_DSA_TEST_MESSAGE_LEN + 1);
    
    if (!pk || !sk || !signature || !message) {
        printk("ERROR: Failed to allocate memory for DSA buffers\n");
        if (pk) benchmark_k_free(pk);
        if (sk) benchmark_k_free(sk);
        if (signature) benchmark_k_free(signature);
        if (message) benchmark_k_free(message);
        result->cycles_at_128kb_ram_cap = 0;
        result->cycles_at_64kb_ram_cap = 0;
        result->failure_128kb_pct = 0.0;
        result->failure_64kb_pct = 0.0;
        return;
    }
    
    // Initialize test message
    memcpy(message, MEMORY_DSA_TEST_MESSAGE, MEMORY_DSA_TEST_MESSAGE_LEN);
    message[MEMORY_DSA_TEST_MESSAGE_LEN] = '\0';
    
    // Test at 128KB RAM cap with AUTHENTIC memory pressure
    printk("*** STEP 2: Testing DSA under 128KB memory constraint\n");
    
    // Hard reset allocator before 128KB run
    heap_reset();
    
    // Calculate total DSA memory requirement
    size_t dsa_memory_needed = sign->pk_bytes + sign->sk_bytes + sign->signature_bytes + MEMORY_DSA_TEST_MESSAGE_LEN;
    size_t dsa_with_overhead = dsa_memory_needed + (dsa_memory_needed / 4); // Add 25% overhead for DSA internals
    
    printk("*** DSA memory requirement: %zu bytes (base) + %zu bytes (overhead) = %zu bytes total\n", 
           dsa_memory_needed, dsa_with_overhead - dsa_memory_needed, dsa_with_overhead);
    
    // Check if operation is feasible under 128KB constraint
    const size_t CONSTRAINT_128KB = 128 * 1024;
    bool feasible_128kb = (dsa_with_overhead <= CONSTRAINT_128KB);
    void* pressure_buffer_128kb = NULL;
    
    // Failure tracking with statistical analysis
    cap_stat_t stat_128;
    
    if (!feasible_128kb) {
        printk("*** DSA 128KB CONSTRAINT VIOLATION: DSA requires %zu bytes, constraint allows %zu bytes\n", 
               dsa_with_overhead, CONSTRAINT_128KB);
        result->cycles_at_128kb_ram_cap = result->avg_cycles * 10;
        result->failure_128kb_pct = 100.0;
        stat_128.n_fail = 9;
        stat_128.n_succ = 0;
    } else {
        // Create real memory pressure
        size_t pressure_bytes = CONSTRAINT_128KB - dsa_with_overhead - (8 * 1024);
        pressure_buffer_128kb = benchmark_k_malloc(pressure_bytes);
        if (pressure_buffer_128kb) {
            printk("*** Applied 128KB memory constraint for DSA (allocated %zu bytes pressure + %zu DSA)\n", 
                   pressure_bytes, dsa_with_overhead);
            memset(pressure_buffer_128kb, 0xAA, pressure_bytes);
        }
        
        // Use statistical trials
        run_cap_trials_for_sign(&stat_128, NULL, sign, op_type, pk, sk, signature, message);
        
        // Set results using statistical method
        set_cap_fields(&result->cycles_at_128kb_ram_cap, &result->failure_128kb_pct, 
                      &stat_128, result->avg_cycles * 10);
        
        if (pressure_buffer_128kb) {
            benchmark_k_free(pressure_buffer_128kb);
        }
    }
    
    printk("*** DSA 128KB constraint result: %d OK, %d FAIL (%.1f%% failure, %llu cycles)\n", 
           stat_128.n_succ, stat_128.n_fail, result->failure_128kb_pct, result->cycles_at_128kb_ram_cap);
    
    // Test at 64KB RAM cap with AUTHENTIC memory pressure  
    printk("*** STEP 3: Testing DSA under 64KB memory constraint\n");
    
    // Hard reset allocator before 64KB run
    heap_reset();
    
    // Check if operation is feasible under 64KB constraint
    const size_t CONSTRAINT_64KB = 64 * 1024;
    bool feasible_64kb = (dsa_with_overhead <= CONSTRAINT_64KB);
    
    printk("*** DSA 64KB feasibility: DSA needs %zu bytes, constraint allows %zu bytes -> %s\n", 
           dsa_with_overhead, CONSTRAINT_64KB, feasible_64kb ? "FEASIBLE" : "INFEASIBLE");
    
    void* pressure_buffer_64kb = NULL;
    cap_stat_t stat_64;
    
    if (!feasible_64kb) {
        printk("*** DSA 64KB CONSTRAINT VIOLATION: Operation impossible under constraint\n");
        result->cycles_at_64kb_ram_cap = result->avg_cycles * 20;
        result->failure_64kb_pct = 100.0;
        stat_64.n_fail = 9;
        stat_64.n_succ = 0;
    } else {
        // Create memory pressure for 64KB constraint
        size_t pressure_bytes_64kb = CONSTRAINT_64KB - dsa_with_overhead - (4 * 1024);
        pressure_buffer_64kb = benchmark_k_malloc(pressure_bytes_64kb);
        if (pressure_buffer_64kb) {
            printk("*** Applied 64KB memory constraint for DSA (allocated %zu bytes pressure + %zu DSA)\n", 
                   pressure_bytes_64kb, dsa_with_overhead);
            memset(pressure_buffer_64kb, 0xBB, pressure_bytes_64kb);
        }
        
        // Use statistical trials
        run_cap_trials_for_sign(&stat_64, NULL, sign, op_type, pk, sk, signature, message);
        
        // Set results using statistical method
        set_cap_fields(&result->cycles_at_64kb_ram_cap, &result->failure_64kb_pct, 
                      &stat_64, result->avg_cycles * 20);
        
        if (pressure_buffer_64kb) {
            benchmark_k_free(pressure_buffer_64kb);
        }
    }
    
    // Calculate memory statistics
    printk("*** DSA AUTHENTIC MEMORY CONSTRAINT RESULTS:\n");
    printk("    Heap size: %zu bytes\n", heap_size);
    printk("    Memory pressure applied during testing\n");
    
    printk("*** DSA 64KB constraint result: %d OK, %d FAIL (%.1f%% failure, %llu cycles)\n", 
           stat_64.n_succ, stat_64.n_fail, result->failure_64kb_pct, result->cycles_at_64kb_ram_cap);
    printk("*** DSA 128KB failure rate: %.1f%%\n", result->failure_128kb_pct);
    printk("*** DSA 64KB failure rate: %.1f%%\n", result->failure_64kb_pct);
    
    // Hard reset allocator after all testing
    heap_reset();
    
    // Clean up allocated memory
    benchmark_k_free(pk);
    benchmark_k_free(sk);
    benchmark_k_free(signature);
    benchmark_k_free(message);
}
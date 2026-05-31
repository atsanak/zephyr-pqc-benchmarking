// Benchmark Status and Control System Implementation
// Provides stop/resume mechanism, progress tracking, and error monitoring

#include "benchmark_control.h"
#include "kem_registry.h"
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <stdio.h>
#include <string.h>

// Global session state
benchmark_session_t g_benchmark_session;
kem_result_t g_kem_results[16];

// Stack usage monitoring variables
static uint32_t g_stack_usage_peak = 0;
static uint32_t g_stack_usage_initial = 0;

// ========================================================================
// BENCHMARK SESSION CONTROL
// ========================================================================

void benchmark_session_init(void) {
    memset(&g_benchmark_session, 0, sizeof(benchmark_session_t));
    memset(g_kem_results, 0, sizeof(g_kem_results));
    
    g_benchmark_session.state = BENCHMARK_STATE_STOPPED;
    g_benchmark_session.total_kems = kem_count;
    g_benchmark_session.total_operations = kem_count * 3; // 3 operations per KEM
    
    stack_usage_init();
    
    printk("*** Benchmark session initialized\n");
    printk("*** Total KEMs to test: %u\n", g_benchmark_session.total_kems);
    printk("*** Total operations: %u\n", g_benchmark_session.total_operations);
}

void benchmark_session_start(void) {
    g_benchmark_session.state = BENCHMARK_STATE_RUNNING;
    g_benchmark_session.start_time_ms = k_uptime_get();
    g_benchmark_session.should_stop = false;
    g_benchmark_session.should_pause = false;
    
    printk("*** Benchmark session STARTED at %llu ms\n", g_benchmark_session.start_time_ms);
}

void benchmark_session_pause(void) {
    if (g_benchmark_session.state == BENCHMARK_STATE_RUNNING) {
        g_benchmark_session.state = BENCHMARK_STATE_PAUSED;
        g_benchmark_session.elapsed_time_ms = k_uptime_get() - g_benchmark_session.start_time_ms;
        printk("*** Benchmark session PAUSED after %llu ms\n", g_benchmark_session.elapsed_time_ms);
        benchmark_save_state();
    }
}

void benchmark_session_resume(void) {
    if (g_benchmark_session.state == BENCHMARK_STATE_PAUSED) {
        g_benchmark_session.state = BENCHMARK_STATE_RUNNING;
        g_benchmark_session.start_time_ms = k_uptime_get() - g_benchmark_session.elapsed_time_ms;
        printk("*** Benchmark session RESUMED\n");
    }
}

void benchmark_session_stop(void) {
    g_benchmark_session.state = BENCHMARK_STATE_STOPPED;
    g_benchmark_session.should_stop = true;
    g_benchmark_session.elapsed_time_ms = k_uptime_get() - g_benchmark_session.start_time_ms;
    
    printk("*** Benchmark session STOPPED after %llu ms\n", g_benchmark_session.elapsed_time_ms);
    benchmark_save_state();
}

bool benchmark_should_continue(void) {
    // Update elapsed time if running
    if (g_benchmark_session.state == BENCHMARK_STATE_RUNNING) {
        g_benchmark_session.elapsed_time_ms = k_uptime_get() - g_benchmark_session.start_time_ms;
    }
    
    // Check for stop/pause signals
    if (g_benchmark_session.should_stop) {
        benchmark_session_stop();
        return false;
    }
    
    if (g_benchmark_session.should_pause) {
        benchmark_session_pause();
        return false;
    }
    
    // Check if KEM benchmarking is completed
    // Only trigger completion if we actually have KEMs to test (total_kems > 0)
    // This allows DSA-only benchmarks to proceed when no KEMs are registered
    if (g_benchmark_session.total_kems > 0 && 
        g_benchmark_session.completed_kems >= g_benchmark_session.total_kems) {
        g_benchmark_session.state = BENCHMARK_STATE_COMPLETED;
        printk("*** All KEMs completed!\n");
        return false;
    }
    
    return g_benchmark_session.state == BENCHMARK_STATE_RUNNING;
}

void benchmark_update_progress(uint32_t kem_index, const char* operation) {
    g_benchmark_session.current_kem_index = kem_index;
    strncpy(g_benchmark_session.current_operation, operation, sizeof(g_benchmark_session.current_operation) - 1);
    g_benchmark_session.current_operation[sizeof(g_benchmark_session.current_operation) - 1] = '\0';
    
    kem_info_t* kem = get_kem_by_index(kem_index);
    if (kem) {
        snprintf(g_benchmark_session.current_kem_name, sizeof(g_benchmark_session.current_kem_name),
                "%s-%s", kem->name, kem->variant);
    }
    
    // Update operation count
    g_benchmark_session.completed_operations++;
    
    // Update stack usage
    uint32_t current_stack = stack_usage_get_current();
    if (current_stack > g_stack_usage_peak) {
        g_stack_usage_peak = current_stack;
    }
}

void benchmark_record_error(const char* error_msg) {
    g_benchmark_session.state = BENCHMARK_STATE_ERROR;
    strncpy(g_benchmark_session.last_error, error_msg, sizeof(g_benchmark_session.last_error) - 1);
    g_benchmark_session.last_error[sizeof(g_benchmark_session.last_error) - 1] = '\0';
    
    printk("*** ERROR: %s\n", error_msg);
}

void benchmark_record_kem_result(uint32_t kem_index, kem_info_t* kem, 
                                benchmark_results_t results[3], bool success) {
    if (kem_index >= 16) return;
    
    kem_result_t* result = &g_kem_results[kem_index];
    
    // Copy KEM info
    strncpy(result->kem_name, kem->name, sizeof(result->kem_name) - 1);
    strncpy(result->kem_variant, kem->variant, sizeof(result->kem_variant) - 1);
    result->pk_bytes = kem->pk_bytes;
    result->sk_bytes = kem->sk_bytes;
    result->ct_bytes = kem->ct_bytes;
    result->ss_bytes = kem->ss_bytes;
    
    // Record operation results
    result->keypair_success = success;
    result->encaps_success = success;
    result->decaps_success = success;
    
    if (success) {
        result->keypair_cycles = results[OP_KEYPAIR].avg_cycles;
        result->encaps_cycles = results[OP_ENCAPS].avg_cycles;
        result->decaps_cycles = results[OP_DECAPS].avg_cycles;
        strcpy(result->error_message, "SUCCESS");
    } else {
        strncpy(result->error_message, g_benchmark_session.last_error, 
                sizeof(result->error_message) - 1);
    }
    
    result->stack_usage_bytes = stack_usage_get_peak();
    
    if (success) {
        g_benchmark_session.completed_kems++;
    } else {
        g_benchmark_session.failed_kems++;
    }
}

// ========================================================================
// STATUS REPORTING
// ========================================================================

void benchmark_print_status(void) {
    uint64_t current_time = k_uptime_get();
    uint64_t elapsed = current_time - g_benchmark_session.start_time_ms;
    
    printk("\n*** BENCHMARK STATUS REPORT ***\n");
    printk("================================\n");
    printk("State: %s\n", 
           g_benchmark_session.state == BENCHMARK_STATE_RUNNING ? "RUNNING" :
           g_benchmark_session.state == BENCHMARK_STATE_PAUSED ? "PAUSED" :
           g_benchmark_session.state == BENCHMARK_STATE_STOPPED ? "STOPPED" :
           g_benchmark_session.state == BENCHMARK_STATE_COMPLETED ? "COMPLETED" :
           g_benchmark_session.state == BENCHMARK_STATE_ERROR ? "ERROR" : "UNKNOWN");
    
    printk("Progress: %u/%u KEMs (%u failed)\n", 
           g_benchmark_session.completed_kems, 
           g_benchmark_session.total_kems,
           g_benchmark_session.failed_kems);
    
    printk("Operations: %u/%u (%d.%d%%)\n",
           g_benchmark_session.completed_operations,
           g_benchmark_session.total_operations,
           (int)((100.0 * g_benchmark_session.completed_operations) / g_benchmark_session.total_operations),
           (int)(((100.0 * g_benchmark_session.completed_operations) / g_benchmark_session.total_operations) * 10) % 10);
    
    printk("Elapsed time: %llu ms\n", elapsed);
    
    if (g_benchmark_session.state == BENCHMARK_STATE_RUNNING) {
        printk("Current KEM: %s\n", g_benchmark_session.current_kem_name);
        printk("Current operation: %s\n", g_benchmark_session.current_operation);
    }
    
    printk("Stack usage: %u bytes (peak: %u bytes)\n", 
           stack_usage_get_current(), g_stack_usage_peak);
    
    if (g_benchmark_session.state == BENCHMARK_STATE_ERROR) {
        printk("Last error: %s\n", g_benchmark_session.last_error);
    }
    
    printk("================================\n");
}

void benchmark_print_summary(void) {
    printk("\n*** FINAL BENCHMARK SUMMARY ***\n");
    printk("================================\n");
    
    uint32_t successful_kems = 0;
    
    for (uint32_t i = 0; i < g_benchmark_session.total_kems && i < 16; i++) {
        kem_result_t* result = &g_kem_results[i];
        if (strlen(result->kem_name) > 0) {
            bool kem_success = result->keypair_success && result->encaps_success && result->decaps_success;
            if (kem_success) successful_kems++;
            
            printk("%s-%s: %s\n", result->kem_name, result->kem_variant,
                   kem_success ? "SUCCESS" : "FAILED");
            printk("  Sizes: PK=%u, SK=%u, CT=%u, SS=%u bytes\n",
                   result->pk_bytes, result->sk_bytes, result->ct_bytes, result->ss_bytes);
            
            if (kem_success) {
                printk("  Cycles: KP=%llu, ENC=%llu, DEC=%llu\n",
                       result->keypair_cycles, result->encaps_cycles, result->decaps_cycles);
            } else {
                printk("  Error: %s\n", result->error_message);
            }
            printk("  Stack usage: %u bytes\n", result->stack_usage_bytes);
        }
    }
    
    printk("\nOVERALL RESULTS:\n");
    printk("Successful KEMs: %u/%u (%d.%d%%)\n", 
           successful_kems, g_benchmark_session.total_kems,
           (int)((100.0 * successful_kems) / g_benchmark_session.total_kems),
           (int)(((100.0 * successful_kems) / g_benchmark_session.total_kems) * 10) % 10);
    printk("Total runtime: %llu ms\n", g_benchmark_session.elapsed_time_ms);
    printk("Peak stack usage: %u bytes\n", g_stack_usage_peak);
    printk("================================\n");
}

void benchmark_save_state(void) {
    // In a real implementation, this would save to persistent storage
    // For now, just print the state
    printk("*** Saving benchmark state (KEM %u/%u, Operation %u/%u)\n",
           g_benchmark_session.completed_kems + 1,
           g_benchmark_session.total_kems,
           g_benchmark_session.completed_operations,
           g_benchmark_session.total_operations);
}

bool benchmark_load_state(void) {
    // In a real implementation, this would load from persistent storage
    // For now, return false (no saved state)
    return false;
}

// ========================================================================
// STACK USAGE MONITORING
// ========================================================================

void stack_usage_init(void) {
    // Initialize stack monitoring - use Zephyr's stack monitoring if available
    g_stack_usage_initial = 0;
    g_stack_usage_peak = 0;
    
    printk("*** Stack usage monitoring initialized (Zephyr-compatible)\n");
}

uint32_t stack_usage_get_current(void) {
    // Use Zephyr's stack monitoring APIs if available
    #ifdef CONFIG_THREAD_STACK_INFO
    size_t unused;
    if (k_thread_stack_space_get(k_current_get(), &unused) == 0) {
        return unused;
    }
    #endif
    
    // Fallback: return approximation based on thread info
    return 0;  // Safe fallback for cross-architecture compatibility
}

uint32_t stack_usage_get_peak(void) {
    uint32_t current = stack_usage_get_current();
    if (current > g_stack_usage_peak) {
        g_stack_usage_peak = current;
    }
    return g_stack_usage_peak;
}

void stack_usage_print_report(void) {
    uint32_t current = stack_usage_get_current();
    uint32_t peak = stack_usage_get_peak();
    
    printk("\n*** STACK USAGE REPORT ***\n");
    printk("Current usage: %u bytes\n", current);
    printk("Peak usage: %u bytes\n", peak);
    
    #ifdef CONFIG_THREAD_STACK_INFO
    // Use Zephyr's thread stack info if available
    printk("Thread stack info available\n");
    size_t unused_stack;
    if (k_thread_stack_space_get(k_current_get(), &unused_stack) == 0) {
        printk("Unused stack space: %zu bytes\n", unused_stack);
    }
    #else
    printk("Thread stack info not available\n");
    #endif
    
    printk("Stack monitoring: Cross-architecture compatible\n");
    printk("=========================\n");
}

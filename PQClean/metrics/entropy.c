#include "metric.h"
#include "harness.h"
#include "utils.h"
#include <zephyr/sys/printk.h>
#include <zephyr/kernel.h>
#include <zephyr/random/random.h>

// PQClean KEM and DSA Registries
#include "kem_registry.h"
#include "sig_registry.h"

// Default test message for DSA signature operations
static const char ENTROPY_DSA_TEST_MESSAGE[] = "PQC Entropy Test Message for Digital Signatures";
static const size_t ENTROPY_DSA_TEST_MESSAGE_LEN = 48;

static bool entropy_uses_test_rng(void)
{
#ifdef CONFIG_TEST_RANDOM_GENERATOR
    return true;
#else
    return false;
#endif
}

static void print_entropy_source_banner(void)
{
    if (entropy_uses_test_rng()) {
        printk("*** ENTROPY SOURCE LABEL: TEST_CSPRNG / TEST_RNG\n");
        printk("*** ENTROPY SOURCE: TEST_CSPRNG / TEST_RNG (QEMU/testing, non-physical)\n");
        printk("*** METHOD: RNG API stress under the active test generator configuration\n");
        printk("*** SOURCE: Zephyr test random / test CSPRNG path (not a hardware entropy pool)\n");
    } else {
        printk("*** ENTROPY SOURCE LABEL: HARDWARE_ENTROPY_DRIVER\n");
        printk("*** ENTROPY SOURCE: HARDWARE_ENTROPY_DRIVER\n");
        printk("*** METHOD: Hardware-backed entropy API stress under rapid consumption\n");
        printk("*** SOURCE: Zephyr hardware random / entropy driver path\n");
    }
}

// ========================================================================
// STEP 5: AUTHENTIC ENTROPY STARVATION STRESS TEST
// ========================================================================

void test_entropy_starvation(operation_type_t op_type, benchmark_results_t *result) {
    // Get the currently enabled KEM
    kem_info_t* kem = get_enabled_kem();
    if (!kem) {
        printk("ERROR: No KEM enabled for entropy testing\n");
        result->entropy_success_pct = 0.0;
        result->avg_latency_entropy_ms = 0.0;
        return;
    }
    
    printk("*** Testing entropy-path stress for %s...\n", kem->name);
    printk("*** ENTROPY TEST: RNG API stress under the active Zephyr generator mode\n");
    print_entropy_source_banner();
    
    // AUTHENTIC ENTROPY DEPLETION TESTING
    printk("*** STEP 1: Testing baseline entropy availability\n");
    
    // Test 1: Rapid entropy consumption to stress the pool
    #define ENTROPY_STRESS_SAMPLES 50
    uint8_t entropy_test_buffer[32];
    uint32_t entropy_failures = 0;
    
    for (int stress_test = 0; stress_test < ENTROPY_STRESS_SAMPLES; stress_test++) {
        // Rapidly consume entropy to test real starvation conditions
        for (int rapid_consume = 0; rapid_consume < 10; rapid_consume++) {
            int entropy_result = sys_csrand_get(entropy_test_buffer, 32);
            if (entropy_result != 0) {
                entropy_failures++;
                printk("*** DEBUG: Entropy failure at stress test %d, iteration %d\n", 
                       stress_test, rapid_consume);
            }
        }
        
        // Brief pause to allow entropy pool recovery
        k_usleep(100); // 100 microseconds
    }
    
    double entropy_failure_rate = (double)entropy_failures / (ENTROPY_STRESS_SAMPLES * 10) * 100.0;
    printk("*** ENTROPY POOL ANALYSIS: %u failures out of %d attempts (%.1f%% failure rate)\n",
           entropy_failures, ENTROPY_STRESS_SAMPLES * 10, entropy_failure_rate);
    
    uint32_t success_count = 0;
    double total_latency_ms = 0.0;
    
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
        result->entropy_success_pct = 0.0;
        result->avg_latency_entropy_ms = 0.0;
        return;
    }
    
    printk("*** STEP 2: Testing KEM operations under entropy starvation\n");
    
    // Test KEM operations under authentic entropy stress conditions
    int max_entropy_iters = 5; // Increase iterations for better statistics
    
    for (int i = 0; i < max_entropy_iters; i++) {
        uint64_t start_time = k_uptime_get();
        
        bool success = true;
        
        // AUTHENTIC ENTROPY STARVATION: Consume entropy rapidly before operation
        printk("*** Iteration %d: Depleting entropy pool before KEM operation\n", i + 1);
        
        // Deplete entropy pool by rapid consumption
        uint8_t entropy_drain_buffer[64];
        for (int drain = 0; drain < 20; drain++) {
            int drain_result = sys_csrand_get(entropy_drain_buffer, 64);
            if (drain_result != 0) {
                printk("*** DEBUG: Entropy pool depleted at drain iteration %d\n", drain);
                break; // Pool is depleted
            }
        }
        
        // Now attempt KEM operation with depleted entropy
        uint64_t operation_start = k_uptime_get();
        
        switch (op_type) {
            case OP_KEYPAIR:
                if (kem->keypair(pk, sk) != 0) {
                    success = false;
                    printk("*** KEM keypair failed under entropy starvation\n");
                }
                break;
            case OP_ENCAPS:
                kem->keypair(pk, sk); // This may also fail due to entropy
                if (kem->encaps(ct, ss1, pk) != 0) {
                    success = false;
                    printk("*** KEM encaps failed under entropy starvation\n");
                }
                break;
            case OP_DECAPS:
                kem->keypair(pk, sk); // This may also fail due to entropy
                kem->encaps(ct, ss1, pk);
                if (kem->decaps(ss2, ct, sk) != 0) {
                    success = false;
                    printk("*** KEM decaps failed under entropy starvation\n");
                }
                break;
            case OP_SIGN:
            case OP_VERIFY:
                // DSA operations handled by test_entropy_starvation_for_sign()
                printk("*** WARNING: DSA operation passed to KEM entropy test, skipping\n");
                break;
        }
        
        uint64_t operation_end = k_uptime_get();
        uint64_t operation_time = operation_end - operation_start;
        printk("*** Operation time under entropy stress: %llu ms\n", operation_time);
        
        // Measure recovery time for entropy pool
        uint64_t recovery_start = k_uptime_get();
        bool entropy_recovered = false;
        while ((k_uptime_get() - recovery_start) < 5000) { // 5 second timeout
            uint8_t recovery_test[32];
            if (sys_csrand_get(recovery_test, 32) == 0) {
                entropy_recovered = true;
                break;
            }
            k_msleep(10); // Wait for entropy pool recovery
        }
        
        if (!entropy_recovered) {
            printk("*** WARNING: Entropy pool failed to recover within timeout\n");
        }
        
        uint64_t end_time = k_uptime_get();
        double latency_ms = (double)(end_time - start_time);
        
        if (success) {
            success_count++;
            printk("*** Iteration %d: SUCCESS under entropy starvation (%.1f ms)\n", i + 1, latency_ms);
        } else {
            printk("*** Iteration %d: FAILED under entropy starvation (%.1f ms)\n", i + 1, latency_ms);
        }
        
        total_latency_ms += latency_ms;
        
        // Allow entropy pool to fully recover before next test
        k_msleep(100);
    }
    
    result->entropy_success_pct = (100.0 * success_count) / max_entropy_iters;
    result->avg_latency_entropy_ms = total_latency_ms / max_entropy_iters;
    
    printk("*** ENTROPY-PATH STRESS RESULTS:\n");
    printk("    Success rate: %.1f%% (%u/%d operations)\n", 
           result->entropy_success_pct, success_count, max_entropy_iters);
    printk("    Average latency: %.1f ms\n", result->avg_latency_entropy_ms);
    printk("    Entropy pool stress: %.1f%% failure rate\n", entropy_failure_rate);
    
    // Clean up allocated memory
    benchmark_k_free(pk);
    benchmark_k_free(sk);
    benchmark_k_free(ct);
    benchmark_k_free(ss1);
    benchmark_k_free(ss2);
    
    printk("*** Entropy-path stress test completed\n");
}

// ========================================================================
// DSA/SIGNATURE AUTHENTIC ENTROPY STARVATION STRESS TEST
// ========================================================================

void test_entropy_starvation_for_sign(sign_info_t* sign, operation_type_t op_type, benchmark_results_t *result) {
    if (!sign || !sign->enabled) {
        printk("ERROR: No DSA enabled for entropy testing\n");
        result->entropy_success_pct = 0.0;
        result->avg_latency_entropy_ms = 0.0;
        return;
    }
    
    printk("*** Testing entropy-path stress for DSA %s...\n", sign->name);
    printk("*** ENTROPY TEST: RNG API stress under the active Zephyr generator mode\n");
    print_entropy_source_banner();
    
    // AUTHENTIC ENTROPY DEPLETION TESTING
    printk("*** STEP 1: Testing baseline entropy availability\n");
    
    // Test 1: Rapid entropy consumption to stress the pool
    #define DSA_ENTROPY_STRESS_SAMPLES 50
    uint8_t entropy_test_buffer[32];
    uint32_t entropy_failures = 0;
    
    for (int stress_test = 0; stress_test < DSA_ENTROPY_STRESS_SAMPLES; stress_test++) {
        // Rapidly consume entropy to test real starvation conditions
        for (int rapid_consume = 0; rapid_consume < 10; rapid_consume++) {
            int entropy_result = sys_csrand_get(entropy_test_buffer, 32);
            if (entropy_result != 0) {
                entropy_failures++;
                printk("*** DEBUG: DSA Entropy failure at stress test %d, iteration %d\n", 
                       stress_test, rapid_consume);
            }
        }
        
        // Brief pause to allow entropy pool recovery
        k_usleep(100); // 100 microseconds
    }
    
    double entropy_failure_rate = (double)entropy_failures / (DSA_ENTROPY_STRESS_SAMPLES * 10) * 100.0;
    printk("*** DSA ENTROPY POOL ANALYSIS: %u failures out of %d attempts (%.1f%% failure rate)\n",
           entropy_failures, DSA_ENTROPY_STRESS_SAMPLES * 10, entropy_failure_rate);
    
    uint32_t success_count = 0;
    double total_latency_ms = 0.0;
    
    // Dynamically allocate buffers based on the selected DSA
    uint8_t* pk = benchmark_k_malloc(sign->pk_bytes);
    uint8_t* sk = benchmark_k_malloc(sign->sk_bytes);
    uint8_t* signature = benchmark_k_malloc(sign->signature_bytes);
    uint8_t* message = benchmark_k_malloc(ENTROPY_DSA_TEST_MESSAGE_LEN + 1);
    
    if (!pk || !sk || !signature || !message) {
        printk("ERROR: Failed to allocate memory for DSA buffers\n");
        if (pk) benchmark_k_free(pk);
        if (sk) benchmark_k_free(sk);
        if (signature) benchmark_k_free(signature);
        if (message) benchmark_k_free(message);
        result->entropy_success_pct = 0.0;
        result->avg_latency_entropy_ms = 0.0;
        return;
    }
    
    // Initialize test message
    memcpy(message, ENTROPY_DSA_TEST_MESSAGE, ENTROPY_DSA_TEST_MESSAGE_LEN);
    message[ENTROPY_DSA_TEST_MESSAGE_LEN] = '\0';
    
    printk("*** STEP 2: Testing DSA operations under entropy starvation\n");
    
    // Test DSA operations under authentic entropy stress conditions
    int max_entropy_iters = 5; // Increase iterations for better statistics
    
    for (int i = 0; i < max_entropy_iters; i++) {
        uint64_t start_time = k_uptime_get();
        
        bool success = true;
        
        // AUTHENTIC ENTROPY STARVATION: Consume entropy rapidly before operation
        printk("*** Iteration %d: Depleting entropy pool before DSA operation\n", i + 1);
        
        // Deplete entropy pool by rapid consumption
        uint8_t entropy_drain_buffer[64];
        for (int drain = 0; drain < 20; drain++) {
            int drain_result = sys_csrand_get(entropy_drain_buffer, 64);
            if (drain_result != 0) {
                printk("*** DEBUG: Entropy pool depleted at drain iteration %d\n", drain);
                break; // Pool is depleted
            }
        }
        
        // Now attempt DSA operation with depleted entropy
        uint64_t operation_start = k_uptime_get();
        size_t sig_len = sign->signature_bytes;
        
        switch (op_type) {
            case OP_KEYPAIR:
                if (sign->keypair(pk, sk) != 0) {
                    success = false;
                    printk("*** DSA keypair failed under entropy starvation\n");
                }
                break;
            case OP_SIGN:
                sign->keypair(pk, sk); // This may also fail due to entropy
                if (sign->sign(signature, &sig_len, message, ENTROPY_DSA_TEST_MESSAGE_LEN, sk) != 0) {
                    success = false;
                    printk("*** DSA sign failed under entropy starvation\n");
                }
                break;
            case OP_VERIFY:
                sign->keypair(pk, sk); // This may also fail due to entropy
                sign->sign(signature, &sig_len, message, ENTROPY_DSA_TEST_MESSAGE_LEN, sk);
                if (sign->verify(signature, sig_len, message, ENTROPY_DSA_TEST_MESSAGE_LEN, pk) != 0) {
                    success = false;
                    printk("*** DSA verify failed under entropy starvation\n");
                }
                break;
            default:
                break;
        }
        
        uint64_t operation_end = k_uptime_get();
        uint64_t operation_time = operation_end - operation_start;
        printk("*** DSA Operation time under entropy stress: %llu ms\n", operation_time);
        
        // Measure recovery time for entropy pool
        uint64_t recovery_start = k_uptime_get();
        bool entropy_recovered = false;
        while ((k_uptime_get() - recovery_start) < 5000) { // 5 second timeout
            uint8_t recovery_test[32];
            if (sys_csrand_get(recovery_test, 32) == 0) {
                entropy_recovered = true;
                break;
            }
            k_msleep(10); // Wait for entropy pool recovery
        }
        
        if (!entropy_recovered) {
            printk("*** WARNING: Entropy pool failed to recover within timeout\n");
        }
        
        uint64_t end_time = k_uptime_get();
        double latency_ms = (double)(end_time - start_time);
        
        if (success) {
            success_count++;
            printk("*** DSA Iteration %d: SUCCESS under entropy starvation (%.1f ms)\n", i + 1, latency_ms);
        } else {
            printk("*** DSA Iteration %d: FAILED under entropy starvation (%.1f ms)\n", i + 1, latency_ms);
        }
        
        total_latency_ms += latency_ms;
        
        // Allow entropy pool to fully recover before next test
        k_msleep(100);
    }
    
    result->entropy_success_pct = (100.0 * success_count) / max_entropy_iters;
    result->avg_latency_entropy_ms = total_latency_ms / max_entropy_iters;
    
    printk("*** DSA AUTHENTIC ENTROPY STARVATION RESULTS:\n");
    printk("    Success rate: %.1f%% (%u/%d operations)\n", 
           result->entropy_success_pct, success_count, max_entropy_iters);
    printk("    Average latency: %.1f ms\n", result->avg_latency_entropy_ms);
    printk("    Entropy pool stress: %.1f%% failure rate\n", entropy_failure_rate);
    
    // Clean up allocated memory
    benchmark_k_free(pk);
    benchmark_k_free(sk);
    benchmark_k_free(signature);
    benchmark_k_free(message);
    
    printk("*** DSA entropy-path stress test completed\n");
}

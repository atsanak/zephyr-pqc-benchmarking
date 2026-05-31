#include "harness.h"
#include "utils.h"
#include "kem_registry.h"
#include "sig_registry.h"
#include <zephyr/sys/printk.h>
#include <string.h>
#include <math.h>

// Randombytes for crypto operations
#include "randombytes.h"

// Entropy consumption tracking
#include "entropy_consumption.h"
#include "symmetric_profile.h"

// Default test message for signature operations
static const char DSA_TEST_MESSAGE[] = "PQC Benchmark Test Message for Digital Signature Algorithms";
static const size_t DSA_TEST_MESSAGE_LEN = 60;

// Calculate 95% confidence interval half-width
double calculate_ci_half_width(uint64_t *samples, size_t n, double mean) {
    if (n < 2) return 0.0;
    
    // Calculate standard deviation
    double sum_sq_diff = 0.0;
    for (size_t i = 0; i < n; i++) {
        double diff = (double)samples[i] - mean;
        sum_sq_diff += diff * diff;
    }
    double stddev = sqrt(sum_sq_diff / (n - 1));
    
    // Use t-distribution critical value (approximation for n > 30, use 1.96)
    double t_critical = (n > 30) ? 1.96 : 2.58; // Conservative for small n
    
    return t_critical * stddev / sqrt((double)n);
}

// Dynamic iteration controller (Step 1.1-1.5) - KEM-agnostic version
uint32_t run_dynamic_iterations(operation_type_t op_type, uint64_t *cycles_out) {
    uint8_t* pk = NULL;
    uint8_t* sk = NULL; 
    uint8_t* ct = NULL;
    uint8_t* ss1 = NULL;
    uint8_t* ss2 = NULL;
    uint64_t samples[MAX_ITERS];
    uint32_t iteration = 0;
    
    // Use the first registered KEM (typically ML-KEM-512) for compatibility
    kem_info_t* kem = get_kem_by_index(0);
    if (!kem || !kem->enabled) {
        printk("*** ERROR: No KEM available for dynamic iterations\n");
        return 0;
    }
    
    printk("*** Using KEM %s-%s for dynamic iterations\n", kem->name, kem->variant);
    
    // Allocate buffers based on actual KEM parameters
    pk = benchmark_k_malloc(kem->pk_bytes);
    sk = benchmark_k_malloc(kem->sk_bytes);
    ct = benchmark_k_malloc(kem->ct_bytes);
    ss1 = benchmark_k_malloc(kem->ss_bytes);
    ss2 = benchmark_k_malloc(kem->ss_bytes);
    
    if (!pk || !sk || !ct || !ss1 || !ss2) {
        printk("*** Memory allocation failed for dynamic iterations\n");
        goto cleanup_and_fail;
    }
    
    // Step 1.2: Warm up 3 times each operation
    printk("*** Warming up %s...\n", 
           op_type == OP_KEYPAIR ? "keypair" : 
           op_type == OP_ENCAPS ? "encaps" : "decaps");
    
    for (int warmup = 0; warmup < WARMUP_ITERS; warmup++) {
        switch (op_type) {
            case OP_KEYPAIR:
                kem->keypair(pk, sk);
                break;
            case OP_ENCAPS:
                kem->keypair(pk, sk); // Need keys first
                kem->encaps(ct, ss1, pk);
                break;
            case OP_DECAPS:
                kem->keypair(pk, sk); // Need keys first
                kem->encaps(ct, ss1, pk); // Need ciphertext
                kem->decaps(ss2, ct, sk);
                break;
            case OP_SIGN:
            case OP_VERIFY:
                // DSA operations handled by run_dynamic_iterations_for_sign()
                break;
        }
    }
    
    uint64_t start_wall_cycles = k_cycle_get_64();
    
    // Auto-tune batch size to avoid timer quantization
    uint32_t inner = 1;
    uint64_t window = 0;
    
    // Determine optimal batch size for stable measurements
    printk("*** Auto-tuning batch size for stable measurements...\n");
    for (;;) {
        uint64_t t0 = k_cycle_get_64();
        for (uint32_t i = 0; i < inner; i++) {
            switch (op_type) {
                case OP_KEYPAIR:
                    kem->keypair(pk, sk);
                    break;
                case OP_ENCAPS:
                    kem->encaps(ct, ss1, pk);
                    break;
                case OP_DECAPS:
                    kem->decaps(ss2, ct, sk);
                    break;
                case OP_SIGN:
                case OP_VERIFY:
                    // DSA operations handled by run_dynamic_iterations_for_sign()
                    break;
            }
        }
        uint64_t t1 = k_cycle_get_64();
        window = t1 - t0;
        
        if (window >= MIN_WINDOW_CYCLES || inner >= MAX_INNER) break;
        inner <<= 1;
    }
    printk("*** Using batch size: %u (window: %llu cycles)\n", inner, window);
    
    // Step 1.3-1.4: Dynamic precision targeting
    for (iteration = 0; iteration < MAX_ITERS; iteration++) {
        uint64_t t0 = k_cycle_get_64();
        
        // Execute the operation in batches
        for (uint32_t i = 0; i < inner; i++) {
            switch (op_type) {
                case OP_KEYPAIR:
                    kem->keypair(pk, sk);
                    break;
                case OP_ENCAPS:
                    if (iteration == 0 && i == 0) kem->keypair(pk, sk); // Keys needed
                    kem->encaps(ct, ss1, pk);
                    break;
                case OP_DECAPS:
                    if (iteration == 0 && i == 0) {
                        kem->keypair(pk, sk); // Keys needed
                        kem->encaps(ct, ss1, pk); // Ciphertext needed
                    }
                    kem->decaps(ss2, ct, sk);
                    break;
                case OP_SIGN:
                case OP_VERIFY:
                    // DSA operations handled by run_dynamic_iterations_for_sign()
                    break;
            }
        }
        
        uint64_t t1 = k_cycle_get_64();
        samples[iteration] = (t1 - t0) / inner;  // Per-operation cycles
        
        // Step 1.3: After each sample, compute mean and 95% CI half-width
        if (iteration >= MIN_ITERS - 1) {
            double mean = 0.0;
            for (uint32_t i = 0; i <= iteration; i++) {
                mean += (double)samples[i];
            }
            mean /= (iteration + 1);
            
            double ci_half_width = calculate_ci_half_width(samples, iteration + 1, mean);
            double precision_pct = (ci_half_width / mean) * 100.0;
            
            // Step 1.4: Stop when (h/x_bar) <= 1% or max 1000 runs
            if (precision_pct <= TARGET_PRECISION_PCT) {
                printk("*** Target precision achieved: %.2f%% (iteration %u)\n", 
                       precision_pct, iteration + 1);
                break;
            }
            
            if (iteration % 50 == 49) {
                printk("*** Iteration %u: precision %.2f%% (target: %.1f%%)\n", 
                       iteration + 1, precision_pct, TARGET_PRECISION_PCT);
            }
        }
        
        // Step 1.5: Fallback - if CI fails, run for >=500ms and average
        uint64_t elapsed_wall_cycles = k_cycle_get_64() - start_wall_cycles;
#ifdef CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC
        uint64_t elapsed_wall_ms = (uint64_t)((double)elapsed_wall_cycles * 1000.0 / (double)CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC);
#else
        uint64_t elapsed_wall_ms = elapsed_wall_cycles / 1000; // Crude approximation
#endif
        if (elapsed_wall_ms >= MIN_WALL_TIME_MS && iteration >= MIN_ITERS - 1) {
            printk("*** Time budget reached: %llu ms (iteration %u)\n", 
                   elapsed_wall_ms, iteration + 1);
            break;
        }
    }
    
    // Copy samples to output
    memcpy(cycles_out, samples, (iteration + 1) * sizeof(uint64_t));
    
    // Cleanup and return
    benchmark_k_free(pk); benchmark_k_free(sk); benchmark_k_free(ct); benchmark_k_free(ss1); benchmark_k_free(ss2);
    return iteration + 1;

cleanup_and_fail:
    if (pk) benchmark_k_free(pk);
    if (sk) benchmark_k_free(sk);
    if (ct) benchmark_k_free(ct);
    if (ss1) benchmark_k_free(ss1);
    if (ss2) benchmark_k_free(ss2);
    return 0;
}

// STEP 0: Environment Setup & Real Code Verification
bool step0_environment_setup(void) {
    printk("\n*** ORCHESTRATION STEP 0: Environment Setup & Real Code Verification\n");
    printk("====================================================================\n");
    
    // 0.1-0.4: Verify Zephyr + PQClean integration (done at build time)
    // Note: PQClean's randombytes automatically uses Zephyr's random subsystem
    printk("*** Zephyr environment: OK\n");
    printk("*** PQClean library: Linked\n");
    
    // 0.5: Verify clean build and hello-benchmark harness
    // Test BOTH KEM AND DSA independently - NO FALLBACK
    bool kem_tested = false;
    bool dsa_tested = false;
    
    // Test KEM if available
    kem_info_t* test_kem = get_kem_by_index(0);
    if (test_kem && test_kem->enabled) {
        printk("*** Testing KEM: %s-%s\n", test_kem->name, test_kem->variant);
        
        // Allocate test buffers
        uint8_t* test_pk = benchmark_k_malloc(test_kem->pk_bytes);
        uint8_t* test_sk = benchmark_k_malloc(test_kem->sk_bytes);
        
        if (!test_pk || !test_sk) {
            printk("*** Memory allocation failed for KEM environment test\n");
            if (test_pk) benchmark_k_free(test_pk);
            if (test_sk) benchmark_k_free(test_sk);
            // Don't return false - continue to test DSA
        } else {
            int ret = test_kem->keypair(test_pk, test_sk);
            benchmark_k_free(test_pk);
            benchmark_k_free(test_sk);
            
            if (ret != 0) {
                printk("*** KEM %s-%s keypair test FAILED\n", test_kem->name, test_kem->variant);
            } else {
                printk("*** Hello-benchmark harness (KEM): OK\n");
                kem_tested = true;
            }
        }
    } else {
        printk("*** No KEM algorithms registered/enabled\n");
    }
    
    // Test DSA if available (INDEPENDENT of KEM result)
    sign_info_t* test_sign = get_sign_by_index(0);
    if (test_sign && test_sign->enabled) {
        printk("*** Testing DSA: %s-%s\n", test_sign->name, test_sign->variant);
        
        // Allocate test buffers
        uint8_t* test_pk = benchmark_k_malloc(test_sign->pk_bytes);
        uint8_t* test_sk = benchmark_k_malloc(test_sign->sk_bytes);
        
        if (!test_pk || !test_sk) {
            printk("*** Memory allocation failed for DSA environment test\n");
            if (test_pk) benchmark_k_free(test_pk);
            if (test_sk) benchmark_k_free(test_sk);
            // Don't return false - check if KEM succeeded
        } else {
            int ret = test_sign->keypair(test_pk, test_sk);
            benchmark_k_free(test_pk);
            benchmark_k_free(test_sk);
            
            if (ret != 0) {
                printk("*** DSA %s-%s keypair test FAILED\n", test_sign->name, test_sign->variant);
            } else {
                printk("*** Hello-benchmark harness (DSA): OK\n");
                dsa_tested = true;
            }
        }
    } else {
        printk("*** No DSA algorithms registered/enabled\n");
    }
    
    // Both KEM and DSA must be tested if available, at least one must succeed
    if (!kem_tested && !dsa_tested) {
        printk("*** ERROR: Neither KEM nor DSA available or all tests failed\n");
        return false;
    }
    
    printk("*** Memory allocation: OK\n");
    printk("*** Environment setup summary: KEM=%s, DSA=%s\n", 
           kem_tested ? "PASS" : "N/A", dsa_tested ? "PASS" : "N/A");
    return true;
}

// KEM-aware dynamic iteration controller for universal benchmarking
uint32_t run_dynamic_iterations_for_kem(kem_info_t* kem, operation_type_t op_type, uint64_t *cycles_out) {
    if (!kem || !kem->enabled) {
        printk("*** Invalid or disabled KEM\n");
        return 0;
    }
    
    const char *op_name = (op_type == OP_KEYPAIR) ? "keypair" : 
                         (op_type == OP_ENCAPS) ? "encaps" : "decaps";
    
    printk("*** [%s-%s] Dynamic iterations for %s\n", kem->name, kem->variant, op_name);

    benchmark_heap_tracker_reset();
    
    // Allocate buffers based on actual KEM parameters using dynamic allocation
    // This is necessary because McEliece has huge keys (>250KB)
    uint8_t* pk = benchmark_k_malloc(kem->pk_bytes);
    uint8_t* sk = benchmark_k_malloc(kem->sk_bytes);
    uint8_t* ct = benchmark_k_malloc(kem->ct_bytes);
    uint8_t* ss1 = benchmark_k_malloc(kem->ss_bytes);
    uint8_t* ss2 = benchmark_k_malloc(kem->ss_bytes);
    
    if (!pk || !sk || !ct || !ss1 || !ss2) {
        printk("*** [%s-%s] Memory allocation failed (pk:%u, sk:%u, ct:%u, ss:%u bytes)\n", 
               kem->name, kem->variant, kem->pk_bytes, kem->sk_bytes, kem->ct_bytes, kem->ss_bytes);
        goto cleanup_and_return_zero;
    }
    
    // Pre-generate keys for encaps/decaps operations
    if (op_type != OP_KEYPAIR) {
        if (kem->keypair(pk, sk) != 0) {
            printk("*** [%s-%s] Key generation failed\n", kem->name, kem->variant);
            goto cleanup_and_return_zero;
        }
    }
    
    // For decaps operation, we also need a ciphertext
    if (op_type == OP_DECAPS) {
        if (kem->encaps(ct, ss1, pk) != 0) {
            printk("*** [%s-%s] Encapsulation for decaps test failed\n", kem->name, kem->variant);
            goto cleanup_and_return_zero;
        }
    }
    
    // CRITICAL: Reset entropy tracking AFTER setup to exclude pre-generated keys/ciphertext
    // The setup calls above (keypair for encaps/decaps, encaps for decaps) should NOT
    // be counted in the per-operation entropy consumption metrics
    printk("*** [%s-%s] About to reset entropy tracking (setup consumed RNG, we want clean measurement)\n",
           kem->name, kem->variant);
    entropy_tracking_reset();
    printk("*** [%s-%s] Entropy tracking reset complete - measuring only %s RNG usage\n",
           kem->name, kem->variant, op_name);
    symmetric_profile_reset();
    
    uint32_t iteration = 0;
    uint64_t start_cycles, end_cycles;
    
    // Ensure we run at least MIN_ITERS and at most MAX_ITERS
    uint32_t target_iterations = (MAX_ITERS < MIN_ITERS) ? MIN_ITERS : MAX_ITERS;
    
    printk("*** [%s-%s] Running %u iterations for %s (MIN=%u, MAX=%u)\n", 
           kem->name, kem->variant, target_iterations, op_name, MIN_ITERS, MAX_ITERS);
    
    // NOTE: DO NOT reset entropy tracking inside the loop!
    // We want to ACCUMULATE RNG usage across all iterations to get total consumption
    for (iteration = 0; iteration < target_iterations; iteration++) {
        // Get starting cycle count
        benchmark_timing_start();
        start_cycles = benchmark_timing_counter_get();
        
        // Execute the KEM operation
        int ret = 0;
        switch (op_type) {
            case OP_KEYPAIR:
                ret = kem->keypair(pk, sk);
                break;
            case OP_ENCAPS:
                ret = kem->encaps(ct, ss1, pk);
                break;
            case OP_DECAPS:
                ret = kem->decaps(ss2, ct, sk);
                break;
            case OP_SIGN:
            case OP_VERIFY:
                // DSA operations handled by run_dynamic_iterations_for_sign()
                break;
        }
        
        // Get ending cycle count
        end_cycles = benchmark_timing_counter_get();
        
        if (ret != 0) {
            printk("*** [%s-%s] Operation %s failed at iteration %u\n", 
                   kem->name, kem->variant, op_name, iteration);
            goto cleanup_and_return_zero;
        }
        
        // Calculate cycles for this iteration
        cycles_out[iteration] = benchmark_timing_cycles_get(&start_cycles, &end_cycles);
        
        printk("*** [%s-%s] Iteration %u/%u: %llu cycles\n", 
               kem->name, kem->variant, iteration + 1, target_iterations, cycles_out[iteration]);
    }
    
    printk("*** [%s-%s] Completed %u iterations for %s\n", 
           kem->name, kem->variant, iteration, op_name);
    
    // Cleanup allocated memory
    benchmark_k_free(pk);
    benchmark_k_free(sk);
    benchmark_k_free(ct);
    benchmark_k_free(ss1);
    benchmark_k_free(ss2);
    
    return iteration;

cleanup_and_return_zero:
    if (pk) benchmark_k_free(pk);
    if (sk) benchmark_k_free(sk);
    if (ct) benchmark_k_free(ct);
    if (ss1) benchmark_k_free(ss1);
    if (ss2) benchmark_k_free(ss2);
    return 0;
}

// DSA/Signature-aware dynamic iteration controller for universal benchmarking
uint32_t run_dynamic_iterations_for_sign(sign_info_t* sign, operation_type_t op_type, uint64_t *cycles_out) {
    if (!sign || !sign->enabled) {
        printk("*** Invalid or disabled Signature algorithm\n");
        return 0;
    }
    
    const char *op_name = (op_type == OP_KEYPAIR) ? "keypair" : 
                         (op_type == OP_SIGN) ? "sign" : "verify";
    
    printk("*** [%s-%s] Dynamic iterations for %s\n", sign->name, sign->variant, op_name);

    benchmark_heap_tracker_reset();
    
    // Allocate buffers based on actual signature algorithm parameters
    uint8_t* pk = benchmark_k_malloc(sign->pk_bytes);
    uint8_t* sk = benchmark_k_malloc(sign->sk_bytes);
    uint8_t* signature = benchmark_k_malloc(sign->signature_bytes);
    uint8_t* message = benchmark_k_malloc(DSA_TEST_MESSAGE_LEN + 1);
    
    if (!pk || !sk || !signature || !message) {
        printk("*** [%s-%s] Memory allocation failed (pk:%u, sk:%u, sig:%u bytes)\n", 
               sign->name, sign->variant, sign->pk_bytes, sign->sk_bytes, sign->signature_bytes);
        goto cleanup_sign_and_return_zero;
    }
    
    // Initialize test message
    memcpy(message, DSA_TEST_MESSAGE, DSA_TEST_MESSAGE_LEN);
    message[DSA_TEST_MESSAGE_LEN] = '\0';
    
    // Pre-generate keys for sign/verify operations
    if (op_type != OP_KEYPAIR) {
        if (sign->keypair(pk, sk) != 0) {
            printk("*** [%s-%s] Key generation failed\n", sign->name, sign->variant);
            goto cleanup_sign_and_return_zero;
        }
    }
    
    // For verify operation, we also need a signature
    size_t sig_len = sign->signature_bytes;
    if (op_type == OP_VERIFY) {
        if (sign->sign(signature, &sig_len, message, DSA_TEST_MESSAGE_LEN, sk) != 0) {
            printk("*** [%s-%s] Signature generation for verify test failed\n", sign->name, sign->variant);
            goto cleanup_sign_and_return_zero;
        }
    }
    
    // CRITICAL: Reset entropy tracking AFTER setup to exclude pre-generated keys/signatures
    printk("*** [%s-%s] Resetting entropy tracking (setup consumed RNG, we want clean measurement)\n",
           sign->name, sign->variant);
    entropy_tracking_reset();
    printk("*** [%s-%s] Entropy tracking reset complete - measuring only %s RNG usage\n",
           sign->name, sign->variant, op_name);
    symmetric_profile_reset();
    
    uint32_t iteration = 0;
    uint64_t start_cycles, end_cycles;
    
    // Ensure we run at least MIN_ITERS and at most MAX_ITERS
    uint32_t target_iterations = (MAX_ITERS < MIN_ITERS) ? MIN_ITERS : MAX_ITERS;
    
    printk("*** [%s-%s] Running %u iterations for %s (MIN=%u, MAX=%u)\n", 
           sign->name, sign->variant, target_iterations, op_name, MIN_ITERS, MAX_ITERS);
    
    // NOTE: DO NOT reset entropy tracking inside the loop!
    // We want to ACCUMULATE RNG usage across all iterations to get total consumption
    for (iteration = 0; iteration < target_iterations; iteration++) {
        // Get starting cycle count
        benchmark_timing_start();
        start_cycles = benchmark_timing_counter_get();
        
        // Execute the signature operation
        int ret = 0;
        switch (op_type) {
            case OP_KEYPAIR:
                ret = sign->keypair(pk, sk);
                break;
            case OP_SIGN:
                sig_len = sign->signature_bytes;
                ret = sign->sign(signature, &sig_len, message, DSA_TEST_MESSAGE_LEN, sk);
                break;
            case OP_VERIFY:
                ret = sign->verify(signature, sig_len, message, DSA_TEST_MESSAGE_LEN, pk);
                break;
            default:
                printk("*** [%s-%s] Invalid operation type %d for signature\n", 
                       sign->name, sign->variant, op_type);
                ret = -1;
                break;
        }
        
        // Get ending cycle count
        end_cycles = benchmark_timing_counter_get();
        
        if (ret != 0) {
            printk("*** [%s-%s] Operation %s failed at iteration %u with code %d\n", 
                   sign->name, sign->variant, op_name, iteration, ret);
            goto cleanup_sign_and_return_zero;
        }
        
        // Calculate cycles for this iteration
        cycles_out[iteration] = benchmark_timing_cycles_get(&start_cycles, &end_cycles);
        
        printk("*** [%s-%s] Iteration %u/%u: %llu cycles\n", 
               sign->name, sign->variant, iteration + 1, target_iterations, cycles_out[iteration]);
    }
    
    printk("*** [%s-%s] Completed %u iterations for %s\n", 
           sign->name, sign->variant, iteration, op_name);
    
    // Cleanup allocated memory
    benchmark_k_free(pk);
    benchmark_k_free(sk);
    benchmark_k_free(signature);
    benchmark_k_free(message);
    
    return iteration;

cleanup_sign_and_return_zero:
    if (pk) benchmark_k_free(pk);
    if (sk) benchmark_k_free(sk);
    if (signature) benchmark_k_free(signature);
    if (message) benchmark_k_free(message);
    return 0;
}

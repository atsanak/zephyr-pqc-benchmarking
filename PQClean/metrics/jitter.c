#include "metric.h"
#include "harness.h"
#include "utils.h"
#include "timing_port.h"
#include <zephyr/sys/printk.h>
#include <zephyr/kernel.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>

// Enable robust statistical calculations (MAD, proper percentiles)
#define JITTER_ROBUST_STATS

// PQClean KEM and DSA Registries
#include "kem_registry.h"
#include "sig_registry.h"

// Default test message for DSA signature operations
static const char JITTER_DSA_TEST_MESSAGE[] = "PQC Jitter Test Message for Digital Signatures";
static const size_t JITTER_DSA_TEST_MESSAGE_LEN = 47;

// --- Statistical helpers: surgical fixes for MAD/percentiles/stddev ---
static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return (x > y) - (x < y);
}

// Safe absolute difference for unsigned 64-bit, avoids underflow.
static inline uint64_t u64_abs_diff(uint64_t a, uint64_t b) {
    return (a > b) ? (a - b) : (b - a);
}

// Numerically stable mean/stddev (sample) using Welford in double.
static void welford_stats(const uint64_t *x, size_t n, double *mean, double *sd) {
    double m = 0.0, s = 0.0;
    for (size_t k = 0; k < n; k++) {
        double v = (double)x[k];
        double d = v - m;
        m += d / (k + 1);
        s += d * (v - m);
    }
    *mean = m;
    *sd   = (n > 1) ? sqrt(s / (n - 1)) : 0.0; // sample stdev
}

// Percentile with (n-1) rank and linear interpolation.
// 'sorted' MUST be non-decreasing.
static uint64_t percentile_u64(const uint64_t *sorted, size_t n, double p) {
    if (n == 0) return 0;
    if (p <= 0.0)  return sorted[0];
    if (p >= 100.) return sorted[n-1];

    double pos = (p/100.0) * (double)(n - 1); // <- key: n-1
    size_t lo  = (size_t)floor(pos);
    size_t hi  = (size_t)ceil(pos);
    double frac = pos - (double)lo;

    if (hi == lo) return sorted[lo];
    double v = (1.0 - frac) * (double)sorted[lo] + frac * (double)sorted[hi];
    return (uint64_t) llround(v);
}

static inline uint64_t median_from_sorted(const uint64_t *sorted, size_t n) {
    return percentile_u64(sorted, n, 50.0);
}

// Median Absolute Deviation (MAD): median(|xi - median(x)|).
// 'scratch' is a temp buffer with length >= n.
static uint64_t mad_u64(const uint64_t *samples, size_t n, uint64_t median,
                        uint64_t *scratch) {
    for (size_t i = 0; i < n; i++) {
        scratch[i] = u64_abs_diff(samples[i], median);
    }
    qsort(scratch, n, sizeof(uint64_t), cmp_u64);
    return median_from_sorted(scratch, n);
}

// ========================================================================
// STEP 4: TIMING STABILITY (JITTER) - Publication-Grade Implementation
// ========================================================================

void measure_timing_jitter(operation_type_t op_type, benchmark_results_t *result) {
    // Get the currently enabled KEM
    kem_info_t* kem = get_enabled_kem();
    if (!kem) {
        printk("ERROR: No KEM enabled for jitter measurement\n");
        result->jitter_cycles = 0;
        return;
    }
    
    printk("*** Measuring publication-grade timing jitter for %s...\n", kem->name);
    printk("*** METHOD: N=%u cycle-precision samples with Welford variance\n", JITTER_SAMPLES);
    
    // ---- Prepare inputs once (no interference inside the measured window)
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
        result->jitter_cycles = 0;
        return;
    }

    kem->keypair(pk, sk);
    if (op_type == OP_DECAPS) kem->encaps(ct, ss1, pk);

    // ---- Batch size auto-tune to avoid timer quantization
    uint32_t inner = 1;
    uint64_t window = 0;
    for (;;) {
        uint64_t t0 = tp_now_cycles();
        for (uint32_t i = 0; i < inner; i++) {
            switch (op_type) {
            case OP_KEYPAIR: kem->keypair(pk, sk); break;
            case OP_ENCAPS:  kem->encaps(ct, ss1, pk); break;
            case OP_DECAPS:  kem->decaps(ss2, ct, sk); break;
            case OP_SIGN:
            case OP_VERIFY:
                // DSA operations handled by measure_timing_jitter_for_sign()
                break;
            }
        }
        uint64_t t1 = tp_now_cycles();
        window = t1 - t0;
        if (window >= MIN_WINDOW_CYCLES || inner >= MAX_INNER) break;
        inner <<= 1;
    }
    printk("*** Using batch size: %u (window: %llu cycles)\n", inner, window);

    // ---- Collect N samples (pure cycle timing)
    const uint32_t N = JITTER_SAMPLES; 
    uint64_t minc = UINT64_MAX, maxc = 0;
    // Welford's online variance (double-precision)
    double mean = 0.0, M2 = 0.0;
    
#ifdef JITTER_ROBUST_STATS
    // Store samples for quantiles/MAD computation
    uint64_t *samples = benchmark_k_malloc(N * sizeof(uint64_t));
    if (!samples) {
        printk("WARNING: Cannot allocate sample buffer for robust stats\n");
    }
#endif
    
    for (uint32_t s = 0; s < N; s++) {
        uint64_t t0 = tp_now_cycles();
        for (uint32_t i = 0; i < inner; i++) {
            switch (op_type) {
            case OP_KEYPAIR: kem->keypair(pk, sk); break;
            case OP_ENCAPS:  kem->encaps(ct, ss1, pk); break;
            case OP_DECAPS:  kem->decaps(ss2, ct, sk); break;
            case OP_SIGN:
            case OP_VERIFY:
                // DSA operations handled by measure_timing_jitter_for_sign()
                break;
            }
        }
        uint64_t t1 = tp_now_cycles();
        uint64_t cycles = (t1 - t0) / inner;

        if (cycles < minc) minc = cycles;
        if (cycles > maxc) maxc = cycles;

        double x = (double)cycles;
        double delta = x - mean;
        mean += delta / (double)(s + 1);
        M2   += delta * (x - mean);
        
#ifdef JITTER_ROBUST_STATS
        // Store sample for quantiles/MAD computation
        if (samples != NULL) {
            samples[s] = cycles;
        }
#endif
        
        // Show sample progress for first few measurements
        if (s < 5) {
            printk("*** Sample %u: %llu cycles\n", s + 1, cycles);
        }
    }

    // --- SURGICAL FIX: Replace old statistics computation with robust helpers ---
#ifdef JITTER_ROBUST_STATS
    if (samples != NULL) {
        // 1) Welford statistics (from stored samples)
        double mean_d, sd_d;
        welford_stats(samples, N, &mean_d, &sd_d);
        
        // 2) Sorted copy for order stats
        uint64_t *sortbuf = benchmark_k_malloc(N * sizeof(uint64_t));
        uint64_t *scratch = benchmark_k_malloc(N * sizeof(uint64_t));
        
        if (sortbuf != NULL && scratch != NULL) {
            printk("*** SURGICAL PATH: Using corrected statistics (sortbuf=%p scratch=%p)\n", sortbuf, scratch);
            memcpy(sortbuf, samples, N * sizeof(uint64_t));
            qsort(sortbuf, N, sizeof(uint64_t), cmp_u64);

            // 3) Order statistics & jitter (corrected) - using IDENTICAL sample set
            uint64_t min_c  = sortbuf[0];
            uint64_t max_c  = sortbuf[N - 1];
            uint64_t p50_c  = median_from_sorted(sortbuf, N);
            uint64_t p95_c  = percentile_u64(sortbuf, N, 95.0);
            uint64_t p99_c  = percentile_u64(sortbuf, N, 99.0);
            uint64_t jitter = max_c - min_c;

            // 4) MAD (from the true median, using safe abs diff)
            uint64_t mad_c  = mad_u64(samples, N, p50_c, scratch);

            // 5) Unit consistency verification (surgical debugging)
            double welford_min = (double)min_c;
            double welford_max = (double)max_c; 
            double welford_range = welford_max - welford_min;
            double sd_cap = 0.5 * welford_range * sqrt((double)N / (double)(N - 1));
            if (sd_d > sd_cap + 1.0) {
                printk("*** UNIT MISMATCH DETECTED: sd=%.1f > cap=%.1f (range=%.1f, N=%u)\n",
                       sd_d, sd_cap, welford_range, N);
                printk("*** Welford samples[0]=%llu samples[%u]=%llu\n", samples[0], N-1, samples[N-1]); 
                printk("*** Sorted min=%llu max=%llu (should be identical to samples min/max)\n", min_c, max_c);
            }

            // 6) Store JITTER-SPECIFIC values ONLY - DO NOT overwrite baseline stats!
            // Baseline stats (avg_cycles, min_cycles, max_cycles, stddev_cycles, p50, p95, p99, MAD, CV)
            // now ALL come from calculate_baseline_stats() using the SAME N samples.
            // Jitter measurement ONLY sets jitter_cycles (max-min from batch-tuned samples).
            result->jitter_cycles = jitter;
            // NOTE: p50/p95/p99/MAD/CV are now set by calculate_baseline_stats() from baseline samples
            // We no longer overwrite them here to maintain statistical consistency
            
            // Log jitter-specific statistics for diagnostic purposes (not stored to result)
            printk("*** JITTER DIAGNOSTIC: batch_min=%llu batch_max=%llu batch_jitter=%llu\n",
                   min_c, max_c, jitter);
            printk("*** JITTER DIAGNOSTIC: batch_p50=%llu batch_p95=%llu batch_p99=%llu batch_MAD=%llu\n",
                   p50_c, p95_c, p99_c, mad_c);
            
            // Sanity check: compare baseline percentiles with jitter percentiles for research insight
            if (result->p50_cycles > 0) {
                double p50_ratio = (double)p50_c / (double)result->p50_cycles;
                if (p50_ratio < 0.8 || p50_ratio > 1.2) {
                    printk("*** INFO: Jitter batch p50 differs from baseline by %.1f%% (expected due to batching)\n",
                           100.0 * (p50_ratio - 1.0));
                }
            }

            
            // Sanity: sample SD cap for N samples (reuse sd_cap from unit verification)
            if ((double)result->stddev_cycles > sd_cap + 1.0) {
                printk("WARNING[jitter]: sd=%llu > cap=%.1f (range=%llu, N=%u)\n",
                       (unsigned long long)result->stddev_cycles, sd_cap,
                       (unsigned long long)(result->max_cycles - result->min_cycles), N);
            }            // Optional: robust RMS proxy (Gaussian-consistent MAD scaling)
            // result->robust_rms_cycles = (uint64_t)llround(1.4826 * (double)mad_c);
            
            printk("*** CORRECTED JITTER STATS: N=%u  min=%llu  max=%llu  avg=%llu  jitter=%llu  stddev=%llu\n",
                   N, min_c, max_c, result->avg_cycles, jitter, result->stddev_cycles);
            printk("    Robust Statistics: p50=%llu p95=%llu p99=%llu MAD=%llu CV=%.3f%%\n", 
                   p50_c, p95_c, p99_c, mad_c, result->coefficient_variation_pct);
            printk("    Unit Verification: computed_sd=%.1f stored_sd=%llu cap=%.1f\n", 
                   sd_d, result->stddev_cycles, sd_cap);
        } else {
            printk("*** FALLBACK PATH: sortbuf/scratch malloc failed (sortbuf=%p scratch=%p)\n", sortbuf, scratch);
            printk("*** WARNING: Using fallback calculation - jitter only, baseline preserved\n");
            // Fallback when sortbuf/scratch buffer allocation failed
            // ONLY set jitter_cycles - p50/p95/p99/MAD/CV are set by calculate_baseline_stats()
            result->jitter_cycles = maxc - minc;
            // NOTE: p50/p95/p99/MAD/CV already set by calculate_baseline_stats()
        }
        
        // Clean up scratch buffers
        if (sortbuf) benchmark_k_free(sortbuf);
        if (scratch) benchmark_k_free(scratch);
        benchmark_k_free(samples);
    } else {
        printk("*** SAMPLES FALLBACK PATH: samples malloc failed\n");
        // Fallback when sample buffer allocation failed at start
        // ONLY set jitter_cycles - p50/p95/p99/MAD/CV are set by calculate_baseline_stats()
        result->jitter_cycles = maxc - minc;
        // NOTE: p50/p95/p99/MAD/CV already set by calculate_baseline_stats()
    }
#else
    // Original calculation when JITTER_ROBUST_STATS not enabled
    // ONLY set jitter_cycles - p50/p95/p99/MAD/CV are set by calculate_baseline_stats()
    result->jitter_cycles = maxc - minc;
    // NOTE: p50/p95/p99/MAD/CV already set by calculate_baseline_stats()
#endif

    // ---- Print jitter classification based on corrected values ---
    double jitter_pct = (result->avg_cycles > 0) ? (100.0 * (double)result->jitter_cycles / (double)result->avg_cycles) : 0.0;
    printk("*** FINAL JITTER SUMMARY: N=%u  min=%llu  max=%llu  avg=%llu  jitter=%llu  stddev=%llu  jitter%%=%.3f%%\n",
           N, result->min_cycles, result->max_cycles, result->avg_cycles, result->jitter_cycles, result->stddev_cycles, jitter_pct);

    // Classify jitter characteristics for publication analysis
    if (jitter_pct < 1.0) {
        printk("    Jitter classification: VERY LOW (< 1%% variance)\n");
    } else if (jitter_pct < 5.0) {
        printk("    Jitter classification: LOW (1-5%% variance)\n");
    } else if (jitter_pct < 15.0) {
        printk("    Jitter classification: MODERATE (5-15%% variance)\n");
    } else {
        printk("    Jitter classification: HIGH (> 15%% variance)\n");
    }

    printk("    Coefficient of Variation: %.3f%% (Corrected from robust stddev)\n", result->coefficient_variation_pct);

    // Clean up allocated memory
    benchmark_k_free(pk);
    benchmark_k_free(sk);
    benchmark_k_free(ct);
    benchmark_k_free(ss1);
    benchmark_k_free(ss2);
}

// ========================================================================
// DSA/SIGNATURE TIMING STABILITY (JITTER) - Publication-Grade Implementation
// ========================================================================

void measure_timing_jitter_for_sign(sign_info_t* sign, operation_type_t op_type, benchmark_results_t *result) {
    if (!sign || !sign->enabled) {
        printk("ERROR: No DSA enabled for jitter measurement\n");
        result->jitter_cycles = 0;
        return;
    }
    
    printk("*** Measuring publication-grade timing jitter for DSA %s...\n", sign->name);
    printk("*** METHOD: N=%u cycle-precision samples with Welford variance\n", JITTER_SAMPLES);
    
    // ---- Prepare inputs once (no interference inside the measured window)
    uint8_t* pk = benchmark_k_malloc(sign->pk_bytes);
    uint8_t* sk = benchmark_k_malloc(sign->sk_bytes);
    uint8_t* signature = benchmark_k_malloc(sign->signature_bytes);
    uint8_t* message = benchmark_k_malloc(JITTER_DSA_TEST_MESSAGE_LEN + 1);
    
    if (!pk || !sk || !signature || !message) {
        printk("ERROR: Failed to allocate memory for DSA buffers\n");
        if (pk) benchmark_k_free(pk);
        if (sk) benchmark_k_free(sk);
        if (signature) benchmark_k_free(signature);
        if (message) benchmark_k_free(message);
        result->jitter_cycles = 0;
        return;
    }

    // Initialize test message
    memcpy(message, JITTER_DSA_TEST_MESSAGE, JITTER_DSA_TEST_MESSAGE_LEN);
    message[JITTER_DSA_TEST_MESSAGE_LEN] = '\0';
    
    // Pre-generate keys for sign/verify operations
    sign->keypair(pk, sk);
    
    // Pre-generate signature for verify operation
    size_t sig_len = sign->signature_bytes;
    if (op_type == OP_VERIFY) {
        sign->sign(signature, &sig_len, message, JITTER_DSA_TEST_MESSAGE_LEN, sk);
    }

    // ---- Batch size auto-tune to avoid timer quantization
    uint32_t inner = 1;
    uint64_t window = 0;
    for (;;) {
        uint64_t t0 = tp_now_cycles();
        for (uint32_t i = 0; i < inner; i++) {
            switch (op_type) {
            case OP_KEYPAIR: sign->keypair(pk, sk); break;
            case OP_SIGN:    sig_len = sign->signature_bytes; sign->sign(signature, &sig_len, message, JITTER_DSA_TEST_MESSAGE_LEN, sk); break;
            case OP_VERIFY:  sign->verify(signature, sig_len, message, JITTER_DSA_TEST_MESSAGE_LEN, pk); break;
            default: break;
            }
        }
        uint64_t t1 = tp_now_cycles();
        window = t1 - t0;
        if (window >= MIN_WINDOW_CYCLES || inner >= MAX_INNER) break;
        inner <<= 1;
    }
    printk("*** Using batch size: %u (window: %llu cycles)\n", inner, window);

    // ---- Collect N samples (pure cycle timing)
    const uint32_t N = JITTER_SAMPLES; 
    uint64_t minc = UINT64_MAX, maxc = 0;
    // Welford's online variance (double-precision)
    double mean = 0.0, M2 = 0.0;
    
#ifdef JITTER_ROBUST_STATS
    // Store samples for quantiles/MAD computation
    uint64_t *samples = benchmark_k_malloc(N * sizeof(uint64_t));
    if (!samples) {
        printk("WARNING: Cannot allocate sample buffer for robust stats\n");
    }
#endif
    
    for (uint32_t s = 0; s < N; s++) {
        uint64_t t0 = tp_now_cycles();
        for (uint32_t i = 0; i < inner; i++) {
            switch (op_type) {
            case OP_KEYPAIR: sign->keypair(pk, sk); break;
            case OP_SIGN:    sig_len = sign->signature_bytes; sign->sign(signature, &sig_len, message, JITTER_DSA_TEST_MESSAGE_LEN, sk); break;
            case OP_VERIFY:  sign->verify(signature, sig_len, message, JITTER_DSA_TEST_MESSAGE_LEN, pk); break;
            default: break;
            }
        }
        uint64_t t1 = tp_now_cycles();
        uint64_t cycles = (t1 - t0) / inner;

        if (cycles < minc) minc = cycles;
        if (cycles > maxc) maxc = cycles;

        double x = (double)cycles;
        double delta = x - mean;
        mean += delta / (double)(s + 1);
        M2   += delta * (x - mean);
        
#ifdef JITTER_ROBUST_STATS
        if (samples != NULL) {
            samples[s] = cycles;
        }
#endif
        
        // Show sample progress for first few measurements
        if (s < 5) {
            printk("*** DSA Sample %u: %llu cycles\n", s + 1, cycles);
        }
    }

    // --- Use robust helpers for statistics computation ---
#ifdef JITTER_ROBUST_STATS
    if (samples != NULL) {
        // 1) Welford statistics (from stored samples)
        double mean_d, sd_d;
        welford_stats(samples, N, &mean_d, &sd_d);
        
        // 2) Sorted copy for order stats
        uint64_t *sortbuf = benchmark_k_malloc(N * sizeof(uint64_t));
        uint64_t *scratch = benchmark_k_malloc(N * sizeof(uint64_t));
        
        if (sortbuf != NULL && scratch != NULL) {
            printk("*** DSA JITTER: Using corrected statistics\n");
            memcpy(sortbuf, samples, N * sizeof(uint64_t));
            qsort(sortbuf, N, sizeof(uint64_t), cmp_u64);

            // 3) Order statistics & jitter (corrected)
            uint64_t min_c  = sortbuf[0];
            uint64_t max_c  = sortbuf[N - 1];
            uint64_t p50_c  = median_from_sorted(sortbuf, N);
            uint64_t p95_c  = percentile_u64(sortbuf, N, 95.0);
            uint64_t p99_c  = percentile_u64(sortbuf, N, 99.0);
            uint64_t jitter = max_c - min_c;

            // 4) MAD (from the true median, using safe abs diff)
            uint64_t mad_c  = mad_u64(samples, N, p50_c, scratch);

            // 5) Store JITTER-SPECIFIC values ONLY - DO NOT overwrite baseline stats!
            // Baseline stats (avg_cycles, min_cycles, max_cycles, stddev_cycles, p50, p95, p99, MAD, CV)
            // now ALL come from calculate_baseline_stats() using the SAME N samples.
            // Jitter measurement ONLY sets jitter_cycles (max-min from batch-tuned samples).
            result->jitter_cycles = jitter;
            // NOTE: p50/p95/p99/MAD/CV are now set by calculate_baseline_stats() from baseline samples
            
            // Log jitter-specific statistics for diagnostic purposes (not stored to result)
            printk("*** DSA JITTER DIAGNOSTIC: batch_min=%llu batch_max=%llu batch_jitter=%llu\n",
                   min_c, max_c, jitter);
            printk("*** DSA JITTER DIAGNOSTIC: batch_p50=%llu batch_p95=%llu batch_p99=%llu batch_MAD=%llu\n",
                   p50_c, p95_c, p99_c, mad_c);
        } else {
            // Fallback when sortbuf/scratch buffer allocation failed
            // ONLY set jitter_cycles - p50/p95/p99/MAD/CV are set by calculate_baseline_stats()
            result->jitter_cycles = maxc - minc;
            // NOTE: p50/p95/p99/MAD/CV already set by calculate_baseline_stats()
        }
        
        // Clean up scratch buffers
        if (sortbuf) benchmark_k_free(sortbuf);
        if (scratch) benchmark_k_free(scratch);
        benchmark_k_free(samples);
    } else {
        // Fallback when sample buffer allocation failed
        // ONLY set jitter_cycles - p50/p95/p99/MAD/CV are set by calculate_baseline_stats()
        result->jitter_cycles = maxc - minc;
        // NOTE: p50/p95/p99/MAD/CV already set by calculate_baseline_stats()
    }
#else
    // Original calculation when JITTER_ROBUST_STATS not enabled
    // ONLY set jitter_cycles - p50/p95/p99/MAD/CV are set by calculate_baseline_stats()
    result->jitter_cycles = maxc - minc;
    // NOTE: p50/p95/p99/MAD/CV already set by calculate_baseline_stats()
#endif

    // ---- Print jitter classification based on corrected values ---
    double jitter_pct = (result->avg_cycles > 0) ? (100.0 * (double)result->jitter_cycles / (double)result->avg_cycles) : 0.0;
    printk("*** DSA FINAL JITTER SUMMARY: N=%u  min=%llu  max=%llu  avg=%llu  jitter=%llu  stddev=%llu  jitter%%=%.3f%%\n",
           N, result->min_cycles, result->max_cycles, result->avg_cycles, result->jitter_cycles, result->stddev_cycles, jitter_pct);

    // Classify jitter characteristics for publication analysis
    if (jitter_pct < 1.0) {
        printk("    DSA Jitter classification: VERY LOW (< 1%% variance)\n");
    } else if (jitter_pct < 5.0) {
        printk("    DSA Jitter classification: LOW (1-5%% variance)\n");
    } else if (jitter_pct < 15.0) {
        printk("    DSA Jitter classification: MODERATE (5-15%% variance)\n");
    } else {
        printk("    DSA Jitter classification: HIGH (> 15%% variance)\n");
    }

    printk("    DSA Coefficient of Variation: %.3f%% (Corrected from robust stddev)\n", result->coefficient_variation_pct);

    // Clean up allocated memory
    benchmark_k_free(pk);
    benchmark_k_free(sk);
    benchmark_k_free(signature);
    benchmark_k_free(message);
}
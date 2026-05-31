#include "metric.h"
#include "harness.h"
#include "utils.h"
#include <zephyr/sys/printk.h>
#include <zephyr/kernel.h>
#include <string.h>
#include <math.h>
#include <float.h>
#include <stdlib.h>

// ========================================================================
// STATISTICAL HELPER FUNCTIONS - For consistent percentile/MAD calculation
// ========================================================================

// Comparator for qsort (uint64_t)
static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return (x > y) - (x < y);
}

// Safe absolute difference for unsigned 64-bit, avoids underflow
static inline uint64_t u64_abs_diff(uint64_t a, uint64_t b) {
    return (a > b) ? (a - b) : (b - a);
}

// Percentile with (n-1) rank and linear interpolation
// 'sorted' MUST be non-decreasing
static uint64_t percentile_u64(const uint64_t *sorted, size_t n, double p) {
    if (n == 0) return 0;
    if (p <= 0.0)  return sorted[0];
    if (p >= 100.) return sorted[n-1];

    double pos = (p/100.0) * (double)(n - 1);
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

// Median Absolute Deviation (MAD): median(|xi - median(x)|)
// 'scratch' is a temp buffer with length >= n
static uint64_t mad_u64(const uint64_t *samples, size_t n, uint64_t median,
                        uint64_t *scratch) {
    for (size_t i = 0; i < n; i++) {
        scratch[i] = u64_abs_diff(samples[i], median);
    }
    qsort(scratch, n, sizeof(uint64_t), cmp_u64);
    return median_from_sorted(scratch, n);
}

// ========================================================================
// STEP 2: BASELINE CYCLE-COUNT OUTPUT  
// ========================================================================

void calculate_baseline_stats(uint64_t *samples, uint32_t n, benchmark_results_t *result) {
    // Comprehensive input validation
    if (!samples) {
        printk("ERROR: calculate_baseline_stats - NULL samples pointer\n");
        return;
    }
    
    if (!result) {
        printk("ERROR: calculate_baseline_stats - NULL result pointer\n");
        return;
    }
    
    if (n == 0) {
        printk("ERROR: calculate_baseline_stats - Zero iterations provided\n");
        memset(result, 0, sizeof(benchmark_results_t));
        return;
    }
    
    if (n > MAX_ITERS) {
        printk("ERROR: calculate_baseline_stats - Too many iterations (%u > %u)\n", n, MAX_ITERS);
        return;
    }
    
    printk("*** Calculating baseline stats for %u samples\n", n);
    result->iterations = n;
    
    // Calculate min, max, average with validation
    result->min_cycles = samples[0];
    result->max_cycles = samples[0]; 
    uint64_t sum = 0;
    
    // Validate first sample
    if (samples[0] == 0) {
        printk("WARNING: calculate_baseline_stats - First sample is zero cycles\n");
    }
    
    for (uint32_t i = 0; i < n; i++) {
        // Validate each sample
        if (samples[i] == 0) {
            printk("WARNING: calculate_baseline_stats - Sample %u is zero cycles\n", i);
        }
        
        if (samples[i] > UINT64_MAX / 2) {
            printk("WARNING: calculate_baseline_stats - Sample %u unusually large: %llu cycles\n", i, samples[i]);
        }
        
        if (samples[i] < result->min_cycles) result->min_cycles = samples[i];
        if (samples[i] > result->max_cycles) result->max_cycles = samples[i];
        
        // Check for overflow
        if (sum > UINT64_MAX - samples[i]) {
            printk("ERROR: calculate_baseline_stats - Overflow in sum calculation at sample %u\n", i);
            return;
        }
        sum += samples[i];
    }
    
    if (sum == 0) {
        printk("ERROR: calculate_baseline_stats - All samples are zero\n");
        return;
    }
    
    result->avg_cycles = sum / n;
    printk("*** Baseline stats: min=%llu, max=%llu, avg=%llu cycles\n", 
           result->min_cycles, result->max_cycles, result->avg_cycles);
    
    // Calculate standard deviation with validation
    double sum_sq_diff = 0.0;
    for (uint32_t i = 0; i < n; i++) {
        double diff = (double)samples[i] - (double)result->avg_cycles;
        double sq_diff = diff * diff;
        
        // Check for floating point overflow
        if (sum_sq_diff > DBL_MAX - sq_diff) {
            printk("ERROR: calculate_baseline_stats - Overflow in stddev calculation at sample %u\n", i);
            result->stddev_cycles = 0;
            return;
        }
        sum_sq_diff += sq_diff;
    }
    
    if (sum_sq_diff < 0.0) {
        printk("ERROR: calculate_baseline_stats - Negative variance: %f\n", sum_sq_diff);
        result->stddev_cycles = 0;
        return;
    }
    
    // Use sample standard deviation with Bessel's correction (n-1) to match paper specification
    double stddev_double = sqrt(sum_sq_diff / (n - 1));
    if (stddev_double > UINT64_MAX) {
        printk("WARNING: calculate_baseline_stats - Stddev too large, capping at UINT64_MAX\n");
        result->stddev_cycles = UINT64_MAX;
    } else {
        result->stddev_cycles = (uint64_t)stddev_double;
    }
    
    printk("*** Standard deviation: %llu cycles (%.2f%% of average)\n", 
           result->stddev_cycles, 
           result->avg_cycles > 0 ? (100.0 * result->stddev_cycles / result->avg_cycles) : 0.0);
    
    // ========================================================================
    // PERCENTILE & ROBUST STATISTICS - From SAME samples as avg/min/max/stddev
    // This ensures statistical consistency across all baseline metrics
    // ========================================================================
    
    // Allocate buffers for sorting and MAD calculation
    uint64_t *sortbuf = benchmark_k_malloc(n * sizeof(uint64_t));
    uint64_t *scratch = benchmark_k_malloc(n * sizeof(uint64_t));
    
    if (sortbuf != NULL && scratch != NULL) {
        // Copy and sort samples for percentile calculation
        memcpy(sortbuf, samples, n * sizeof(uint64_t));
        qsort(sortbuf, n, sizeof(uint64_t), cmp_u64);
        
        // Calculate percentiles from the SAME samples as avg/min/max/stddev
        result->q1_cycles = percentile_u64(sortbuf, n, 25.0);
        result->p50_cycles = median_from_sorted(sortbuf, n);
        result->q3_cycles = percentile_u64(sortbuf, n, 75.0);
        result->p95_cycles = percentile_u64(sortbuf, n, 95.0);
        result->p99_cycles = percentile_u64(sortbuf, n, 99.0);
        result->iqr_cycles = (result->q3_cycles >= result->q1_cycles) ?
            (result->q3_cycles - result->q1_cycles) : 0;

        // Calculate MAD (Median Absolute Deviation) for robust dispersion
        result->mad_cycles = mad_u64(samples, n, result->p50_cycles, scratch);

        // Calculate Coefficient of Variation from baseline stats (consistent with stddev)
        result->coefficient_variation_pct = (result->avg_cycles > 0) ? 
            (100.0 * (double)result->stddev_cycles / (double)result->avg_cycles) : 0.0;
        result->quartile_coeff_dispersion_pct =
            ((result->q3_cycles + result->q1_cycles) > 0) ?
            (100.0 * (double)result->iqr_cycles /
             (double)(result->q3_cycles + result->q1_cycles)) : 0.0;

        printk("*** Percentiles (from SAME N=%u samples): q1=%llu p50=%llu q3=%llu p95=%llu p99=%llu\n",
               n, result->q1_cycles, result->p50_cycles, result->q3_cycles,
               result->p95_cycles, result->p99_cycles);
        printk("*** Robust stats: IQR=%llu cycles, QCD=%.3f%%, MAD=%llu cycles, CV=%.3f%%\n",
               result->iqr_cycles, result->quartile_coeff_dispersion_pct,
               result->mad_cycles, result->coefficient_variation_pct);
        
        // Sanity check: percentiles should be monotone and within [min, max]
        if (!(result->min_cycles <= result->p50_cycles &&
              result->p50_cycles <= result->p95_cycles &&
              result->p95_cycles <= result->p99_cycles &&
              result->p99_cycles <= result->max_cycles)) {
            printk("WARNING: Percentile ordering violated - possible measurement issue\n");
        }
    } else {
        // Fallback if allocation fails - use approximate values
        printk("WARNING: Cannot allocate buffers for percentile calculation, using approximations\n");
        result->p50_cycles = result->avg_cycles;
        result->q1_cycles = result->min_cycles;
        result->q3_cycles = result->max_cycles;
        result->p95_cycles = result->max_cycles;
        result->p99_cycles = result->max_cycles;
        result->iqr_cycles = (result->q3_cycles >= result->q1_cycles) ?
            (result->q3_cycles - result->q1_cycles) : 0;
        result->quartile_coeff_dispersion_pct =
            ((result->q3_cycles + result->q1_cycles) > 0) ?
            (100.0 * (double)result->iqr_cycles /
             (double)(result->q3_cycles + result->q1_cycles)) : 0.0;
        result->mad_cycles = 0;
        result->coefficient_variation_pct = (result->avg_cycles > 0) ? 
            (100.0 * (double)result->stddev_cycles / (double)result->avg_cycles) : 0.0;
    }
    
    // Clean up allocated buffers
    if (sortbuf) benchmark_k_free(sortbuf);
    if (scratch) benchmark_k_free(scratch);
}

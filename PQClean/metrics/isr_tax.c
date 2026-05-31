/**
 * ISR-Injection Tax Profile (IITP) — Phase 4, novel RTOS-specific metric.
 *
 * For each primitive operation we execute a matched pair of sample windows:
 *   (1) a baseline window with no kernel-injected interrupts, and
 *   (2) a stressed window with a k_timer firing an ISR-context callback at a
 *       fixed high rate.
 *
 * From the two windows we derive four fields:
 *   - isr_injection_rate_hz        : the ACTUALLY delivered ISR rate during the
 *                                    stressed window (measured, not configured)
 *   - isr_injected_cycles_avg      : mean cycles/op while ISRs are firing
 *   - isr_injection_slowdown_pct   : 100 * (injected - baseline) / baseline
 *   - isr_dispatch_tax_cycles      : per-ISR kernel dispatch tax, amortized
 *                                    as (injected - baseline) / ISRs_per_op
 *
 * Load-bearing RTOS primitive: k_timer_init / k_timer_start / k_timer_stop.
 * The k_timer expiry callback executes in system-timer ISR context (Zephyr
 * API contract), providing a kernel-visible, phase-deterministic, ISA-uniform
 * interrupt injection source identical on qemu_x86_64, qemu_cortex_m3, and
 * qemu_riscv32. Userspace SIGALRM (SUPERCOP) cannot fire in ISR context;
 * bare-metal (pqm4) requires per-MCU NVIC/CLINT programming that is not
 * cross-comparable. IITP closes the "ISR-specific interference" gap
 * identified in IOTJ_ECOSYSTEM_NOVELTY_ANALYSIS.md section 5.
 */

#include "../include/utils.h"
#include "timing_port.h"
#include "kem_registry.h"
#include "sig_registry.h"

#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/printk.h>
#include <string.h>

#ifndef PQC_ISR_TAX_PERIOD_US
#define PQC_ISR_TAX_PERIOD_US   100U    /* 10 kHz requested; tickless kernel
                                         * delivers sub-tick resolution, and
                                         * the field reports the actually
                                         * observed rate regardless. */
#endif

#define PQC_ISR_TAX_TARGET_RATE_HZ  (1000000U / PQC_ISR_TAX_PERIOD_US)

static const char ISR_TAX_DSA_MESSAGE[] =
    "PQC ISR-Injection Tax Profile probe message";
static const size_t ISR_TAX_DSA_MESSAGE_LEN = 44;

static atomic_t isr_tax_isr_count;
static struct k_timer isr_tax_timer;
static bool isr_tax_timer_initialized;

static void isr_tax_expiry(struct k_timer *timer)
{
    (void)timer;
    /* Empty-body ISR: we measure only the kernel's dispatch prologue/epilogue
     * cost, not the cost of userland work performed inside the handler.
     * atomic_inc is required to prevent the callback from being elided by
     * the linker and to give us an empirically observed ISR count. */
    atomic_inc(&isr_tax_isr_count);
}

static void ensure_isr_tax_timer_initialized(void)
{
    if (!isr_tax_timer_initialized) {
        k_timer_init(&isr_tax_timer, isr_tax_expiry, NULL);
        isr_tax_timer_initialized = true;
    }
}

static int select_isr_tax_samples(uint64_t base_avg_cycles)
{
    /* Mirror select_rtos_stress_samples() in throttle.c so IITP adds no new
     * iteration-count policy surface — runtime grows in lockstep with the
     * existing RTOS stress window. */
    if (base_avg_cycles > 500000000ULL) {
        return 3;
    }
    if (base_avg_cycles > 50000000ULL) {
        return 4;
    }
    return 8;
}

static uint64_t avg_u64(const uint64_t *samples, int n)
{
    if (!samples || n <= 0) {
        return 0;
    }
    uint64_t sum = 0;
    for (int i = 0; i < n; i++) {
        sum += samples[i];
    }
    return sum / (uint64_t)n;
}

void zero_isr_tax_metrics(benchmark_results_t *r)
{
    r->isr_injection_rate_hz       = 0U;
    r->isr_injected_cycles_avg     = 0ULL;
    r->isr_injection_slowdown_pct  = 0.0;
    r->isr_dispatch_tax_cycles     = 0.0;
}

static void finalize_isr_tax(benchmark_results_t *r,
                             uint64_t baseline_avg,
                             uint64_t injected_avg,
                             uint64_t window_cycles,
                             uint32_t observed_isrs)
{
    const double hz = (double)CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC;
    if (hz <= 0.0 || window_cycles == 0ULL) {
        zero_isr_tax_metrics(r);
        return;
    }

    double window_sec = (double)window_cycles / hz;
    double actual_rate = (window_sec > 0.0) ?
                         ((double)observed_isrs / window_sec) : 0.0;

    r->isr_injection_rate_hz   = (uint32_t)actual_rate;
    r->isr_injected_cycles_avg = injected_avg;

    if (baseline_avg == 0ULL) {
        r->isr_injection_slowdown_pct = 0.0;
        r->isr_dispatch_tax_cycles    = 0.0;
        return;
    }

    double delta = (double)injected_avg - (double)baseline_avg;
    r->isr_injection_slowdown_pct = 100.0 * delta / (double)baseline_avg;

    double expected_isrs_per_op =
        ((double)injected_avg / hz) * actual_rate;
    r->isr_dispatch_tax_cycles =
        (expected_isrs_per_op > 0.0) ? (delta / expected_isrs_per_op) : 0.0;
}

static int run_kem_once(kem_info_t *kem, operation_type_t op,
                        uint8_t *pk, uint8_t *sk, uint8_t *ct,
                        uint8_t *ss1, uint8_t *ss2)
{
    switch (op) {
    case OP_KEYPAIR: return kem->keypair(pk, sk);
    case OP_ENCAPS:  return kem->encaps(ct, ss1, pk);
    case OP_DECAPS:  return kem->decaps(ss2, ct, sk);
    default:         return -1;
    }
}

static int run_sign_once(sign_info_t *sign, operation_type_t op,
                         uint8_t *pk, uint8_t *sk,
                         uint8_t *signature, size_t *sig_len,
                         uint8_t *message, size_t message_len)
{
    switch (op) {
    case OP_KEYPAIR:
        return sign->keypair(pk, sk);
    case OP_SIGN:
        *sig_len = sign->signature_bytes;
        return sign->sign(signature, sig_len, message, message_len, sk);
    case OP_VERIFY:
        return sign->verify(signature, *sig_len, message, message_len, pk);
    default:
        return -1;
    }
}

void measure_isr_tax_for_kem(kem_info_t *kem,
                             operation_type_t op_type,
                             benchmark_results_t *result,
                             uint8_t *pk, uint8_t *sk,
                             uint8_t *ct, uint8_t *ss1, uint8_t *ss2)
{
    zero_isr_tax_metrics(result);

    int n = select_isr_tax_samples(result->avg_cycles);
    uint64_t *baseline = benchmark_k_malloc((size_t)n * sizeof(uint64_t));
    uint64_t *injected = benchmark_k_malloc((size_t)n * sizeof(uint64_t));
    if (!baseline || !injected) {
        printk("WARN[isr_tax]: KEM probe alloc failed\n");
        if (baseline) benchmark_k_free(baseline);
        if (injected) benchmark_k_free(injected);
        return;
    }

    for (int i = 0; i < n; i++) {
        uint64_t t0 = tp_now_cycles();
        int ret = run_kem_once(kem, op_type, pk, sk, ct, ss1, ss2);
        uint64_t t1 = tp_now_cycles();
        if (ret != 0) {
            printk("WARN[isr_tax]: KEM baseline probe failed at sample %d\n", i);
            benchmark_k_free(baseline);
            benchmark_k_free(injected);
            return;
        }
        baseline[i] = t1 - t0;
    }

    ensure_isr_tax_timer_initialized();
    atomic_set(&isr_tax_isr_count, 0);
    k_timer_start(&isr_tax_timer,
                  K_USEC(PQC_ISR_TAX_PERIOD_US),
                  K_USEC(PQC_ISR_TAX_PERIOD_US));

    uint64_t window_t0 = tp_now_cycles();
    for (int i = 0; i < n; i++) {
        uint64_t t0 = tp_now_cycles();
        int ret = run_kem_once(kem, op_type, pk, sk, ct, ss1, ss2);
        uint64_t t1 = tp_now_cycles();
        if (ret != 0) {
            printk("WARN[isr_tax]: KEM injected probe failed at sample %d\n", i);
            k_timer_stop(&isr_tax_timer);
            benchmark_k_free(baseline);
            benchmark_k_free(injected);
            return;
        }
        injected[i] = t1 - t0;
    }
    uint64_t window_t1 = tp_now_cycles();
    k_timer_stop(&isr_tax_timer);

    uint32_t observed_isrs = (uint32_t)atomic_get(&isr_tax_isr_count);
    uint64_t window_cycles = window_t1 - window_t0;
    uint64_t baseline_avg = avg_u64(baseline, n);
    uint64_t injected_avg = avg_u64(injected, n);

    finalize_isr_tax(result, baseline_avg, injected_avg,
                     window_cycles, observed_isrs);

    printk("*** ISR-Injection Tax (KEM): rate=%u Hz, baseline=%llu, injected=%llu, slowdown=%.3f%%, tax/ISR=%.3f cy\n",
           result->isr_injection_rate_hz,
           baseline_avg, injected_avg,
           result->isr_injection_slowdown_pct,
           result->isr_dispatch_tax_cycles);

    benchmark_k_free(baseline);
    benchmark_k_free(injected);
}

void measure_isr_tax_for_sign(sign_info_t *sign,
                              operation_type_t op_type,
                              benchmark_results_t *result,
                              uint8_t *pk, uint8_t *sk,
                              uint8_t *signature, size_t *sig_len,
                              uint8_t *message, size_t message_len)
{
    zero_isr_tax_metrics(result);

    if (!message || message_len == 0) {
        message = (uint8_t *)ISR_TAX_DSA_MESSAGE;
        message_len = ISR_TAX_DSA_MESSAGE_LEN;
    }

    int n = select_isr_tax_samples(result->avg_cycles);
    uint64_t *baseline = benchmark_k_malloc((size_t)n * sizeof(uint64_t));
    uint64_t *injected = benchmark_k_malloc((size_t)n * sizeof(uint64_t));
    if (!baseline || !injected) {
        printk("WARN[isr_tax]: DSA probe alloc failed\n");
        if (baseline) benchmark_k_free(baseline);
        if (injected) benchmark_k_free(injected);
        return;
    }

    for (int i = 0; i < n; i++) {
        uint64_t t0 = tp_now_cycles();
        int ret = run_sign_once(sign, op_type, pk, sk, signature,
                                sig_len, message, message_len);
        uint64_t t1 = tp_now_cycles();
        if (ret != 0) {
            printk("WARN[isr_tax]: DSA baseline probe failed at sample %d\n", i);
            benchmark_k_free(baseline);
            benchmark_k_free(injected);
            return;
        }
        baseline[i] = t1 - t0;
    }

    ensure_isr_tax_timer_initialized();
    atomic_set(&isr_tax_isr_count, 0);
    k_timer_start(&isr_tax_timer,
                  K_USEC(PQC_ISR_TAX_PERIOD_US),
                  K_USEC(PQC_ISR_TAX_PERIOD_US));

    uint64_t window_t0 = tp_now_cycles();
    for (int i = 0; i < n; i++) {
        uint64_t t0 = tp_now_cycles();
        int ret = run_sign_once(sign, op_type, pk, sk, signature,
                                sig_len, message, message_len);
        uint64_t t1 = tp_now_cycles();
        if (ret != 0) {
            printk("WARN[isr_tax]: DSA injected probe failed at sample %d\n", i);
            k_timer_stop(&isr_tax_timer);
            benchmark_k_free(baseline);
            benchmark_k_free(injected);
            return;
        }
        injected[i] = t1 - t0;
    }
    uint64_t window_t1 = tp_now_cycles();
    k_timer_stop(&isr_tax_timer);

    uint32_t observed_isrs = (uint32_t)atomic_get(&isr_tax_isr_count);
    uint64_t window_cycles = window_t1 - window_t0;
    uint64_t baseline_avg = avg_u64(baseline, n);
    uint64_t injected_avg = avg_u64(injected, n);

    finalize_isr_tax(result, baseline_avg, injected_avg,
                     window_cycles, observed_isrs);

    printk("*** ISR-Injection Tax (DSA): rate=%u Hz, baseline=%llu, injected=%llu, slowdown=%.3f%%, tax/ISR=%.3f cy\n",
           result->isr_injection_rate_hz,
           baseline_avg, injected_avg,
           result->isr_injection_slowdown_pct,
           result->isr_dispatch_tax_cycles);

    benchmark_k_free(baseline);
    benchmark_k_free(injected);
}

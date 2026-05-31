/**
 * Periodic Release Jitter Profile (PRJP) — novel RTOS-specific metric.
 *
 * Many RTOS deployments schedule cryptography as a periodic task (control
 * loop keying, session-refresh tick, telemetry-frame MAC, etc.). The figure
 * of merit in those deployments is not the op's average latency, but how
 * precisely the RTOS can RELEASE a blocked task at the requested period
 * while the PQC primitive concurrently saturates the CPU.
 *
 * We model this with a pure Zephyr construct: a k_timer fires periodically
 * (period = PQC_PRJP_PERIOD_US), and its ISR-context expiry callback both
 * (a) atomically latches the release cycle-stamp and (b) k_sem_gives the
 * consumer. The consumer thread (this thread, running the PQC op) is
 * k_sem_taking at the top of each iteration. The scheduler release latency
 * per cycle is:
 *
 *   release_latency = tp_now_cycles_after_sem_take  -  ISR_latched_cycle
 *
 * Over a batch of PRJP_BATCH releases we sort the latencies and emit p50,
 * p99, jitter = p99 - p50, and the number of overrun releases (ISR fired
 * while the previous op hadn't yet consumed the semaphore — counted via
 * k_sem_count_get before the take).
 *
 * Load-bearing RTOS primitives:
 *   - k_timer_init/start/stop    (periodic, ISR-context release source)
 *   - k_sem_init/take/count_get  (kernel-mediated release with overrun
 *                                 detection via pending-count)
 *
 * Output fields:
 *   - release_period_us             : configured period
 *   - release_latency_p50_cycles    : 50th-pct post-ISR release latency
 *   - release_latency_p99_cycles    : 99th-pct release latency
 *   - release_jitter_cycles         : p99 - p50
 *   - release_overruns              : count of cycles where timer fired
 *                                     before the previous release was taken
 *
 * Ecosystem gap: pqm4/SUPERCOP/PQC-LEO run ops in tight loops with no
 * scheduler at all, so "release precision under PQC load" is a dimension
 * they structurally cannot report. This complements deadline_slack (which
 * uses pre-measured baseline percentiles) and IITP (which charts ISR cost
 * DURING an op) by adding the scheduler-release-precision axis.
 */

#include "../include/utils.h"
#include "timing_port.h"
#include "kem_registry.h"
#include "sig_registry.h"

#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/printk.h>
#include <string.h>

#ifndef PQC_PRJP_PERIOD_US
#define PQC_PRJP_PERIOD_US    1000U   /* 1 kHz release cadence */
#endif

#ifndef PQC_PRJP_MAX_BATCH
#define PQC_PRJP_MAX_BATCH    16U     /* hard cap on samples per probe */
#endif

#ifndef PQC_PRJP_MIN_BATCH
#define PQC_PRJP_MIN_BATCH    4U
#endif

static const char PRJP_DSA_MESSAGE[] = "PQC PRJP probe message";
static const size_t PRJP_DSA_MESSAGE_LEN = 22;

static struct k_sem   prjp_release_sem;
static struct k_timer prjp_release_timer;
static bool           prjp_primitives_initialized;

/* Atomic 32-bit split for the 64-bit release cycle stamp. We only need
 * lower-32 differences for the latency, but ordering between expiry_fn and
 * the consumer thread is guaranteed by the k_sem_give/k_sem_take pair.
 * atomic_t is unsigned-long-wide on all Zephyr targets; we store the
 * low-32 bits which wraps well within one period at any HW_CYCLES_PER_SEC
 * we will see in QEMU (≤ 4 GHz → 4 ms wrap, >> 1 kHz period). */
static atomic_t prjp_last_release_lo;

static void prjp_timer_expiry(struct k_timer *t)
{
    (void)t;
    uint64_t now = tp_now_cycles();
    atomic_set(&prjp_last_release_lo, (atomic_val_t)(now & 0xFFFFFFFFULL));
    k_sem_give(&prjp_release_sem);
}

static void ensure_prjp_primitives(void)
{
    if (prjp_primitives_initialized) {
        return;
    }
    k_sem_init(&prjp_release_sem, 0, K_SEM_MAX_LIMIT);
    k_timer_init(&prjp_release_timer, prjp_timer_expiry, NULL);
    prjp_primitives_initialized = true;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x < y) ? -1 : (x > y ? 1 : 0);
}

static void sort_u64(uint64_t *arr, int n)
{
    /* Small insertion sort — n ≤ PQC_PRJP_MAX_BATCH (16). */
    for (int i = 1; i < n; i++) {
        uint64_t key = arr[i];
        int j = i - 1;
        while (j >= 0 && arr[j] > key) {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
    (void)cmp_u64;  /* reserved for future qsort swap */
}

static uint64_t pick_percentile(uint64_t *sorted, int n, double pct)
{
    if (n <= 0) return 0ULL;
    int idx = (int)((pct / 100.0) * (double)(n - 1) + 0.5);
    if (idx < 0) idx = 0;
    if (idx >= n) idx = n - 1;
    return sorted[idx];
}

static int select_prjp_batch(uint64_t base_avg_cycles)
{
    /* Each release cycle consumes ~one op of work. Batch must be small
     * enough to keep the probe short but large enough for the percentile
     * estimate to be meaningful. Scale inversely with op cost. */
    const double hz = (double)CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC;
    if (hz <= 0.0 || base_avg_cycles == 0ULL) {
        return (int)PQC_PRJP_MIN_BATCH;
    }
    /* Target probe wall-time ≈ 16 ms → batch = 16 ms / period */
    int by_period = 16000 / (int)PQC_PRJP_PERIOD_US;
    /* but also cap at what we can finish given op cost */
    double op_us = ((double)base_avg_cycles * 1.0e6) / hz;
    int by_op = (op_us > 0.0) ? (int)(16000.0 / op_us) : (int)PQC_PRJP_MAX_BATCH;

    int batch = by_period < by_op ? by_period : by_op;
    if (batch < (int)PQC_PRJP_MIN_BATCH) batch = (int)PQC_PRJP_MIN_BATCH;
    if (batch > (int)PQC_PRJP_MAX_BATCH) batch = (int)PQC_PRJP_MAX_BATCH;
    return batch;
}

void zero_release_jitter_metrics(benchmark_results_t *r)
{
    r->release_period_us            = PQC_PRJP_PERIOD_US;
    r->release_latency_p50_cycles   = 0ULL;
    r->release_latency_p99_cycles   = 0ULL;
    r->release_jitter_cycles        = 0ULL;
    r->release_overruns             = 0U;
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

static void finalize_prjp(benchmark_results_t *r,
                          uint64_t *lat, int n,
                          uint32_t overruns)
{
    if (n <= 0) {
        zero_release_jitter_metrics(r);
        return;
    }
    sort_u64(lat, n);
    uint64_t p50 = pick_percentile(lat, n, 50.0);
    uint64_t p99 = pick_percentile(lat, n, 99.0);
    r->release_period_us          = PQC_PRJP_PERIOD_US;
    r->release_latency_p50_cycles = p50;
    r->release_latency_p99_cycles = p99;
    r->release_jitter_cycles      = (p99 > p50) ? (p99 - p50) : 0ULL;
    r->release_overruns           = overruns;
}

void measure_release_jitter_for_kem(kem_info_t *kem,
                                    operation_type_t op_type,
                                    benchmark_results_t *result,
                                    uint8_t *pk, uint8_t *sk,
                                    uint8_t *ct, uint8_t *ss1, uint8_t *ss2)
{
    zero_release_jitter_metrics(result);
    ensure_prjp_primitives();

    int batch = select_prjp_batch(result->avg_cycles);
    uint64_t *lat = benchmark_k_malloc((size_t)batch * sizeof(uint64_t));
    if (!lat) {
        printk("WARN[prjp]: KEM latency buffer alloc failed\n");
        return;
    }

    k_sem_reset(&prjp_release_sem);
    atomic_set(&prjp_last_release_lo, 0);
    uint32_t overruns = 0;

    k_timer_start(&prjp_release_timer,
                  K_USEC(PQC_PRJP_PERIOD_US),
                  K_USEC(PQC_PRJP_PERIOD_US));

    for (int i = 0; i < batch; i++) {
        /* Overrun = pending > 1: timer ISR fired twice before we took. */
        unsigned int pending = k_sem_count_get(&prjp_release_sem);
        if (pending > 1) {
            overruns += (uint32_t)pending - 1U;
        }
        if (k_sem_take(&prjp_release_sem, K_MSEC(200)) != 0) {
            /* Timeout: timer never fired or victim was long-starved. */
            benchmark_k_free(lat);
            k_timer_stop(&prjp_release_timer);
            zero_release_jitter_metrics(result);
            return;
        }
        uint64_t take_cycles = tp_now_cycles();
        uint32_t release_lo = (uint32_t)atomic_get(&prjp_last_release_lo);
        uint32_t take_lo = (uint32_t)(take_cycles & 0xFFFFFFFFULL);
        uint32_t dlo = take_lo - release_lo;   /* wraps naturally in u32 */
        lat[i] = (uint64_t)dlo;

        int ret = run_kem_once(kem, op_type, pk, sk, ct, ss1, ss2);
        if (ret != 0) {
            printk("WARN[prjp]: KEM op failed at iter %d\n", i);
            k_timer_stop(&prjp_release_timer);
            benchmark_k_free(lat);
            zero_release_jitter_metrics(result);
            return;
        }
    }

    k_timer_stop(&prjp_release_timer);

    finalize_prjp(result, lat, batch, overruns);

    printk("*** PRJP (KEM): period=%u us, p50=%llu, p99=%llu, jitter=%llu cy, overruns=%u\n",
           result->release_period_us,
           result->release_latency_p50_cycles,
           result->release_latency_p99_cycles,
           result->release_jitter_cycles,
           result->release_overruns);

    benchmark_k_free(lat);
}

void measure_release_jitter_for_sign(sign_info_t *sign,
                                     operation_type_t op_type,
                                     benchmark_results_t *result,
                                     uint8_t *pk, uint8_t *sk,
                                     uint8_t *signature, size_t *sig_len,
                                     uint8_t *message, size_t message_len)
{
    zero_release_jitter_metrics(result);
    ensure_prjp_primitives();

    if (!message || message_len == 0) {
        message = (uint8_t *)PRJP_DSA_MESSAGE;
        message_len = PRJP_DSA_MESSAGE_LEN;
    }

    int batch = select_prjp_batch(result->avg_cycles);
    uint64_t *lat = benchmark_k_malloc((size_t)batch * sizeof(uint64_t));
    if (!lat) {
        printk("WARN[prjp]: DSA latency buffer alloc failed\n");
        return;
    }

    k_sem_reset(&prjp_release_sem);
    atomic_set(&prjp_last_release_lo, 0);
    uint32_t overruns = 0;

    k_timer_start(&prjp_release_timer,
                  K_USEC(PQC_PRJP_PERIOD_US),
                  K_USEC(PQC_PRJP_PERIOD_US));

    for (int i = 0; i < batch; i++) {
        unsigned int pending = k_sem_count_get(&prjp_release_sem);
        if (pending > 1) {
            overruns += (uint32_t)pending - 1U;
        }
        if (k_sem_take(&prjp_release_sem, K_MSEC(500)) != 0) {
            benchmark_k_free(lat);
            k_timer_stop(&prjp_release_timer);
            zero_release_jitter_metrics(result);
            return;
        }
        uint64_t take_cycles = tp_now_cycles();
        uint32_t release_lo = (uint32_t)atomic_get(&prjp_last_release_lo);
        uint32_t take_lo = (uint32_t)(take_cycles & 0xFFFFFFFFULL);
        uint32_t dlo = take_lo - release_lo;
        lat[i] = (uint64_t)dlo;

        int ret = run_sign_once(sign, op_type, pk, sk, signature,
                                sig_len, message, message_len);
        if (ret != 0) {
            printk("WARN[prjp]: DSA op failed at iter %d\n", i);
            k_timer_stop(&prjp_release_timer);
            benchmark_k_free(lat);
            zero_release_jitter_metrics(result);
            return;
        }
    }

    k_timer_stop(&prjp_release_timer);

    finalize_prjp(result, lat, batch, overruns);

    printk("*** PRJP (DSA): period=%u us, p50=%llu, p99=%llu, jitter=%llu cy, overruns=%u\n",
           result->release_period_us,
           result->release_latency_p50_cycles,
           result->release_latency_p99_cycles,
           result->release_jitter_cycles,
           result->release_overruns);

    benchmark_k_free(lat);
}

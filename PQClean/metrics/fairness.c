/**
 * Cooperative Fairness to Co-Runners (CFCR) — novel RTOS-specific metric.
 *
 * Flips the direction of RTOS_Stress_*: instead of measuring pressure ON the
 * PQC op from a higher-priority worker, CFCR measures pressure FROM the PQC
 * op ON a higher-priority ready thread that is released periodically by a
 * k_timer ISR. We compare:
 *
 *   (1) IDLE baseline window  : main thread k_sleeps, victim wakes freely
 *   (2) OP window              : main thread runs PQC ops back-to-back
 *
 * Under Zephyr's preempt-enabled scheduler the higher-priority victim is
 * released as soon as the timer ISR gives its semaphore. During the OP
 * window, every such release forces a context-switch of a thread that was
 * mid-way through a PQC op — the PQC op's register/FPU/stack footprint
 * widens the context-save/restore cost, reducing the number of victim wakes
 * completed per unit wall-clock. The drop, expressed as a starvation
 * percentage, is a direct "cost-to-system" measurement.
 *
 * Load-bearing RTOS primitives:
 *   - k_thread_create            (spawn the victim at higher priority)
 *   - k_sem_init/give/take       (kernel-mediated release)
 *   - k_timer_init/start/stop    (periodic, ISR-context release trigger)
 *
 * Ecosystem gap: pqm4/SUPERCOP/PQC-LEO run the primitive alone in a tight
 * loop (bare-metal or host userspace) with no concurrently scheduled
 * workload, so the "cost imposed on co-runners" axis is structurally
 * unmeasurable in those frameworks.
 *
 * Output fields:
 *   - coop_victim_idle_ticks   : wakes during idle baseline
 *   - coop_victim_op_ticks     : wakes during PQC-op window
 *   - coop_starvation_pct      : 100*(1 - op_ticks/idle_ticks), clamped
 *   - coop_fairness_index      : 1 - starvation/100, clamped to [0,1]
 */

#include "../include/utils.h"
#include "timing_port.h"
#include "kem_registry.h"
#include "sig_registry.h"

#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/printk.h>
#include <string.h>

#ifndef PQC_COOP_VICTIM_PERIOD_US
#define PQC_COOP_VICTIM_PERIOD_US   250U   /* 4 kHz victim release rate */
#endif

#ifndef PQC_COOP_WINDOW_MS
#define PQC_COOP_WINDOW_MS          10U    /* idle-baseline window length */
#endif

#ifndef PQC_COOP_VICTIM_STACK_SIZE
#define PQC_COOP_VICTIM_STACK_SIZE  1024
#endif

/* Victim priority chosen one step above the main thread's default (0) so it
 * preempts on every k_sem_give regardless of main's priority band. Negative
 * priorities in Zephyr are cooperative; using a preemptible positive one-less
 * value keeps the victim preemptible by anything more urgent (e.g. the timer
 * ISR itself). */
#ifndef PQC_COOP_VICTIM_PRIORITY
#define PQC_COOP_VICTIM_PRIORITY    (-1)
#endif

static K_THREAD_STACK_DEFINE(cfcr_victim_stack, PQC_COOP_VICTIM_STACK_SIZE);
static struct k_thread cfcr_victim_thread_data;
static k_tid_t         cfcr_victim_tid;
static bool            cfcr_victim_spawned;

static struct k_sem    cfcr_victim_sem;
static struct k_timer  cfcr_victim_timer;
static bool            cfcr_primitives_initialized;

static atomic_t        cfcr_victim_wakes;
static atomic_t        cfcr_victim_stop;

static void cfcr_timer_expiry(struct k_timer *t)
{
    (void)t;
    /* Runs in system-timer ISR context. k_sem_give is ISR-safe. */
    k_sem_give(&cfcr_victim_sem);
}

static void cfcr_victim_fn(void *a, void *b, void *c)
{
    (void)a; (void)b; (void)c;
    while (!atomic_get(&cfcr_victim_stop)) {
        if (k_sem_take(&cfcr_victim_sem, K_MSEC(50)) == 0) {
            atomic_inc(&cfcr_victim_wakes);
        }
    }
}

static void ensure_cfcr_primitives(void)
{
    if (cfcr_primitives_initialized) {
        return;
    }
    k_sem_init(&cfcr_victim_sem, 0, K_SEM_MAX_LIMIT);
    k_timer_init(&cfcr_victim_timer, cfcr_timer_expiry, NULL);
    cfcr_primitives_initialized = true;
}

static void ensure_cfcr_victim_spawned(void)
{
    if (cfcr_victim_spawned) {
        return;
    }
    atomic_set(&cfcr_victim_stop, 0);
    atomic_set(&cfcr_victim_wakes, 0);
    cfcr_victim_tid = k_thread_create(&cfcr_victim_thread_data,
                                      cfcr_victim_stack,
                                      K_THREAD_STACK_SIZEOF(cfcr_victim_stack),
                                      cfcr_victim_fn, NULL, NULL, NULL,
                                      PQC_COOP_VICTIM_PRIORITY, 0,
                                      K_NO_WAIT);
    cfcr_victim_spawned = true;
}

void zero_fairness_metrics(benchmark_results_t *r)
{
    r->coop_victim_idle_ticks = 0ULL;
    r->coop_victim_op_ticks   = 0ULL;
    r->coop_starvation_pct    = 0.0;
    r->coop_fairness_index    = 1.0;
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

static int cfcr_select_op_repeats(uint64_t base_avg_cycles)
{
    /* Match an op-window duration roughly equal to PQC_COOP_WINDOW_MS so
     * idle and op windows are comparable. Over-long windows on cheap
     * primitives inflate runtime without improving signal. */
    const double hz = (double)CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC;
    if (hz <= 0.0 || base_avg_cycles == 0ULL) {
        return 4;
    }
    double per_op_ms = ((double)base_avg_cycles * 1.0e3) / hz;
    if (per_op_ms <= 0.0) {
        return 4;
    }
    int repeats = (int)((double)PQC_COOP_WINDOW_MS / per_op_ms);
    if (repeats < 2)   repeats = 2;
    if (repeats > 64)  repeats = 64;
    return repeats;
}

static void finalize_fairness(benchmark_results_t *r,
                              uint64_t idle_ticks,
                              uint64_t op_ticks)
{
    r->coop_victim_idle_ticks = idle_ticks;
    r->coop_victim_op_ticks   = op_ticks;

    if (idle_ticks == 0ULL) {
        r->coop_starvation_pct = 0.0;
        r->coop_fairness_index = 1.0;
        return;
    }

    double ratio = (double)op_ticks / (double)idle_ticks;
    if (ratio > 1.0) ratio = 1.0;
    if (ratio < 0.0) ratio = 0.0;

    r->coop_starvation_pct = 100.0 * (1.0 - ratio);
    r->coop_fairness_index = ratio;
}

void measure_fairness_for_kem(kem_info_t *kem,
                              operation_type_t op_type,
                              benchmark_results_t *result,
                              uint8_t *pk, uint8_t *sk,
                              uint8_t *ct, uint8_t *ss1, uint8_t *ss2)
{
    zero_fairness_metrics(result);

    ensure_cfcr_primitives();
    ensure_cfcr_victim_spawned();

    /* --- Idle baseline window --- */
    k_sem_reset(&cfcr_victim_sem);
    atomic_set(&cfcr_victim_wakes, 0);
    k_timer_start(&cfcr_victim_timer,
                  K_USEC(PQC_COOP_VICTIM_PERIOD_US),
                  K_USEC(PQC_COOP_VICTIM_PERIOD_US));
    k_sleep(K_MSEC(PQC_COOP_WINDOW_MS));
    k_timer_stop(&cfcr_victim_timer);
    /* Let any in-flight give drain into the victim so the counter is stable. */
    k_yield();
    uint64_t idle_ticks = (uint64_t)atomic_get(&cfcr_victim_wakes);

    /* --- Op window --- */
    int repeats = cfcr_select_op_repeats(result->avg_cycles);
    k_sem_reset(&cfcr_victim_sem);
    atomic_set(&cfcr_victim_wakes, 0);
    k_timer_start(&cfcr_victim_timer,
                  K_USEC(PQC_COOP_VICTIM_PERIOD_US),
                  K_USEC(PQC_COOP_VICTIM_PERIOD_US));
    for (int i = 0; i < repeats; i++) {
        int ret = run_kem_once(kem, op_type, pk, sk, ct, ss1, ss2);
        if (ret != 0) {
            printk("WARN[fairness]: KEM op failed at repeat %d\n", i);
            k_timer_stop(&cfcr_victim_timer);
            zero_fairness_metrics(result);
            return;
        }
    }
    k_timer_stop(&cfcr_victim_timer);
    k_yield();
    uint64_t op_ticks = (uint64_t)atomic_get(&cfcr_victim_wakes);

    finalize_fairness(result, idle_ticks, op_ticks);

    printk("*** CFCR (KEM): idle=%llu, op=%llu, starvation=%.3f%%, fairness=%.3f\n",
           result->coop_victim_idle_ticks,
           result->coop_victim_op_ticks,
           result->coop_starvation_pct,
           result->coop_fairness_index);
}

static const char COOP_DSA_MESSAGE[] = "PQC CFCR probe message";
static const size_t COOP_DSA_MESSAGE_LEN = 22;

void measure_fairness_for_sign(sign_info_t *sign,
                               operation_type_t op_type,
                               benchmark_results_t *result,
                               uint8_t *pk, uint8_t *sk,
                               uint8_t *signature, size_t *sig_len,
                               uint8_t *message, size_t message_len)
{
    zero_fairness_metrics(result);

    if (!message || message_len == 0) {
        message = (uint8_t *)COOP_DSA_MESSAGE;
        message_len = COOP_DSA_MESSAGE_LEN;
    }

    ensure_cfcr_primitives();
    ensure_cfcr_victim_spawned();

    k_sem_reset(&cfcr_victim_sem);
    atomic_set(&cfcr_victim_wakes, 0);
    k_timer_start(&cfcr_victim_timer,
                  K_USEC(PQC_COOP_VICTIM_PERIOD_US),
                  K_USEC(PQC_COOP_VICTIM_PERIOD_US));
    k_sleep(K_MSEC(PQC_COOP_WINDOW_MS));
    k_timer_stop(&cfcr_victim_timer);
    k_yield();
    uint64_t idle_ticks = (uint64_t)atomic_get(&cfcr_victim_wakes);

    int repeats = cfcr_select_op_repeats(result->avg_cycles);
    k_sem_reset(&cfcr_victim_sem);
    atomic_set(&cfcr_victim_wakes, 0);
    k_timer_start(&cfcr_victim_timer,
                  K_USEC(PQC_COOP_VICTIM_PERIOD_US),
                  K_USEC(PQC_COOP_VICTIM_PERIOD_US));
    for (int i = 0; i < repeats; i++) {
        int ret = run_sign_once(sign, op_type, pk, sk, signature,
                                sig_len, message, message_len);
        if (ret != 0) {
            printk("WARN[fairness]: DSA op failed at repeat %d\n", i);
            k_timer_stop(&cfcr_victim_timer);
            zero_fairness_metrics(result);
            return;
        }
    }
    k_timer_stop(&cfcr_victim_timer);
    k_yield();
    uint64_t op_ticks = (uint64_t)atomic_get(&cfcr_victim_wakes);

    finalize_fairness(result, idle_ticks, op_ticks);

    printk("*** CFCR (DSA): idle=%llu, op=%llu, starvation=%.3f%%, fairness=%.3f\n",
           result->coop_victim_idle_ticks,
           result->coop_victim_op_ticks,
           result->coop_starvation_pct,
           result->coop_fairness_index);
}

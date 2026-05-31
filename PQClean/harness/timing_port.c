#include "timing_port.h"
#include <zephyr/kernel.h>
#include <zephyr/sys_clock.h>   // sys_clock_hw_cycles_per_sec()
#include <zephyr/spinlock.h>


#if defined(CONFIG_TIMER_HAS_64BIT_CYCLE_COUNTER)
  #define HAVE_64B_COUNTER 1
#else
  #define HAVE_64B_COUNTER 0
#endif

/* -------- Frequency (Hz) handling -------- */
static atomic_t g_init_done;
static uint64_t g_hw_hz;           /* cached cycles/second */

/* We prefer the runtime API; it’s provided by the timer driver. */
static inline uint64_t read_hw_hz_runtime(void) {
    /* Authoritative cycles-per-second, no Kconfig needed. */
    return (uint64_t)sys_clock_hw_cycles_per_sec();
}

/* As a last resort, calibrate cycles vs. uptime (~20 ms) */
static uint64_t calibrate_hw_hz(void) {
    k_sleep(K_MSEC(5));  /* settle */
    uint64_t t0_ms = k_uptime_get();
#if HAVE_64B_COUNTER
    uint64_t c0 = k_cycle_get_64();
#else
    uint32_t c0 = k_cycle_get_32();
#endif
    k_sleep(K_MSEC(20));
    uint64_t t1_ms = k_uptime_get();
#if HAVE_64B_COUNTER
    uint64_t c1 = k_cycle_get_64();
    uint64_t dcy = c1 - c0;
#else
    uint32_t c1 = k_cycle_get_32();
    uint64_t dcy = (c1 >= c0) ? (uint64_t)(c1 - c0)
                              : ( (1ULL << 32) - (uint64_t)c0 + (uint64_t)c1 );
#endif
    uint64_t dms = (t1_ms > t0_ms) ? (t1_ms - t0_ms) : 1ULL;
    return (dcy * 1000ULL) / dms; /* Hz = cycles / seconds */
}

void tp_timing_init(void) {
    if (atomic_cas(&g_init_done, 0, 1)) {
        g_hw_hz = read_hw_hz_runtime();
        if (g_hw_hz == 0) {
            g_hw_hz = calibrate_hw_hz();
        }
        if (g_hw_hz == 0) {
            /* should never happen, but keep numbers finite */
            g_hw_hz = 1000000ULL;
        }
    }
}

uint64_t tp_cycles_per_sec(void) {
    if (unlikely(atomic_get(&g_init_done) == 0)) {
        tp_timing_init();
    }
    return g_hw_hz;
}

/* -------- Monotonic 64-bit “cycle” time -------- */
#if HAVE_64B_COUNTER

uint64_t tp_now_cycles(void) {
    return k_cycle_get_64();
}

#else /* stitch a 64-bit value from the 32-bit hardware counter */

static struct k_spinlock s_lock;
static uint32_t s_prev_lo;   /* last seen 32-bit value */
static uint32_t s_hi;        /* rollover count (upper 32 bits) */

uint64_t tp_now_cycles(void) {
    k_spinlock_key_t key = k_spin_lock(&s_lock);
    uint32_t lo = k_cycle_get_32();
    if (lo < s_prev_lo) {
        /* 32-bit rollover */
        ++s_hi;
    }
    s_prev_lo = lo;
    uint64_t now = ( (uint64_t)s_hi << 32 ) | lo;
    k_spin_unlock(&s_lock, key);
    return now;
}

#endif /* HAVE_64B_COUNTER */

/* -------- Optional: derive Zephyr “ticks per second” at runtime -------- */
uint32_t bench_ticks_per_sec(void) {
    /* duration (µs) of one tick; portable and runtime-derived */
    uint64_t us_per_tick = k_ticks_to_us_floor64(1);
    return (us_per_tick != 0ULL) ? (uint32_t)(1000000ULL / us_per_tick) : 0U;
}
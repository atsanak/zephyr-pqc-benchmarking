#pragma once
#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Call once early (app start). Calibrates freq_hz if needed. */
void tp_timing_init(void);

/* Returns monotonically increasing cycle counter (always 64-bit). */
uint64_t tp_now_cycles(void);

/* Returns hardware cycles per second. */
uint64_t tp_cycles_per_sec(void);

/* Optional helpers */
static inline uint64_t tp_cycles_to_ns(uint64_t cycles) {
    uint64_t f = tp_cycles_per_sec();
    /* Avoid overflow: (cycles * 1e9) / f using 64-bit arithmetic */
    if (cycles > (UINT64_MAX / 1000000000ULL)) {
        /* For very large cycle counts, use division first */
        return (cycles / f) * 1000000000ULL + ((cycles % f) * 1000000000ULL) / f;
    } else {
        return (cycles * 1000000000ULL) / f;
    }
}
static inline uint64_t tp_cycles_to_ms(uint64_t cycles) {
    uint64_t f = tp_cycles_per_sec();
    /* Simple 64-bit arithmetic: (cycles * 1000) / f */
    if (cycles > (UINT64_MAX / 1000ULL)) {
        /* For very large cycle counts, use division first */
        return (cycles / f) * 1000ULL + ((cycles % f) * 1000ULL) / f;
    } else {
        return (cycles * 1000ULL) / f;
    }
}

#ifdef __cplusplus
}
#endif
// time_budget.c  (final portable version)
#include "harness.h"
#include "timing_port.h"
#include <zephyr/kernel.h>

// ---------------------------------------------------------------------
// All timing goes through timing_port.* so we work on 32-bit and 64-bit
// targets (qemu_leon3, qemu_malta, …) without CONFIG_TIMER_HAS_64BIT_*.
// ---------------------------------------------------------------------

void benchmark_timing_init(void)  { /* no-op; timing_port does any setup */ }
void benchmark_timing_start(void) { /* no-op */ }

uint64_t benchmark_timing_counter_get(void) {
    return tp_now_cycles();               // portable cycle timestamp
}

uint64_t benchmark_timing_cycles_get(uint64_t *start, uint64_t *end) {
    return (*end - *start);               // tp_now_cycles() is monotonic in timing_port
}

// For logs only (never for metrics math)
static inline double cycles_to_ms(uint64_t cycles) {
    return (double)cycles * 1000.0 / (double)tp_cycles_per_sec();
}
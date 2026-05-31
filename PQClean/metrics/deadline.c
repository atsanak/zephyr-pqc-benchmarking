/**
 * Deadline-Slack & Miss-Risk Analysis (Phase 4)
 *
 * Converts the already-computed baseline percentile distribution into a
 * real-time deadline decision for each (algo, op, isa) row.
 *
 * Absent from pqm4 (no deadline contract), SUPERCOP (host-only, no RTOS),
 * and PQC-LEO (TLS layer, not primitive/RTOS). First PQC benchmark to
 * quantify per-algorithm deadline-miss risk against an explicit budget.
 *
 * Zero new Zephyr API calls: uses only CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC
 * (already on the OBS-2 verified-safe list) and the p50/p95/p99 fields
 * already populated by calculate_baseline_stats() in cycles.c.
 */

#include "../include/utils.h"
#include <zephyr/sys/printk.h>

#ifndef PQC_DEADLINE_BUDGET_US
#define PQC_DEADLINE_BUDGET_US 10000.0   /* 10 ms: typical UAV/IoT control-loop */
#endif

/*
 * compute_deadline_metrics — fill four deadline fields in the result struct.
 *
 * Called once per operation immediately before CSV emission, after
 * calculate_baseline_stats() has populated p50_cycles, p95_cycles, p99_cycles.
 *
 * Miss-risk uses piecewise-linear CDF interpolation over three empirical
 * quantile knots: {p50 → 50 %, p95 → 5 %, p99 → 1 %}. Outside the observed
 * range it is clamped: budget < p50 → 100 %, budget ≥ p99 → 0 %.
 * Document the approximation honestly: values are interpolated from three
 * quantile knots, not counted from the raw sample buffer (which is
 * transient and not retained in the result struct).
 */
void compute_deadline_metrics(benchmark_results_t *r)
{
    const double budget_us = PQC_DEADLINE_BUDGET_US;
    const double hz = (double)CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC;

    if (hz <= 0.0 || r->p50_cycles == 0) {
        r->deadline_budget_us     = budget_us;
        r->deadline_slack_p50_us  = 0.0;
        r->deadline_slack_p99_us  = 0.0;
        r->deadline_miss_risk_pct = 100.0;
        return;
    }

    double p50_us = (double)r->p50_cycles * 1.0e6 / hz;
    double p95_us = (double)r->p95_cycles * 1.0e6 / hz;
    double p99_us = (double)r->p99_cycles * 1.0e6 / hz;

    r->deadline_budget_us    = budget_us;
    r->deadline_slack_p50_us = budget_us - p50_us;
    r->deadline_slack_p99_us = budget_us - p99_us;

    double miss_risk;
    if (budget_us < p50_us) {
        miss_risk = 100.0;
    } else if (budget_us >= p99_us) {
        miss_risk = 0.0;
    } else if (p95_us > p50_us && budget_us < p95_us) {
        double t = (budget_us - p50_us) / (p95_us - p50_us);
        miss_risk = 50.0 - t * 45.0;   /* 50 % → 5 % */
    } else {
        double denom = (p99_us > p95_us) ? (p99_us - p95_us) : 1e-9;
        double t = (budget_us - p95_us) / denom;
        miss_risk = 5.0 - t * 4.0;     /* 5 % → 1 % */
    }
    r->deadline_miss_risk_pct = miss_risk;
}

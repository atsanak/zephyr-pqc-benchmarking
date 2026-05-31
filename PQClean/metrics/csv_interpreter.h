/**
 * CSV Benchmark Data Interpreter (v2 schema)
 *
 * Lightweight helper utilities for explaining raw CSV rows emitted by the
 * Zephyr PQClean benchmark harness after the Balanced v2 schema upgrade.
 */

#ifndef CSV_INTERPRETER_H
#define CSV_INTERPRETER_H

#include <stdio.h>
#include <string.h>

static const char *KEM_V2_FIELDS[] = {
    "KEM", "Variant", "PK_Bytes", "SK_Bytes", "CT_Bytes", "SS_Bytes",
    "Operation", "Iterations", "Avg_Cycles", "Min_Cycles", "Max_Cycles",
    "StdDev_Cycles", "Energy_uJ", "StdDev_Energy_uJ", "Energy_Model_Tag",
    "Jitter_Cycles", "CoeffVar_pct", "p50_Cycles", "p95_Cycles", "p99_Cycles",
    "Q1_Cycles", "Q3_Cycles", "IQR_Cycles", "Quartile_Coeff_Dispersion_pct",
    "MAD_Cycles", "Entropy_Success_pct", "Avg_Latency_Entropy_ms",
    "RNG_Bytes_Consumed", "RNG_Call_Count", "RNG_Failures",
    "RNG_Shannon_Entropy", "RNG_Min_Entropy_H_inf", "RNG_Bytes_Per_Call",
    "Session_Crypto_Bytes", "Operation_IO_Bytes",
    "Cycles_Per_Session_Crypto_Byte", "Energy_Per_Session_Crypto_Byte_uJ",
    "Cycles_Per_Op_IO_Byte", "Cycles_At_128KB_RAM_Cap", "Failure_128KB_pct",
    "Cycles_At_64KB_RAM_Cap", "Failure_64KB_pct", "Cycles_Throttled_50pct",
    "Latency_Throttled_50pct_ms", "Jitter_Adder_Throttled_Cycles",
    "Throttle_Slowdown_pct", "Cycles_Cache_TLB_Stress",
    "Cycles_Memory_BW_Stress", "Cycles_Branch_Stress",
    "Tail_Amplification_Factor", "Throttle_Profile_Used",
    "p50_Stress_Cycles", "p99_Stress_Cycles", "Jitter_Stress_Cycles",
    "Min_Stress_Cycles", "Max_Stress_Cycles", "RTOS_Stress_Avg_Cycles",
    "RTOS_Stress_Slowdown_Pct", "RTOS_Stress_Activations",
    "RTOS_Stress_Jitter_Cycles", "RTOS_Stress_p50_Cycles",
    "RTOS_Stress_p95_Cycles", "RTOS_Stress_p99_Cycles",
    "RTOS_Tail_Amplification_Factor",
    "RTOS_Slowdown_CI_Lo_pct", "RTOS_Slowdown_CI_Hi_pct",
    "RTOS_Tail_Amp_CI_Lo", "RTOS_Tail_Amp_CI_Hi",
    "RTOS_Stress_Perm_P", "RTOS_N_Baseline", "RTOS_N_Stress",
    "Deadline_Budget_us", "Deadline_Slack_p50_us",
    "Deadline_Slack_p99_us", "Deadline_Miss_Risk_pct",
    "ISR_Injection_Rate_Hz", "ISR_Injected_Cycles_Avg",
    "ISR_Injection_Slowdown_pct", "ISR_Dispatch_Tax_Cycles",
    "Coop_Victim_Idle_Ticks", "Coop_Victim_Op_Ticks",
    "Coop_Starvation_pct", "Coop_Fairness_Index",
    "Release_Period_us", "Release_Latency_p50_Cycles",
    "Release_Latency_p99_Cycles", "Release_Jitter_Cycles",
    "Release_Overruns",
    "Stack_Used_Bytes",
    "Stack_Peak_Bytes", "Stack_Available_Bytes", "Heap_Peak_Bytes",
    "Heap_Alloc_Total_Bytes", "Heap_Alloc_Calls", "Working_Set_Peak_Bytes",
    "Peak_Memory_Per_Session_Crypto_Byte", "Peak_Memory_Per_Op_IO_Byte",
    "Cycles_SHA2", "Cycles_SHA3_Keccak", "Cycles_AES",
    "Cycles_Symmetric_Total", "Symmetric_Cycles_Pct", "SHA2_Share_pct",
    "SHA3_Keccak_Share_pct", "AES_Share_pct", "Dominant_Symmetric_Primitive",
    "Instr_Count", "Cache_Misses", "Branch_Mispredictions",
    "Cache_Misses_Per_KInstr", "Branch_Mispredictions_Per_KInstr",
    "TEE_Mode", "TEE_Provider", "TEE_Overhead_Cycles", "TEE_Overhead_pct",
    "TEE_World_Switch_Cycles", "TEE_Context_Save_Cycles",
    "TEE_Context_Restore_Cycles", "TEE_RNG_Overhead_Cycles",
    "TEE_IPC_Overhead_Cycles", "TEE_RNG_Calls", "TEE_RNG_Bytes"
};

static const char *DSA_V2_FIELDS[] = {
    "DSA", "Variant", "PK_Bytes", "SK_Bytes", "Sig_Bytes", "Operation",
    "Iterations", "Avg_Cycles", "Min_Cycles", "Max_Cycles", "StdDev_Cycles",
    "Energy_uJ", "StdDev_Energy_uJ", "Energy_Model_Tag", "Jitter_Cycles",
    "CoeffVar_pct", "p50_Cycles", "p95_Cycles", "p99_Cycles",
    "Q1_Cycles", "Q3_Cycles", "IQR_Cycles", "Quartile_Coeff_Dispersion_pct",
    "MAD_Cycles",
    "Entropy_Success_pct", "Avg_Latency_Entropy_ms", "RNG_Bytes_Consumed",
    "RNG_Call_Count", "RNG_Failures", "RNG_Shannon_Entropy",
    "RNG_Min_Entropy_H_inf", "RNG_Bytes_Per_Call", "Session_Crypto_Bytes",
    "Operation_IO_Bytes", "Cycles_Per_Session_Crypto_Byte",
    "Energy_Per_Session_Crypto_Byte_uJ", "Cycles_Per_Op_IO_Byte",
    "Cycles_At_128KB_RAM_Cap", "Failure_128KB_pct", "Cycles_At_64KB_RAM_Cap",
    "Failure_64KB_pct", "Cycles_Throttled_50pct",
    "Latency_Throttled_50pct_ms", "Jitter_Adder_Throttled_Cycles",
    "Throttle_Slowdown_pct", "Cycles_Cache_TLB_Stress",
    "Cycles_Memory_BW_Stress", "Cycles_Branch_Stress",
    "Tail_Amplification_Factor", "Throttle_Profile_Used",
    "p50_Stress_Cycles", "p99_Stress_Cycles", "Jitter_Stress_Cycles",
    "Min_Stress_Cycles", "Max_Stress_Cycles", "RTOS_Stress_Avg_Cycles",
    "RTOS_Stress_Slowdown_Pct", "RTOS_Stress_Activations",
    "RTOS_Stress_Jitter_Cycles", "RTOS_Stress_p50_Cycles",
    "RTOS_Stress_p95_Cycles", "RTOS_Stress_p99_Cycles",
    "RTOS_Tail_Amplification_Factor",
    "RTOS_Slowdown_CI_Lo_pct", "RTOS_Slowdown_CI_Hi_pct",
    "RTOS_Tail_Amp_CI_Lo", "RTOS_Tail_Amp_CI_Hi",
    "RTOS_Stress_Perm_P", "RTOS_N_Baseline", "RTOS_N_Stress",
    "Deadline_Budget_us", "Deadline_Slack_p50_us",
    "Deadline_Slack_p99_us", "Deadline_Miss_Risk_pct",
    "ISR_Injection_Rate_Hz", "ISR_Injected_Cycles_Avg",
    "ISR_Injection_Slowdown_pct", "ISR_Dispatch_Tax_Cycles",
    "Coop_Victim_Idle_Ticks", "Coop_Victim_Op_Ticks",
    "Coop_Starvation_pct", "Coop_Fairness_Index",
    "Release_Period_us", "Release_Latency_p50_Cycles",
    "Release_Latency_p99_Cycles", "Release_Jitter_Cycles",
    "Release_Overruns",
    "Stack_Used_Bytes",
    "Stack_Peak_Bytes", "Stack_Available_Bytes", "Heap_Peak_Bytes",
    "Heap_Alloc_Total_Bytes", "Heap_Alloc_Calls", "Working_Set_Peak_Bytes",
    "Peak_Memory_Per_Session_Crypto_Byte", "Peak_Memory_Per_Op_IO_Byte",
    "Cycles_SHA2", "Cycles_SHA3_Keccak", "Cycles_AES",
    "Cycles_Symmetric_Total", "Symmetric_Cycles_Pct", "SHA2_Share_pct",
    "SHA3_Keccak_Share_pct", "AES_Share_pct", "Dominant_Symmetric_Primitive",
    "Instr_Count", "Cache_Misses", "Branch_Mispredictions",
    "Cache_Misses_Per_KInstr", "Branch_Mispredictions_Per_KInstr",
    "TEE_Mode", "TEE_Provider", "TEE_Overhead_Cycles", "TEE_Overhead_pct",
    "TEE_World_Switch_Cycles", "TEE_Context_Save_Cycles",
    "TEE_Context_Restore_Cycles", "TEE_RNG_Overhead_Cycles",
    "TEE_IPC_Overhead_Cycles", "TEE_RNG_Calls", "TEE_RNG_Bytes"
};

static void print_field_breakdown(const char *line,
                                  const char *const *field_names,
                                  size_t field_count) {
    char buffer[8192];
    char *tokens[128];
    size_t token_count = 0;
    char *cursor = NULL;

    strncpy(buffer, line, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    char *token = strtok_r(buffer, ",", &cursor);
    while (token && token_count < 128) {
        tokens[token_count++] = token;
        token = strtok_r(NULL, ",", &cursor);
    }

    printf("Field count: %zu\n", token_count);
    if (token_count != field_count) {
        printf("WARNING: expected %zu v2 fields but found %zu\n", field_count, token_count);
    }

    size_t limit = token_count < field_count ? token_count : field_count;
    for (size_t i = 0; i < limit; ++i) {
        printf("  %02zu. %-36s = %s\n", i + 1, field_names[i], tokens[i]);
    }
}

/**
 * Explain a single raw v2 CSV data row by printing field/value pairs.
 */
static void explain_csv_data_line(const char *line) {
    if (!line || !*line) {
        printf("Error: empty CSV line\n");
        return;
    }

    if (strncmp(line, "DSA,", 4) == 0 ||
        strstr(line, ",sign,") != NULL ||
        strstr(line, ",verify,") != NULL) {
        print_field_breakdown(line, DSA_V2_FIELDS,
                              sizeof(DSA_V2_FIELDS) / sizeof(DSA_V2_FIELDS[0]));
    } else {
        print_field_breakdown(line, KEM_V2_FIELDS,
                              sizeof(KEM_V2_FIELDS) / sizeof(KEM_V2_FIELDS[0]));
    }
}

/**
 * Print a compact legend for the Balanced v2 raw CSV schema.
 */
static void print_csv_legend(void) {
    printf("\n=== BALANCED V2 CSV LEGEND ===\n");
    printf("Identity: algorithm/variant/sizes/op/iterations\n");
    printf("Core timing: Avg/Min/Max/StdDev + percentiles + MAD + jitter\n");
    printf("SUPERCOP-style distribution: Q1/Q3/IQR + quartile dispersion coefficient\n");
    printf("Entropy: success/latency + RNG bytes/calls/failures + entropy estimates\n");
    printf("Byte efficiency: session bytes, operation I/O bytes, cycles/byte, energy/byte\n");
    printf("Stress: RAM caps, throttled slowdown, cache/TLB, memory BW, branch, tail amp\n");
    printf("RTOS stress: matched baseline vs stressed window, activations, p50/p95/p99\n");
    printf("RTOS CI (reproducible, seed=FNV-1a(algo|op|isa)): slowdown CI95, tail-amp CI95, permutation p, n_base/n_stress\n");
    printf("Deadline: budget_us (default 10ms), slack_p50_us, slack_p99_us (negative=miss), miss_risk_pct (piecewise-CDF interpolation)\n");
    printf("ISR-Injection Tax (IITP): k_timer-scheduled ISR-context callback at 10 kHz; reports observed injection rate, injected avg cycles, slowdown pct, per-ISR kernel dispatch tax\n");
    printf("Cooperative Fairness to Co-Runners (CFCR): higher-priority k_sem-gated victim woken by 4 kHz k_timer; idle vs op wake-tick ratio measures cost imposed on co-runners\n");
    printf("Periodic Release Jitter Profile (PRJP): 1 kHz k_timer release latency under PQC load; p50/p99/jitter cycles plus release-overrun count\n");
    printf("Footprint: stack, heap, working-set peak, peak-memory-per-byte ratios\n");
    printf("Symmetric attribution: SHA-2, SHA3/Keccak, AES, subtotal, shares, dominant primitive\n");
    printf("Microarchitecture: instructions, cache misses, branch misses, miss rates per kInstr\n");
    printf("TEE: mode/provider plus detailed overhead breakdown\n");
}

#endif // CSV_INTERPRETER_H

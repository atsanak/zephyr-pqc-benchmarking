#!/usr/bin/env python3
"""Validate the canonical v2 unified CSV schema and metric invariants."""

from __future__ import annotations

import argparse
import csv
import math
from collections import defaultdict
from pathlib import Path

try:
    from schema_v2 import LEGACY_CORE_COLUMNS, OPERATION_ORDER, UNIFIED_COLUMNS
except ImportError:
    from PQClean.scripts.schema_v2 import LEGACY_CORE_COLUMNS, OPERATION_ORDER, UNIFIED_COLUMNS  # type: ignore


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", required=True)
    parser.add_argument("--reference-csv")
    return parser.parse_args()


def load_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        return reader.fieldnames or [], list(reader)


def numeric(value: str) -> float | None:
    if value in {"", "NA", "NaN", "None", None}:  # type: ignore[arg-type]
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def validate_schema(header: list[str]) -> list[str]:
    errors = []
    if header != UNIFIED_COLUMNS:
        errors.append(
            f"Header mismatch: expected {len(UNIFIED_COLUMNS)} canonical columns, got {len(header)}"
        )
    for col in LEGACY_CORE_COLUMNS:
        if col not in header:
            errors.append(f"Missing legacy core column: {col}")
    return errors


def validate_rows(rows: list[dict[str, str]]) -> list[str]:
    errors = []
    warnings = []  # non-fatal notices (e.g. QEMU timing artefacts)
    required_v2_fields = [
        "Schema_Version",
        "Benchmark_Layer",
        "Implementation_Corpus",
        "F_nom_Hz",
        "Main_Stack_Size",
        "Heap_Pool_Size",
        "Q1_Cycles",
        "Q3_Cycles",
        "IQR_Cycles",
        "Quartile_Coeff_Dispersion_pct",
        "Session_Crypto_Bytes",
        "Operation_IO_Bytes",
        "RTOS_Stress_Avg_Cycles",
        "RTOS_Stress_Slowdown_Pct",
        "RTOS_Stress_Activations",
        "Heap_Peak_Bytes",
        "Heap_Alloc_Total_Bytes",
        "Heap_Alloc_Calls",
        "Working_Set_Peak_Bytes",
        "Peak_Total_Memory_Bytes",
        "Ops_Per_Sec",
        "Session_Bytes_Per_Sec",
        "Ops_Per_mJ",
        "Peak_Total_Memory_Per_Session_Crypto_Byte",
        "Peak_Total_Memory_Per_Op_IO_Byte",
        "Stack_Peak_Pct_Of_Config",
        "Heap_Peak_Pct_Of_Config",
        "Working_Set_Pct_Of_Config_Memory",
        "Cycles_SHA2",
        "Cycles_SHA3_Keccak",
        "Cycles_AES",
        "Cycles_Symmetric_Total",
        "Symmetric_Cycles_Pct",
    ]

    for idx, row in enumerate(rows, start=2):
        for field in required_v2_fields:
            if row.get(field, "") == "":
                errors.append(f"Row {idx}: missing required v2 field {field}")

        if row["Schema_Version"] != "v2":
            errors.append(f"Row {idx}: unexpected Schema_Version={row['Schema_Version']}")
        if row["Benchmark_Layer"] != "primitive_rtos":
            errors.append(f"Row {idx}: unexpected Benchmark_Layer={row['Benchmark_Layer']}")
        if row["Implementation_Corpus"] != "PQClean":
            errors.append(f"Row {idx}: unexpected Implementation_Corpus={row['Implementation_Corpus']}")

        q1 = numeric(row["Q1_Cycles"])
        p50 = numeric(row["RTOS_Stress_p50_Cycles"])
        p95 = numeric(row["RTOS_Stress_p95_Cycles"])
        p99 = numeric(row["RTOS_Stress_p99_Cycles"])
        base_p50 = numeric(row["p50_Cycles"])
        q3 = numeric(row["Q3_Cycles"])
        base_p95 = numeric(row["p95_Cycles"])
        activations = numeric(row["RTOS_Stress_Activations"])
        tail_amp = numeric(row["RTOS_Tail_Amplification_Factor"])
        avg_cycles = numeric(row["Avg_Cycles"])
        sym_total = numeric(row["Cycles_Symmetric_Total"])
        sha2_share = numeric(row["SHA2_Share_pct"])
        sha3_share = numeric(row["SHA3_Keccak_Share_pct"])
        aes_share = numeric(row["AES_Share_pct"])
        peak_session = numeric(row["Peak_Memory_Per_Session_Crypto_Byte"])
        peak_op = numeric(row["Peak_Memory_Per_Op_IO_Byte"])
        peak_total = numeric(row["Peak_Total_Memory_Bytes"])
        peak_total_session = numeric(row["Peak_Total_Memory_Per_Session_Crypto_Byte"])
        peak_total_op = numeric(row["Peak_Total_Memory_Per_Op_IO_Byte"])
        stack_peak_pct = numeric(row["Stack_Peak_Pct_Of_Config"])
        heap_peak_pct = numeric(row["Heap_Peak_Pct_Of_Config"])
        working_set_pct = numeric(row["Working_Set_Pct_Of_Config_Memory"])
        ops_per_sec = numeric(row["Ops_Per_Sec"])
        session_bps = numeric(row["Session_Bytes_Per_Sec"])
        ops_per_mj = numeric(row["Ops_Per_mJ"])
        dominant_sym = row["Dominant_Symmetric_Primitive"]
        instr_count = numeric(row["Instr_Count"])
        cache_misses = numeric(row["Cache_Misses"])
        branch_misses = numeric(row["Branch_Mispredictions"])
        cache_per_kinstr = numeric(row["Cache_Misses_Per_KInstr"])
        branch_per_kinstr = numeric(row["Branch_Mispredictions_Per_KInstr"])

        if q1 is not None and base_p50 is not None and q1 > base_p50:
            errors.append(f"Row {idx}: Q1 exceeds p50")
        if base_p50 is not None and q3 is not None and base_p50 > q3:
            errors.append(f"Row {idx}: p50 exceeds Q3")
        if q3 is not None and base_p95 is not None and q3 > base_p95:
            errors.append(f"Row {idx}: Q3 exceeds p95")
        if p50 is not None and p95 is not None and p50 > p95:
            errors.append(f"Row {idx}: RTOS p50 exceeds p95")
        if p95 is not None and p99 is not None and p95 > p99:
            errors.append(f"Row {idx}: RTOS p95 exceeds p99")
        if activations is not None and activations < 0:
            errors.append(f"Row {idx}: negative RTOS activations")
        if tail_amp is not None and tail_amp < 0:
            errors.append(f"Row {idx}: negative RTOS tail amplification")

        ci_slow_lo = numeric(row.get("RTOS_Slowdown_CI_Lo_pct", ""))
        ci_slow_hi = numeric(row.get("RTOS_Slowdown_CI_Hi_pct", ""))
        ci_tail_lo = numeric(row.get("RTOS_Tail_Amp_CI_Lo", ""))
        ci_tail_hi = numeric(row.get("RTOS_Tail_Amp_CI_Hi", ""))
        perm_p     = numeric(row.get("RTOS_Stress_Perm_P", ""))
        n_base     = numeric(row.get("RTOS_N_Baseline", ""))
        n_stress   = numeric(row.get("RTOS_N_Stress", ""))
        if ci_slow_lo is not None and ci_slow_hi is not None and ci_slow_lo > ci_slow_hi:
            errors.append(f"Row {idx}: RTOS_Slowdown CI lo exceeds hi")
        if ci_tail_lo is not None and ci_tail_hi is not None and ci_tail_lo > ci_tail_hi:
            errors.append(f"Row {idx}: RTOS_Tail_Amp CI lo exceeds hi")
        if ci_tail_lo is not None and ci_tail_lo < 0:
            errors.append(f"Row {idx}: negative RTOS_Tail_Amp_CI_Lo")
        if perm_p is not None and not (0.0 <= perm_p <= 1.0):
            errors.append(f"Row {idx}: RTOS_Stress_Perm_P out of [0,1]: {perm_p}")
        if n_base is not None and n_base < 0:
            errors.append(f"Row {idx}: negative RTOS_N_Baseline")
        if n_stress is not None and n_stress < 0:
            errors.append(f"Row {idx}: negative RTOS_N_Stress")
        deadline_budget    = numeric(row.get("Deadline_Budget_us", ""))
        deadline_slack_p99 = numeric(row.get("Deadline_Slack_p99_us", ""))
        miss_risk          = numeric(row.get("Deadline_Miss_Risk_pct", ""))
        if deadline_budget is not None and deadline_budget <= 0:
            errors.append(f"Row {idx}: Deadline_Budget_us must be positive")
        if miss_risk is not None and not (0.0 <= miss_risk <= 100.0):
            errors.append(f"Row {idx}: Deadline_Miss_Risk_pct out of [0,100]: {miss_risk}")
        if (deadline_budget is not None and deadline_slack_p99 is not None and
                deadline_slack_p99 > deadline_budget):
            errors.append(f"Row {idx}: Deadline_Slack_p99_us exceeds budget "
                          f"(slack={deadline_slack_p99:.1f} > budget={deadline_budget:.1f})")
        isr_rate         = numeric(row.get("ISR_Injection_Rate_Hz", ""))
        isr_inj_avg      = numeric(row.get("ISR_Injected_Cycles_Avg", ""))
        isr_slowdown_pct = numeric(row.get("ISR_Injection_Slowdown_pct", ""))
        isr_tax_cycles   = numeric(row.get("ISR_Dispatch_Tax_Cycles", ""))
        if isr_rate is not None and isr_rate < 0:
            errors.append(f"Row {idx}: negative ISR_Injection_Rate_Hz")
        if isr_inj_avg is not None and isr_inj_avg < 0:
            errors.append(f"Row {idx}: negative ISR_Injected_Cycles_Avg")
        if isr_slowdown_pct is not None and isr_slowdown_pct < -50.0:
            errors.append(f"Row {idx}: implausible ISR_Injection_Slowdown_pct "
                          f"({isr_slowdown_pct:.2f}); IITP should not speed up a primitive")
        if (isr_rate is not None and isr_rate > 0 and
                isr_tax_cycles is not None and isr_tax_cycles < 0):
            warnings.append(f"Row {idx}: negative ISR_Dispatch_Tax_Cycles (QEMU timing non-determinism)")

        # Cooperative Fairness to Co-Runners (CFCR) invariants
        coop_idle      = numeric(row.get("Coop_Victim_Idle_Ticks", ""))
        coop_op        = numeric(row.get("Coop_Victim_Op_Ticks", ""))
        coop_starve    = numeric(row.get("Coop_Starvation_pct", ""))
        coop_fair      = numeric(row.get("Coop_Fairness_Index", ""))
        if coop_idle is not None and coop_idle < 0:
            errors.append(f"Row {idx}: negative Coop_Victim_Idle_Ticks")
        if coop_op is not None and coop_op < 0:
            errors.append(f"Row {idx}: negative Coop_Victim_Op_Ticks")
        if coop_starve is not None and not (0.0 <= coop_starve <= 100.0):
            errors.append(f"Row {idx}: Coop_Starvation_pct out of [0,100]: {coop_starve}")
        if coop_fair is not None and not (0.0 <= coop_fair <= 1.0):
            errors.append(f"Row {idx}: Coop_Fairness_Index out of [0,1]: {coop_fair}")

        # Periodic Release Jitter Profile (PRJP) invariants
        rel_period   = numeric(row.get("Release_Period_us", ""))
        rel_p50      = numeric(row.get("Release_Latency_p50_Cycles", ""))
        rel_p99      = numeric(row.get("Release_Latency_p99_Cycles", ""))
        rel_jitter   = numeric(row.get("Release_Jitter_Cycles", ""))
        rel_overruns = numeric(row.get("Release_Overruns", ""))
        if rel_period is not None and rel_period <= 0:
            errors.append(f"Row {idx}: Release_Period_us must be positive")
        if (rel_p50 is not None and rel_p99 is not None and rel_p50 > rel_p99):
            errors.append(f"Row {idx}: Release_Latency_p50 > p99 "
                          f"(p50={rel_p50}, p99={rel_p99})")
        if rel_jitter is not None and rel_jitter < 0:
            errors.append(f"Row {idx}: negative Release_Jitter_Cycles")
        if rel_overruns is not None and rel_overruns < 0:
            errors.append(f"Row {idx}: negative Release_Overruns")

        if sym_total is not None and avg_cycles is not None and sym_total > avg_cycles:
            errors.append(f"Row {idx}: symmetric cycle subtotal exceeds Avg_Cycles")
        if peak_session is not None and peak_session < 0:
            errors.append(f"Row {idx}: negative Peak_Memory_Per_Session_Crypto_Byte")
        if peak_op is not None and peak_op < 0:
            errors.append(f"Row {idx}: negative Peak_Memory_Per_Op_IO_Byte")
        if peak_total is not None and peak_total < 0:
            errors.append(f"Row {idx}: negative Peak_Total_Memory_Bytes")
        if peak_total_session is not None and peak_total_session < 0:
            errors.append(f"Row {idx}: negative Peak_Total_Memory_Per_Session_Crypto_Byte")
        if peak_total_op is not None and peak_total_op < 0:
            errors.append(f"Row {idx}: negative Peak_Total_Memory_Per_Op_IO_Byte")
        if stack_peak_pct is not None and stack_peak_pct < 0:
            errors.append(f"Row {idx}: negative Stack_Peak_Pct_Of_Config")
        if heap_peak_pct is not None and heap_peak_pct < 0:
            errors.append(f"Row {idx}: negative Heap_Peak_Pct_Of_Config")
        if working_set_pct is not None and working_set_pct < 0:
            errors.append(f"Row {idx}: negative Working_Set_Pct_Of_Config_Memory")
        if ops_per_sec is not None and ops_per_sec <= 0:
            errors.append(f"Row {idx}: non-positive Ops_Per_Sec")
        if session_bps is not None and session_bps < 0:
            errors.append(f"Row {idx}: negative Session_Bytes_Per_Sec")
        if ops_per_mj is not None and ops_per_mj <= 0:
            errors.append(f"Row {idx}: non-positive Ops_Per_mJ")
        if sym_total is not None and sym_total > 0:
            share_sum = sum(v for v in (sha2_share, sha3_share, aes_share) if v is not None)
            if share_sum and not math.isclose(share_sum, 100.0, rel_tol=1e-3, abs_tol=1e-2):
                errors.append(f"Row {idx}: symmetric share percentages sum to {share_sum:.4f}, expected 100")
            if dominant_sym and dominant_sym not in {"SHA2", "SHA3_Keccak", "AES", "None"}:
                errors.append(f"Row {idx}: invalid Dominant_Symmetric_Primitive={dominant_sym}")
        if instr_count is None:
            if any(row.get(field, "") != "" for field in (
                "Cache_Misses",
                "Branch_Mispredictions",
                "Cache_Misses_Per_KInstr",
                "Branch_Mispredictions_Per_KInstr",
            )):
                errors.append(f"Row {idx}: PMU-derived fields present while Instr_Count is unavailable")
        else:
            if instr_count < 0:
                errors.append(f"Row {idx}: negative Instr_Count")
            if cache_misses is None or branch_misses is None:
                errors.append(f"Row {idx}: partial PMU data present")
            if instr_count > 0:
                if cache_per_kinstr is None or branch_per_kinstr is None:
                    errors.append(f"Row {idx}: missing PMU rate fields for non-zero Instr_Count")
        if peak_total is not None:
            stack_peak = numeric(row["Stack_Peak_Bytes"]) or 0.0
            heap_peak = numeric(row["Heap_Peak_Bytes"]) or 0.0
            if not math.isclose(peak_total, stack_peak + heap_peak, rel_tol=1e-6, abs_tol=1e-6):
                errors.append(f"Row {idx}: Peak_Total_Memory_Bytes mismatch vs stack+heap")

    grouped_rows = defaultdict(list)
    grouped_sizes = defaultdict(set)
    grouped_builds = defaultdict(set)

    for row in rows:
        algo_key = (row["Algorithm_Type"], row["Algorithm"], row["Variant"])
        build_key = (row["Algorithm_Type"], row["Algorithm"], row["Variant"], row["Board"])
        grouped_rows[algo_key].append(row)
        grouped_sizes[algo_key].add(row["Session_Crypto_Bytes"])
        build_tuple = (
            row["Binary_Text_Bytes"],
            row["Binary_Data_Bytes"],
            row["Binary_Bss_Bytes"],
            row["Binary_Flash_Bytes"],
            row["Binary_RAM_Bytes"],
        )
        grouped_builds[build_key].add(build_tuple)

    for algo_key, sizes in grouped_sizes.items():
        non_blank = {value for value in sizes if value != ""}
        if len(non_blank) > 1:
            errors.append(f"Session_Crypto_Bytes not constant for {algo_key}: {sorted(non_blank)}")

    for build_key, build_values in grouped_builds.items():
        non_blank = {value for value in build_values if any(part != "" for part in value)}
        if len(non_blank) > 1:
            errors.append(f"Binary footprint differs across operations for {build_key}")

    expected_io = {
        "KEM": {"keypair": "PK_Bytes", "encaps": "CT_or_Sig_Bytes", "decaps": "CT_or_Sig_Bytes"},
        "DSA": {"keypair": "PK_Bytes", "sign": "CT_or_Sig_Bytes", "verify": "CT_or_Sig_Bytes"},
    }
    for idx, row in enumerate(rows, start=2):
        target_col = expected_io.get(row["Algorithm_Type"], {}).get(row["Operation"])
        if not target_col:
            continue
        expected = row[target_col]
        actual = row["Operation_IO_Bytes"]
        if expected and actual and expected != actual:
            errors.append(
                f"Row {idx}: Operation_IO_Bytes={actual} does not match {target_col}={expected}"
            )

    if warnings:
        import sys
        for w in warnings:
            print(f"WARN: {w}", file=sys.stderr)
    return errors


def compare_reference(rows: list[dict[str, str]], reference_rows: list[dict[str, str]]) -> list[str]:
    errors = []
    key_cols = ("Algorithm_Type", "Algorithm", "Variant", "Operation", "ISA", "Board")
    metrics = [
        "Iterations",
        "Avg_Cycles",
        "Min_Cycles",
        "Max_Cycles",
        "StdDev_Cycles",
        "Energy_uJ",
        "Jitter_Cycles",
        "CoeffVar_pct",
        "p50_Cycles",
        "p95_Cycles",
        "p99_Cycles",
        "MAD_Cycles",
        "Entropy_Success_pct",
        "Avg_Latency_Entropy_ms",
    ]

    reference_map = {
        tuple(row[col] for col in key_cols): row
        for row in reference_rows
    }

    for row in rows:
        key = tuple(row[col] for col in key_cols)
        ref = reference_map.get(key)
        if not ref:
            continue
        for metric in metrics:
            cur_val = numeric(row.get(metric, ""))
            ref_val = numeric(ref.get(metric, ""))
            if cur_val is None or ref_val is None:
                continue
            if not math.isclose(cur_val, ref_val, rel_tol=1e-9, abs_tol=1e-6):
                errors.append(f"Regression mismatch for {key} metric {metric}: {cur_val} vs {ref_val}")
                break

    return errors


def main() -> int:
    args = parse_args()
    header, rows = load_rows(Path(args.csv))
    errors = []
    errors.extend(validate_schema(header))
    errors.extend(validate_rows(rows))

    if args.reference_csv:
        _, reference_rows = load_rows(Path(args.reference_csv))
        errors.extend(compare_reference(rows, reference_rows))

    if errors:
        print("VALIDATION FAILED")
        for err in errors:
            print(f" - {err}")
        return 1

    print(
        f"Validation passed for {args.csv}: "
        f"{len(rows)} rows, {len(header)} columns"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

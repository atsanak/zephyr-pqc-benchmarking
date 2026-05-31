#!/usr/bin/env python3
"""Build the canonical v2 unified benchmark CSV from raw benchmark logs."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

try:
    from schema_v2 import (
        BENCHMARK_LAYER,
        IMPLEMENTATION_CORPUS,
        ISA_TOKEN_ALIASES,
        OPERATION_ORDER,
        RAW_COMMON_COLUMNS,
        RAW_DSA_HEADER,
        RAW_ENV_PRELUDE_KEYS,
        RAW_KEM_HEADER,
        SCHEMA_VERSION,
        UNIFIED_COLUMNS,
        derive_assurance_metadata,
        derive_fips_standard,
        derive_implementation_path,
        normalize_raw_header,
        parse_zephyr_stat,
        resolve_board_from_filename,
        safe_board_name,
    )
except ImportError:
    from PQClean.scripts.schema_v2 import (  # type: ignore
        BENCHMARK_LAYER,
        IMPLEMENTATION_CORPUS,
        ISA_TOKEN_ALIASES,
        OPERATION_ORDER,
        RAW_COMMON_COLUMNS,
        RAW_DSA_HEADER,
        RAW_ENV_PRELUDE_KEYS,
        RAW_KEM_HEADER,
        SCHEMA_VERSION,
        UNIFIED_COLUMNS,
        derive_assurance_metadata,
        derive_fips_standard,
        derive_implementation_path,
        normalize_raw_header,
        parse_zephyr_stat,
        resolve_board_from_filename,
        safe_board_name,
    )


ROOT = Path(__file__).resolve().parents[2]
PQCLEAN_DIR = ROOT / "PQClean"
DEFAULT_LOGS_DIR = PQCLEAN_DIR / "src" / "benchmark_outputs"
DEFAULT_OUTPUT = PQCLEAN_DIR / "unified_benchmark_results.csv"
REQUIRED_V2_RAW_COLUMNS = {
    "Q1_Cycles",
    "Q3_Cycles",
    "IQR_Cycles",
    "Quartile_Coeff_Dispersion_pct",
    "Session_Crypto_Bytes",
    "Operation_IO_Bytes",
    "RTOS_Stress_Avg_Cycles",
    "Heap_Peak_Bytes",
    "Working_Set_Peak_Bytes",
    "Cycles_SHA2",
    "Instr_Count",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logs-dir", default=str(DEFAULT_LOGS_DIR))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    return parser.parse_args()


def clean_value(value: str) -> str:
    value = value.strip()
    if "#" in value:
        value = value.split("#", 1)[0].strip()
    if value in {"NA", "NaN", "None", "none"}:
        return ""
    return value


def int_or_none(value: str) -> int | None:
    value = clean_value(value)
    if not value:
        return None
    try:
        return int(float(value))
    except ValueError:
        return None


def float_or_none(value: str) -> float | None:
    value = clean_value(value)
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def normalize_energy_model_tag(raw_value: str) -> str:
    value = clean_value(raw_value)
    if value.lower() in ISA_TOKEN_ALIASES:
        return ""
    return value


def resolve_stat_file(log_path: Path) -> Path | None:
    board, _ = resolve_board_from_filename(log_path)
    board_safe = safe_board_name(board)
    candidates = [
        log_path.with_suffix(".stat"),
        PQCLEAN_DIR / "src" / f"build_{board_safe}" / "zephyr" / "zephyr.stat",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def map_row(header: list[str], tokens: list[str]) -> dict[str, str]:
    padded = list(tokens)
    if len(padded) < len(header):
        padded.extend([""] * (len(header) - len(padded)))
    return {name: clean_value(value) for name, value in zip(header, padded)}


def has_required_v2_raw_values(raw_row: dict[str, str]) -> bool:
    for column in REQUIRED_V2_RAW_COLUMNS:
        if clean_value(raw_row.get(column, "")) == "":
            return False
    return True


def has_required_v2_env_prelude(env_prelude: dict[str, str]) -> bool:
    for key in RAW_ENV_PRELUDE_KEYS:
        if clean_value(env_prelude.get(key, "")) == "":
            return False
    return True


def is_data_row(tokens: list[str], current_family: str | None) -> bool:
    if not current_family:
        return False
    if current_family == "KEM":
        return len(tokens) >= 7 and tokens[6] in {"keypair", "encaps", "decaps"}
    return len(tokens) >= 6 and tokens[5] in {"keypair", "sign", "verify"}


def build_unified_row(
    raw: dict[str, str],
    algorithm_type: str,
    board: str,
    isa: str,
    env_prelude: dict[str, str],
    source_file: str,
    stat_metrics: dict[str, str],
    extraction_timestamp: str,
) -> dict[str, str]:
    algorithm_key = "KEM" if algorithm_type == "KEM" else "DSA"
    algorithm = raw.get(algorithm_key, "")
    variant = raw.get("Variant", "")

    row = {column: "" for column in UNIFIED_COLUMNS}
    row["Schema_Version"] = SCHEMA_VERSION
    row["Benchmark_Layer"] = BENCHMARK_LAYER
    row["Implementation_Corpus"] = IMPLEMENTATION_CORPUS
    row["Implementation_Path"] = derive_implementation_path(algorithm_type, algorithm, variant)
    (
        row["Implementation_Assurance_Level"],
        row["Assurance_Evidence_Tag"],
        row["Benchmark_Uniqueness_Score"],
    ) = derive_assurance_metadata(row["Implementation_Corpus"], row["Implementation_Path"])
    row["Algorithm_Type"] = algorithm_type
    row["Algorithm"] = algorithm
    row["Variant"] = variant
    row["FIPS_Standard"] = derive_fips_standard(algorithm, algorithm_type)
    row["PK_Bytes"] = raw.get("PK_Bytes", "")
    row["SK_Bytes"] = raw.get("SK_Bytes", "")
    row["CT_or_Sig_Bytes"] = raw.get("CT_Bytes", raw.get("Sig_Bytes", ""))
    row["SS_Bytes"] = raw.get("SS_Bytes", "0" if algorithm_type == "DSA" else "")
    row["Operation"] = raw.get("Operation", "")
    row["ISA"] = isa
    row["Board"] = safe_board_name(board)
    row["F_nom_Hz"] = env_prelude.get("F_nom_Hz", "")
    row["Main_Stack_Size"] = env_prelude.get("Main_Stack_Size", "")
    row["Heap_Pool_Size"] = env_prelude.get("Heap_Pool_Size", "")

    for key in RAW_COMMON_COLUMNS:
        if key in row:
            row[key] = raw.get(key, "")

    row["Energy_Model_Tag"] = normalize_energy_model_tag(raw.get("Energy_Model_Tag", ""))
    row.update(stat_metrics)
    row["Source_File"] = source_file
    row["Extraction_Timestamp"] = extraction_timestamp
    derive_backfilled_metrics(row)
    apply_target_capability_masks(row, env_prelude)
    return row


def derive_backfilled_metrics(row: dict[str, str]) -> None:
    pk = int_or_none(row["PK_Bytes"])
    ct_or_sig = int_or_none(row["CT_or_Sig_Bytes"])
    avg_cycles = float_or_none(row["Avg_Cycles"])
    energy_uj = float_or_none(row["Energy_uJ"])
    f_nom_hz = float_or_none(row["F_nom_Hz"])
    stack_cfg = float_or_none(row["Main_Stack_Size"])
    heap_cfg = float_or_none(row["Heap_Pool_Size"])
    stack_peak = float_or_none(row["Stack_Peak_Bytes"])
    heap_peak = float_or_none(row["Heap_Peak_Bytes"])
    working_set_peak = float_or_none(row["Working_Set_Peak_Bytes"])
    binary_flash = float_or_none(row["Binary_Flash_Bytes"])
    binary_ram = float_or_none(row["Binary_RAM_Bytes"])
    symmetric_total = float_or_none(row["Cycles_Symmetric_Total"])
    cycles_sha2 = float_or_none(row["Cycles_SHA2"])
    cycles_sha3 = float_or_none(row["Cycles_SHA3_Keccak"])
    cycles_aes = float_or_none(row["Cycles_AES"])
    instr_count = float_or_none(row["Instr_Count"])
    cache_misses = float_or_none(row["Cache_Misses"])
    branch_misses = float_or_none(row["Branch_Mispredictions"])

    session_bytes = int_or_none(row["Session_Crypto_Bytes"])
    if session_bytes is None and pk is not None and ct_or_sig is not None:
        session_bytes = pk + ct_or_sig
        row["Session_Crypto_Bytes"] = str(session_bytes)

    op_io = int_or_none(row["Operation_IO_Bytes"])
    if op_io is None:
        if row["Operation"] == "keypair" and pk is not None:
            op_io = pk
        elif row["Operation"] in {"encaps", "decaps", "sign", "verify"} and ct_or_sig is not None:
            op_io = ct_or_sig
        if op_io is not None:
            row["Operation_IO_Bytes"] = str(op_io)

    if not row["Cycles_Per_Session_Crypto_Byte"] and avg_cycles is not None and session_bytes:
        row["Cycles_Per_Session_Crypto_Byte"] = f"{avg_cycles / session_bytes:.6f}"
    if not row["Energy_Per_Session_Crypto_Byte_uJ"] and energy_uj is not None and session_bytes:
        row["Energy_Per_Session_Crypto_Byte_uJ"] = f"{energy_uj / session_bytes:.6f}"
    if not row["Cycles_Per_Op_IO_Byte"] and avg_cycles is not None and op_io:
        row["Cycles_Per_Op_IO_Byte"] = f"{avg_cycles / op_io:.6f}"
    if not row["Ops_Per_Sec"] and avg_cycles is not None and avg_cycles > 0 and f_nom_hz is not None:
        row["Ops_Per_Sec"] = f"{f_nom_hz / avg_cycles:.6f}"
    ops_per_sec = float_or_none(row["Ops_Per_Sec"])
    if not row["Session_Bytes_Per_Sec"] and ops_per_sec is not None and session_bytes:
        row["Session_Bytes_Per_Sec"] = f"{ops_per_sec * session_bytes:.6f}"
    if not row["Ops_Per_mJ"] and energy_uj is not None and energy_uj > 0:
        row["Ops_Per_mJ"] = f"{1000.0 / energy_uj:.6f}"
    peak_total = None
    if stack_peak is not None or heap_peak is not None:
        peak_total = (stack_peak or 0.0) + (heap_peak or 0.0)
        row["Peak_Total_Memory_Bytes"] = str(int(round(peak_total)))
    if not row["Peak_Memory_Per_Session_Crypto_Byte"] and working_set_peak is not None and session_bytes:
        row["Peak_Memory_Per_Session_Crypto_Byte"] = f"{working_set_peak / session_bytes:.6f}"
    if not row["Peak_Memory_Per_Op_IO_Byte"] and working_set_peak is not None and op_io:
        row["Peak_Memory_Per_Op_IO_Byte"] = f"{working_set_peak / op_io:.6f}"
    if peak_total is not None and session_bytes:
        row["Peak_Total_Memory_Per_Session_Crypto_Byte"] = f"{peak_total / session_bytes:.6f}"
    if peak_total is not None and op_io:
        row["Peak_Total_Memory_Per_Op_IO_Byte"] = f"{peak_total / op_io:.6f}"
    if stack_cfg and stack_cfg > 0 and stack_peak is not None:
        row["Stack_Peak_Pct_Of_Config"] = f"{100.0 * stack_peak / stack_cfg:.6f}"
    if heap_cfg and heap_cfg > 0 and heap_peak is not None:
        row["Heap_Peak_Pct_Of_Config"] = f"{100.0 * heap_peak / heap_cfg:.6f}"
    configured_memory = (stack_cfg or 0.0) + (heap_cfg or 0.0)
    if configured_memory > 0 and working_set_peak is not None:
        row["Working_Set_Pct_Of_Config_Memory"] = f"{100.0 * working_set_peak / configured_memory:.6f}"
    if symmetric_total and symmetric_total > 0:
        if not row["SHA2_Share_pct"] and cycles_sha2 is not None:
            row["SHA2_Share_pct"] = f"{100.0 * cycles_sha2 / symmetric_total:.6f}"
        if not row["SHA3_Keccak_Share_pct"] and cycles_sha3 is not None:
            row["SHA3_Keccak_Share_pct"] = f"{100.0 * cycles_sha3 / symmetric_total:.6f}"
        if not row["AES_Share_pct"] and cycles_aes is not None:
            row["AES_Share_pct"] = f"{100.0 * cycles_aes / symmetric_total:.6f}"
        if not row["Dominant_Symmetric_Primitive"]:
            dominant = max(
                [("SHA2", cycles_sha2 or 0.0), ("SHA3_Keccak", cycles_sha3 or 0.0), ("AES", cycles_aes or 0.0)],
                key=lambda item: item[1],
            )
            row["Dominant_Symmetric_Primitive"] = dominant[0] if dominant[1] > 0 else "None"
    if instr_count and instr_count > 0:
        if not row["Cache_Misses_Per_KInstr"] and cache_misses is not None:
            row["Cache_Misses_Per_KInstr"] = f"{1000.0 * cache_misses / instr_count:.6f}"
        if not row["Branch_Mispredictions_Per_KInstr"] and branch_misses is not None:
            row["Branch_Mispredictions_Per_KInstr"] = f"{1000.0 * branch_misses / instr_count:.6f}"
    if session_bytes:
        if not row["Binary_Flash_Per_Session_Crypto_Byte"] and binary_flash is not None:
            row["Binary_Flash_Per_Session_Crypto_Byte"] = f"{binary_flash / session_bytes:.6f}"
        if not row["Binary_RAM_Per_Session_Crypto_Byte"] and binary_ram is not None:
            row["Binary_RAM_Per_Session_Crypto_Byte"] = f"{binary_ram / session_bytes:.6f}"


def apply_target_capability_masks(row: dict[str, str], env_prelude: dict[str, str]) -> None:
    pmu_supported = clean_value(env_prelude.get("PMU_Counters_Supported", ""))
    if pmu_supported == "0":
        for key in (
            "Instr_Count",
            "Cache_Misses",
            "Branch_Mispredictions",
            "Cache_Misses_Per_KInstr",
            "Branch_Mispredictions_Per_KInstr",
        ):
            row[key] = ""


def extract_rows_from_log(log_path: Path) -> list[dict[str, str]]:
    board, isa = resolve_board_from_filename(log_path)
    extraction_timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    stat_metrics = parse_zephyr_stat(resolve_stat_file(log_path))
    log_text = log_path.read_text(errors="ignore")

    if f"Schema_Version,{SCHEMA_VERSION}" not in log_text:
        return []

    current_header: list[str] | None = None
    current_family: str | None = None
    env_prelude: dict[str, str] = {}
    rows: list[dict[str, str]] = []

    for raw_line in log_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("***"):
            continue
        tokens = next(csv.reader([line]))
        if not tokens:
            continue

        if len(tokens) >= 2 and tokens[0] in RAW_ENV_PRELUDE_KEYS:
            env_prelude[tokens[0]] = clean_value(tokens[1])
            continue

        if tokens[0] in {"KEM", "DSA"} and "Operation" in tokens:
            current_header = normalize_raw_header(tokens)
            expected_header = RAW_KEM_HEADER if tokens[0] == "KEM" else RAW_DSA_HEADER
            if current_header != expected_header:
                current_header = None
                current_family = None
                continue
            current_family = tokens[0]
            continue

        if not is_data_row(tokens, current_family):
            continue
        if not current_header:
            continue
        if current_family is None:
            continue

        raw_row = map_row(current_header, tokens)
        if not has_required_v2_raw_values(raw_row):
            continue
        if not has_required_v2_env_prelude(env_prelude):
            continue
        rows.append(
            build_unified_row(
                raw_row,
                current_family,
                board,
                isa,
                env_prelude,
                log_path.name,
                stat_metrics,
                extraction_timestamp,
            )
        )

    return rows


def row_sort_key(row: dict[str, str]) -> tuple:
    return (
        row["Algorithm_Type"],
        row["Algorithm"],
        row["Variant"],
        row["Board"],
        OPERATION_ORDER.get(row["Operation"], 99),
    )


def row_identity_key(row: dict[str, str]) -> tuple:
    return (
        row["Algorithm_Type"],
        row["Algorithm"],
        row["Variant"],
        row["Operation"],
        row["ISA"],
        row["Board"],
    )


def collect_rows(logs_dir: Path) -> list[dict[str, str]]:
    deduped: dict[tuple, dict[str, str]] = {}
    skipped_non_v2 = 0
    skipped_empty_v2 = 0
    log_paths = sorted(logs_dir.glob("benchmark_output_*.txt"), key=lambda p: (p.stat().st_mtime, p.name))
    for log_path in log_paths:
        rows = extract_rows_from_log(log_path)
        if not rows:
            log_text = log_path.read_text(errors="ignore")
            if f"Schema_Version,{SCHEMA_VERSION}" in log_text:
                skipped_empty_v2 += 1
            else:
                skipped_non_v2 += 1
            continue
        for row in rows:
            deduped[row_identity_key(row)] = row
    rows = list(deduped.values())
    rows.sort(key=row_sort_key)
    if skipped_non_v2:
        print(f"Skipped {skipped_non_v2} non-v{SCHEMA_VERSION[-1]} raw log(s) that do not declare Schema_Version,{SCHEMA_VERSION}")
    if skipped_empty_v2:
        print(f"Skipped {skipped_empty_v2} malformed {SCHEMA_VERSION} raw log(s) missing required v2 columns")
    return rows


def write_rows(output_path: Path, rows: Iterable[dict[str, str]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=UNIFIED_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in UNIFIED_COLUMNS})


def main() -> int:
    args = parse_args()
    logs_dir = Path(args.logs_dir)
    output_path = Path(args.output)

    rows = collect_rows(logs_dir)
    if not rows:
        print(
            f"No canonical {SCHEMA_VERSION} benchmark rows found in {logs_dir}. "
            f"Re-run benchmarks so raw logs declare Schema_Version,{SCHEMA_VERSION} "
            "and emit the full v2 header."
        )
        return 1
    write_rows(output_path, rows)
    print(
        f"Built {output_path} with {len(rows)} rows and "
        f"{len(UNIFIED_COLUMNS)} columns from {logs_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

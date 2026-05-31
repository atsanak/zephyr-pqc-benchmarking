#!/usr/bin/env python3
"""Canonical unified CSV schema for the Zephyr PQClean benchmark pipeline."""

from __future__ import annotations

from pathlib import Path
import re

SCHEMA_VERSION = "v2"
BENCHMARK_LAYER = "primitive_rtos"
IMPLEMENTATION_CORPUS = "PQClean"

RAW_ENV_PRELUDE_KEYS = {
    "F_nom_Hz",
    "Main_Stack_Size",
    "Heap_Pool_Size",
    "Entropy_Source_Mode",
    "PMU_Counters_Supported",
}

RAW_COMMON_COLUMNS = [
    "Operation",
    "Iterations",
    "Avg_Cycles",
    "Min_Cycles",
    "Max_Cycles",
    "StdDev_Cycles",
    "Energy_uJ",
    "StdDev_Energy_uJ",
    "Energy_Model_Tag",
    "Jitter_Cycles",
    "CoeffVar_pct",
    "p50_Cycles",
    "p95_Cycles",
    "p99_Cycles",
    "Q1_Cycles",
    "Q3_Cycles",
    "IQR_Cycles",
    "Quartile_Coeff_Dispersion_pct",
    "MAD_Cycles",
    "Entropy_Success_pct",
    "Avg_Latency_Entropy_ms",
    "RNG_Bytes_Consumed",
    "RNG_Call_Count",
    "RNG_Failures",
    "RNG_Shannon_Entropy",
    "RNG_Min_Entropy_H_inf",
    "RNG_Bytes_Per_Call",
    "Session_Crypto_Bytes",
    "Operation_IO_Bytes",
    "Cycles_Per_Session_Crypto_Byte",
    "Energy_Per_Session_Crypto_Byte_uJ",
    "Cycles_Per_Op_IO_Byte",
    "Cycles_At_128KB_RAM_Cap",
    "Failure_128KB_pct",
    "Cycles_At_64KB_RAM_Cap",
    "Failure_64KB_pct",
    "Cycles_Throttled_50pct",
    "Latency_Throttled_50pct_ms",
    "Jitter_Adder_Throttled_Cycles",
    "Throttle_Slowdown_pct",
    "Cycles_Cache_TLB_Stress",
    "Cycles_Memory_BW_Stress",
    "Cycles_Branch_Stress",
    "Tail_Amplification_Factor",
    "Throttle_Profile_Used",
    "p50_Stress_Cycles",
    "p99_Stress_Cycles",
    "Jitter_Stress_Cycles",
    "Min_Stress_Cycles",
    "Max_Stress_Cycles",
    "RTOS_Stress_Avg_Cycles",
    "RTOS_Stress_Slowdown_Pct",
    "RTOS_Stress_Activations",
    "RTOS_Stress_Jitter_Cycles",
    "RTOS_Stress_p50_Cycles",
    "RTOS_Stress_p95_Cycles",
    "RTOS_Stress_p99_Cycles",
    "RTOS_Tail_Amplification_Factor",
    "RTOS_Slowdown_CI_Lo_pct",
    "RTOS_Slowdown_CI_Hi_pct",
    "RTOS_Tail_Amp_CI_Lo",
    "RTOS_Tail_Amp_CI_Hi",
    "RTOS_Stress_Perm_P",
    "RTOS_N_Baseline",
    "RTOS_N_Stress",
    "Deadline_Budget_us",
    "Deadline_Slack_p50_us",
    "Deadline_Slack_p99_us",
    "Deadline_Miss_Risk_pct",
    "ISR_Injection_Rate_Hz",
    "ISR_Injected_Cycles_Avg",
    "ISR_Injection_Slowdown_pct",
    "ISR_Dispatch_Tax_Cycles",
    "Coop_Victim_Idle_Ticks",
    "Coop_Victim_Op_Ticks",
    "Coop_Starvation_pct",
    "Coop_Fairness_Index",
    "Release_Period_us",
    "Release_Latency_p50_Cycles",
    "Release_Latency_p99_Cycles",
    "Release_Jitter_Cycles",
    "Release_Overruns",
    "Stack_Used_Bytes",
    "Stack_Peak_Bytes",
    "Stack_Available_Bytes",
    "Heap_Peak_Bytes",
    "Heap_Alloc_Total_Bytes",
    "Heap_Alloc_Calls",
    "Working_Set_Peak_Bytes",
    "Peak_Memory_Per_Session_Crypto_Byte",
    "Peak_Memory_Per_Op_IO_Byte",
    "Cycles_SHA2",
    "Cycles_SHA3_Keccak",
    "Cycles_AES",
    "Cycles_Symmetric_Total",
    "Symmetric_Cycles_Pct",
    "SHA2_Share_pct",
    "SHA3_Keccak_Share_pct",
    "AES_Share_pct",
    "Dominant_Symmetric_Primitive",
    "Instr_Count",
    "Cache_Misses",
    "Branch_Mispredictions",
    "Cache_Misses_Per_KInstr",
    "Branch_Mispredictions_Per_KInstr",
    "TEE_Mode",
    "TEE_Provider",
    "TEE_Overhead_Cycles",
    "TEE_Overhead_pct",
    "TEE_World_Switch_Cycles",
    "TEE_Context_Save_Cycles",
    "TEE_Context_Restore_Cycles",
    "TEE_RNG_Overhead_Cycles",
    "TEE_IPC_Overhead_Cycles",
    "TEE_RNG_Calls",
    "TEE_RNG_Bytes",
]

RAW_KEM_HEADER = [
    "KEM",
    "Variant",
    "PK_Bytes",
    "SK_Bytes",
    "CT_Bytes",
    "SS_Bytes",
    *RAW_COMMON_COLUMNS,
]

RAW_DSA_HEADER = [
    "DSA",
    "Variant",
    "PK_Bytes",
    "SK_Bytes",
    "Sig_Bytes",
    *RAW_COMMON_COLUMNS,
]

UNIFIED_COLUMNS = [
    "Schema_Version",
    "Benchmark_Layer",
    "Implementation_Corpus",
    "Implementation_Path",
    "Algorithm_Type",
    "Algorithm",
    "Variant",
    "FIPS_Standard",
    "PK_Bytes",
    "SK_Bytes",
    "CT_or_Sig_Bytes",
    "SS_Bytes",
    "Operation",
    "ISA",
    "Board",
    "F_nom_Hz",
    "Main_Stack_Size",
    "Heap_Pool_Size",
    "Iterations",
    "Avg_Cycles",
    "Min_Cycles",
    "Max_Cycles",
    "StdDev_Cycles",
    "Energy_uJ",
    "StdDev_Energy_uJ",
    "Energy_Model_Tag",
    "Jitter_Cycles",
    "CoeffVar_pct",
    "p50_Cycles",
    "p95_Cycles",
    "p99_Cycles",
    "Q1_Cycles",
    "Q3_Cycles",
    "IQR_Cycles",
    "Quartile_Coeff_Dispersion_pct",
    "MAD_Cycles",
    "Entropy_Success_pct",
    "Avg_Latency_Entropy_ms",
    "RNG_Bytes_Consumed",
    "RNG_Call_Count",
    "RNG_Failures",
    "RNG_Shannon_Entropy",
    "RNG_Min_Entropy_H_inf",
    "RNG_Bytes_Per_Call",
    "Session_Crypto_Bytes",
    "Operation_IO_Bytes",
    "Cycles_Per_Session_Crypto_Byte",
    "Energy_Per_Session_Crypto_Byte_uJ",
    "Cycles_Per_Op_IO_Byte",
    "Ops_Per_Sec",
    "Session_Bytes_Per_Sec",
    "Ops_Per_mJ",
    "Cycles_At_128KB_RAM_Cap",
    "Failure_128KB_pct",
    "Cycles_At_64KB_RAM_Cap",
    "Failure_64KB_pct",
    "Cycles_Throttled_50pct",
    "Latency_Throttled_50pct_ms",
    "Jitter_Adder_Throttled_Cycles",
    "Throttle_Slowdown_pct",
    "Cycles_Cache_TLB_Stress",
    "Cycles_Memory_BW_Stress",
    "Cycles_Branch_Stress",
    "Tail_Amplification_Factor",
    "Throttle_Profile_Used",
    "p50_Stress_Cycles",
    "p99_Stress_Cycles",
    "Jitter_Stress_Cycles",
    "Min_Stress_Cycles",
    "Max_Stress_Cycles",
    "RTOS_Stress_Avg_Cycles",
    "RTOS_Stress_Slowdown_Pct",
    "RTOS_Stress_Activations",
    "RTOS_Stress_Jitter_Cycles",
    "RTOS_Stress_p50_Cycles",
    "RTOS_Stress_p95_Cycles",
    "RTOS_Stress_p99_Cycles",
    "RTOS_Tail_Amplification_Factor",
    "RTOS_Slowdown_CI_Lo_pct",
    "RTOS_Slowdown_CI_Hi_pct",
    "RTOS_Tail_Amp_CI_Lo",
    "RTOS_Tail_Amp_CI_Hi",
    "RTOS_Stress_Perm_P",
    "RTOS_N_Baseline",
    "RTOS_N_Stress",
    "Deadline_Budget_us",
    "Deadline_Slack_p50_us",
    "Deadline_Slack_p99_us",
    "Deadline_Miss_Risk_pct",
    "ISR_Injection_Rate_Hz",
    "ISR_Injected_Cycles_Avg",
    "ISR_Injection_Slowdown_pct",
    "ISR_Dispatch_Tax_Cycles",
    "Coop_Victim_Idle_Ticks",
    "Coop_Victim_Op_Ticks",
    "Coop_Starvation_pct",
    "Coop_Fairness_Index",
    "Release_Period_us",
    "Release_Latency_p50_Cycles",
    "Release_Latency_p99_Cycles",
    "Release_Jitter_Cycles",
    "Release_Overruns",
    "Stack_Used_Bytes",
    "Stack_Peak_Bytes",
    "Stack_Available_Bytes",
    "Heap_Peak_Bytes",
    "Heap_Alloc_Total_Bytes",
    "Heap_Alloc_Calls",
    "Working_Set_Peak_Bytes",
    "Peak_Total_Memory_Bytes",
    "Peak_Memory_Per_Session_Crypto_Byte",
    "Peak_Memory_Per_Op_IO_Byte",
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
    "SHA2_Share_pct",
    "SHA3_Keccak_Share_pct",
    "AES_Share_pct",
    "Dominant_Symmetric_Primitive",
    "Instr_Count",
    "Cache_Misses",
    "Branch_Mispredictions",
    "Cache_Misses_Per_KInstr",
    "Branch_Mispredictions_Per_KInstr",
    "Binary_Text_Bytes",
    "Binary_Data_Bytes",
    "Binary_Bss_Bytes",
    "Binary_Flash_Bytes",
    "Binary_RAM_Bytes",
    "Binary_Flash_Per_Session_Crypto_Byte",
    "Binary_RAM_Per_Session_Crypto_Byte",
    "Implementation_Assurance_Level",
    "Assurance_Evidence_Tag",
    "Benchmark_Uniqueness_Score",
    "TEE_Mode",
    "TEE_Provider",
    "TEE_Overhead_Cycles",
    "TEE_Overhead_pct",
    "TEE_World_Switch_Cycles",
    "TEE_Context_Save_Cycles",
    "TEE_Context_Restore_Cycles",
    "TEE_RNG_Overhead_Cycles",
    "TEE_IPC_Overhead_Cycles",
    "TEE_RNG_Calls",
    "TEE_RNG_Bytes",
    "Source_File",
    "Extraction_Timestamp",
]

LEGACY_CORE_COLUMNS = [
    "Algorithm_Type",
    "Algorithm",
    "Variant",
    "FIPS_Standard",
    "PK_Bytes",
    "SK_Bytes",
    "CT_or_Sig_Bytes",
    "SS_Bytes",
    "Operation",
    "ISA",
    "Board",
    "Iterations",
    "Avg_Cycles",
    "Min_Cycles",
    "Max_Cycles",
    "StdDev_Cycles",
    "Energy_uJ",
    "StdDev_Energy_uJ",
    "Jitter_Cycles",
    "CoeffVar_pct",
    "p50_Cycles",
    "p95_Cycles",
    "p99_Cycles",
    "Q1_Cycles",
    "Q3_Cycles",
    "IQR_Cycles",
    "Quartile_Coeff_Dispersion_pct",
    "MAD_Cycles",
    "Entropy_Success_pct",
    "Avg_Latency_Entropy_ms",
    "RNG_Bytes_Consumed",
    "RNG_Call_Count",
    "RNG_Failures",
    "RNG_Shannon_Entropy",
    "RNG_Min_Entropy_H_inf",
    "RNG_Bytes_Per_Call",
    "Cycles_At_128KB_RAM_Cap",
    "Failure_128KB_pct",
    "Cycles_At_64KB_RAM_Cap",
    "Failure_64KB_pct",
    "Cycles_Throttled_50pct",
    "Latency_Throttled_50pct_ms",
    "Jitter_Adder_Throttled_Cycles",
    "Throttle_Slowdown_pct",
    "Cycles_Cache_TLB_Stress",
    "Cycles_Memory_BW_Stress",
    "Cycles_Branch_Stress",
    "Tail_Amplification_Factor",
    "Throttle_Profile_Used",
    "p50_Stress_Cycles",
    "p99_Stress_Cycles",
    "Jitter_Stress_Cycles",
    "Min_Stress_Cycles",
    "Max_Stress_Cycles",
    "Stack_Used_Bytes",
    "Stack_Peak_Bytes",
    "Stack_Available_Bytes",
    "Instr_Count",
    "Cache_Misses",
    "Branch_Mispredictions",
    "TEE_Mode",
    "TEE_Provider",
    "TEE_Overhead_Cycles",
    "TEE_Overhead_pct",
    "TEE_World_Switch_Cycles",
    "TEE_Context_Save_Cycles",
    "TEE_Context_Restore_Cycles",
    "TEE_RNG_Overhead_Cycles",
    "TEE_IPC_Overhead_Cycles",
    "TEE_RNG_Calls",
    "TEE_RNG_Bytes",
    "Source_File",
    "Extraction_Timestamp",
]

RAW_HEADER_ALIASES = {
    "Model_Tag": "Energy_Model_Tag",
    "CV_Pct": "CoeffVar_pct",
    "P50_Cycles": "p50_Cycles",
    "P95_Cycles": "p95_Cycles",
    "P99_Cycles": "p99_Cycles",
    "Entropy_Success_Pct": "Entropy_Success_pct",
    "RNG_Failure_Count": "RNG_Failures",
    "RNG_Min_Entropy": "RNG_Min_Entropy_H_inf",
    "Cycles_128KB_Cap": "Cycles_At_128KB_RAM_Cap",
    "Failure_128KB_Pct": "Failure_128KB_pct",
    "Cycles_64KB_Cap": "Cycles_At_64KB_RAM_Cap",
    "Failure_64KB_Pct": "Failure_64KB_pct",
    "Cycles_Throttled_50Pct": "Cycles_Throttled_50pct",
    "Latency_Throttled_ms": "Latency_Throttled_50pct_ms",
    "JitterAdder_Throttled": "Jitter_Adder_Throttled_Cycles",
    "Throttle_Slowdown_Pct": "Throttle_Slowdown_pct",
    "Cycles_CacheTLB_Stress": "Cycles_Cache_TLB_Stress",
    "Cycles_MemBW_Stress": "Cycles_Memory_BW_Stress",
    "TailAmp_Factor": "Tail_Amplification_Factor",
    "Throttle_Profile": "Throttle_Profile_Used",
    "P50_Stress": "p50_Stress_Cycles",
    "P99_Stress": "p99_Stress_Cycles",
    "Jitter_Stress": "Jitter_Stress_Cycles",
    "Min_Stress": "Min_Stress_Cycles",
    "Max_Stress": "Max_Stress_Cycles",
}

BOARD_MAP = {
    "qemu_x86_64": ("qemu_x86_64", "x86_64"),
    "qemu_x86": ("qemu_x86", "x86_32"),
    "qemu_riscv64": ("qemu_riscv64", "RISC-V_64"),
    "qemu_riscv32": ("qemu_riscv32", "RISC-V_32"),
    "qemu_riscv32e": ("qemu_riscv32e", "RISC-V_32E"),
    "qemu_cortex_a53": ("qemu_cortex_a53", "ARM_Cortex-A53"),
    "qemu_cortex_a9": ("qemu_cortex_a9", "ARM_Cortex-A9"),
    "qemu_cortex_r5": ("qemu_cortex_r5", "ARM_Cortex-R5"),
    "qemu_arc_qemu_arc_em": ("qemu_arc/qemu_arc_em", "ARC_EM"),
    "qemu_arc_qemu_arc_hs": ("qemu_arc/qemu_arc_hs", "ARC_HS"),
    "qemu_xtensa": ("qemu_xtensa", "Xtensa_ESP32"),
    "qemu_malta": ("qemu_malta", "MIPS_Malta"),
    "qemu_leon3": ("qemu_leon3", "SPARC_LEON3"),
}

ISA_TOKEN_ALIASES = {
    "x86_64",
    "x86",
    "riscv64",
    "riscv32",
    "riscv32e",
    "a53",
    "a9",
    "r5",
    "arc_em",
    "arc_hs",
    "xtensa",
    "malta",
    "leon3",
}

OPERATION_ORDER = {
    "keypair": 0,
    "encaps": 1,
    "decaps": 2,
    "sign": 1,
    "verify": 2,
}


def canonicalize_raw_header(name: str) -> str:
    return RAW_HEADER_ALIASES.get(name.strip(), name.strip())


def normalize_raw_header(fields: list[str]) -> list[str]:
    return [canonicalize_raw_header(field) for field in fields]


def resolve_board_from_filename(log_path: Path) -> tuple[str, str]:
    stem = log_path.stem
    for safe_name in sorted(BOARD_MAP, key=len, reverse=True):
        if stem.endswith("_" + safe_name):
            return BOARD_MAP[safe_name]
    return ("unknown", "unknown")


def safe_board_name(board: str) -> str:
    for safe_name, (canonical, _) in BOARD_MAP.items():
        if board == canonical:
            return safe_name
    return board.replace("/", "_")


def derive_fips_standard(algorithm: str, algorithm_type: str) -> str:
    algo = algorithm.lower()
    if algo.startswith("ml-kem"):
        return "FIPS203"
    if algo.startswith("ml-dsa"):
        return "FIPS204"
    if algo.startswith("sphincs"):
        return "FIPS205"
    if algo.startswith("falcon"):
        return "FIPS206"
    if algo.startswith("hqc"):
        return "HQC_Round4"
    if algo.startswith("mceliece"):
        return "McEliece_Round4"
    return "Unknown"


def derive_implementation_path(algorithm_type: str, algorithm: str, variant: str) -> str:
    base = "crypto_kem" if algorithm_type == "KEM" else "crypto_sign"
    return f"{base}/{algorithm}/{variant or 'clean'}"


def derive_assurance_metadata(
    implementation_corpus: str, implementation_path: str
) -> tuple[str, str, str]:
    corpus = implementation_corpus or "Unknown"
    path = implementation_path or ""

    if corpus == "PQClean":
        return (
            "dynamic_tested_ct_checked",
            "PQClean_CI_Valgrind_ASan_UBSan",
            "1.000",
        )
    if "mlkem-native" in path:
        return (
            "formal_proofs_plus_ct_hardening",
            "CBMC_HOLLight_Valgrind",
            "1.000",
        )
    return ("unknown", "unknown", "1.000")


def parse_zephyr_stat(stat_path: Path | None) -> dict[str, str]:
    metrics = {
        "Binary_Text_Bytes": "",
        "Binary_Data_Bytes": "",
        "Binary_Bss_Bytes": "",
        "Binary_Flash_Bytes": "",
        "Binary_RAM_Bytes": "",
    }
    if not stat_path or not stat_path.is_file():
        return metrics

    section_sizes: dict[str, int] = {}
    current_name = None
    section_header_re = re.compile(r"^\s*\[\s*\d+\]\s+([^\s]+)")
    size_line_re = re.compile(r"^\s*([0-9A-Fa-f]+)\s+[0-9A-Fa-f]+\s")

    for raw_line in stat_path.read_text(errors="ignore").splitlines():
        line = raw_line.rstrip("\n")

        header_match = section_header_re.match(line)
        if header_match:
            current_name = header_match.group(1)
            continue

        if current_name is None:
            continue

        size_match = size_line_re.match(line)
        if not size_match:
            continue

        try:
            section_sizes[current_name] = int(size_match.group(1), 16)
            current_name = None
        except ValueError:
            continue

    text = section_sizes.get("text", 0)
    rodata = section_sizes.get("rodata", 0)
    data = section_sizes.get("datas", 0)
    bss = section_sizes.get("bss", 0)

    metrics["Binary_Text_Bytes"] = str(text) if text else ""
    metrics["Binary_Data_Bytes"] = str(data) if data else ""
    metrics["Binary_Bss_Bytes"] = str(bss) if bss else ""

    flash = text + rodata + data
    ram = data + bss
    metrics["Binary_Flash_Bytes"] = str(flash) if flash else ""
    metrics["Binary_RAM_Bytes"] = str(ram) if ram else ""
    return metrics

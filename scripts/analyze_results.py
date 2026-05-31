#!/usr/bin/env python3
"""Validate and summarize the public benchmark CSV."""

from __future__ import annotations

import argparse
import csv
import statistics
from collections import Counter, defaultdict
from pathlib import Path


DEFAULT_CSV = Path("results/final/validated_results.csv")
DEFAULT_OUT = Path("results/summaries/results_summary.md")


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def family_for(algorithm: str) -> str:
    if algorithm.startswith("ml-kem"):
        return "ML-KEM"
    if algorithm.startswith("hqc"):
        return "HQC"
    if algorithm.startswith("ml-dsa"):
        return "ML-DSA"
    if algorithm.startswith("falcon"):
        return "Falcon"
    if algorithm.startswith("sphincs"):
        return "SLH-DSA / SPHINCS+"
    if algorithm.startswith("mceliece"):
        return "Classic McEliece"
    return "Other"


def f(row: dict[str, str], column: str) -> float:
    return float(row[column])


def validate(rows: list[dict[str, str]]) -> list[str]:
    issues: list[str] = []
    keys = Counter((r["Algorithm"], r["Operation"], r["ISA"], r["Board"]) for r in rows)
    duplicate_count = sum(1 for count in keys.values() if count > 1)
    if duplicate_count:
        issues.append(f"{duplicate_count} duplicate algorithm/operation/ISA/board keys")

    for row in rows:
        identity = f"{row['Algorithm']} {row['Operation']} {row['ISA']}"
        if f(row, "Avg_Cycles") <= 0:
            issues.append(f"{identity}: Avg_Cycles <= 0")
        if f(row, "Min_Cycles") <= 0:
            issues.append(f"{identity}: Min_Cycles <= 0")
        ordered = [
            f(row, "Min_Cycles"),
            f(row, "p50_Cycles"),
            f(row, "p95_Cycles"),
            f(row, "p99_Cycles"),
            f(row, "Max_Cycles"),
        ]
        if ordered != sorted(ordered):
            issues.append(f"{identity}: percentile ordering failed")
        if row.get("Source_File") and row["Algorithm"] not in row["Source_File"]:
            issues.append(f"{identity}: algorithm/source-file mismatch")
    return issues


def median(rows: list[dict[str, str]], column: str) -> float:
    return statistics.median(f(row, column) for row in rows)


def pct(count: int, total: int) -> float:
    return 100.0 * count / total if total else 0.0


def build_summary(rows: list[dict[str, str]], issues: list[str]) -> str:
    algorithms = sorted({r["Algorithm"] for r in rows})
    boards = sorted({r["Board"] for r in rows})
    isas = sorted({r["ISA"] for r in rows})
    operations = sorted({r["Operation"] for r in rows})

    cv_tight = sum(1 for r in rows if f(r, "CoeffVar_pct") < 0.2)
    taf_stable = sum(1 for r in rows if f(r, "Tail_Amplification_Factor") <= 1.05)
    heap_ok = sum(1 for r in rows if f(r, "Failure_64KB_pct") == 0.0)

    by_family: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_family[family_for(row["Algorithm"])].append(row)

    lines: list[str] = []
    lines.append("# Results Summary")
    lines.append("")
    lines.append("This summary is generated from `results/final/validated_results.csv`.")
    lines.append("")
    lines.append("## Dataset")
    lines.append("")
    lines.append(f"- Rows: {len(rows)}")
    lines.append(f"- Algorithms: {len(algorithms)}")
    lines.append(f"- ISA labels: {len(isas)}")
    lines.append(f"- QEMU boards: {len(boards)}")
    lines.append(f"- Operations: {', '.join(operations)}")
    lines.append("- Timed iterations per accepted row: 1000")
    lines.append("")
    lines.append("## Validation Checks")
    lines.append("")
    if issues:
        lines.append("The following issues were found:")
        for issue in issues:
            lines.append(f"- {issue}")
    else:
        lines.append("- No duplicate operation keys.")
        lines.append("- No non-positive cycle rows.")
        lines.append("- Percentile ordering passed for every row.")
        lines.append("- Algorithm names match source-file provenance for every row.")
    lines.append("")
    lines.append("## Headline Metrics")
    lines.append("")
    lines.append(f"- Rows with CV < 0.2%: {cv_tight}/{len(rows)} ({pct(cv_tight, len(rows)):.1f}%)")
    lines.append(f"- Rows with TAF <= 1.05: {taf_stable}/{len(rows)} ({pct(taf_stable, len(rows)):.1f}%)")
    lines.append(f"- Rows with no 64 KB heap-cap failure: {heap_ok}/{len(rows)} ({pct(heap_ok, len(rows)):.1f}%)")
    lines.append("")
    lines.append("## Family Summary")
    lines.append("")
    lines.append("| Family | Rows | Algorithms | Median cycles | Median CV (%) | Stack range (KB) |")
    lines.append("| --- | ---: | --- | ---: | ---: | ---: |")
    order = ["ML-KEM", "HQC", "ML-DSA", "Falcon", "SLH-DSA / SPHINCS+", "Classic McEliece"]
    for family in order:
        group = by_family.get(family, [])
        if not group:
            continue
        alg_list = ", ".join(sorted({r["Algorithm"] for r in group}))
        stack_min = min(f(r, "Stack_Peak_Bytes") for r in group) / 1024.0
        stack_max = max(f(r, "Stack_Peak_Bytes") for r in group) / 1024.0
        lines.append(
            f"| {family} | {len(group)} | {alg_list} | {median(group, 'Avg_Cycles'):,.0f} | "
            f"{median(group, 'CoeffVar_pct'):.3f} | {stack_min:.1f}-{stack_max:.1f} |"
        )
    lines.append("")
    lines.append("## KEM Comparison")
    lines.append("")
    mlkem = by_family["ML-KEM"]
    hqc = by_family["HQC"]
    if mlkem and hqc:
        cycle_ratio = median(hqc, "Avg_Cycles") / median(mlkem, "Avg_Cycles")
        energy_ratio = median(hqc, "Energy_uJ") / median(mlkem, "Energy_uJ")
        lines.append(f"- Median HQC/ML-KEM cycle ratio: {cycle_ratio:.1f}x")
        lines.append(f"- Median HQC/ML-KEM modelled-energy ratio: {energy_ratio:.1f}x")
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- Energy is modelled from cycle counts and ISA coefficients; it is not board-measured power.")
    lines.append("- QEMU results support controlled cross-ISA comparison, not physical-board timing certification.")
    lines.append("- `results/summaries/result_file_audit.md` explains which CSV files were included or excluded.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    rows = read_rows(args.csv)
    issues = validate(rows)
    summary = build_summary(rows, issues)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(summary, encoding="utf-8")
    print(f"Wrote {args.out}")
    if issues:
        print(f"Validation issues: {len(issues)}")
        return 1
    print("Validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


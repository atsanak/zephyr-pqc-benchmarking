#!/usr/bin/env python3
"""Validate and summarize the public benchmark CSV."""

from __future__ import annotations

import argparse
import csv
import html
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path


DEFAULT_CSV = Path("results/final/validated_results.csv")
DEFAULT_OUT = Path("results/summaries/results_summary.md")
DEFAULT_SUMMARY_DIR = Path("results/summaries")
DEFAULT_FIGURE_DIR = Path("figures/results")

FAMILY_ORDER = ["ML-KEM", "HQC", "ML-DSA", "Falcon", "SLH-DSA / SPHINCS+", "Classic McEliece"]
FAMILY_COLORS = {
    "ML-KEM": "#2f6fb0",
    "HQC": "#d98c2b",
    "ML-DSA": "#3f8f6b",
    "Falcon": "#7a5aa6",
    "SLH-DSA / SPHINCS+": "#7d6651",
    "Classic McEliece": "#b8483c",
}


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


def compact(value: float) -> str:
    if value >= 1_000_000_000:
        return f"{value / 1_000_000_000:.1f}B"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"{value / 1_000:.1f}K"
    return f"{value:.0f}"


def family_groups(rows: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[family_for(row["Algorithm"])].append(row)
    return groups


def build_summary(rows: list[dict[str, str]], issues: list[str]) -> str:
    algorithms = sorted({r["Algorithm"] for r in rows})
    boards = sorted({r["Board"] for r in rows})
    isas = sorted({r["ISA"] for r in rows})
    operations = sorted({r["Operation"] for r in rows})

    cv_tight = sum(1 for r in rows if f(r, "CoeffVar_pct") < 0.2)
    taf_stable = sum(1 for r in rows if f(r, "Tail_Amplification_Factor") <= 1.05)
    heap_ok = sum(1 for r in rows if f(r, "Failure_64KB_pct") == 0.0)

    by_family = family_groups(rows)

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
    for family in FAMILY_ORDER:
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
    lines.append("- `figures/results/` contains generated SVG figures from the same trusted CSV.")
    lines.append("")
    return "\n".join(lines)


def write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_derived_csvs(rows: list[dict[str, str]], out_dir: Path) -> None:
    by_family = family_groups(rows)
    family_rows: list[dict[str, object]] = []
    for family in FAMILY_ORDER:
        group = by_family.get(family, [])
        if not group:
            continue
        family_rows.append(
            {
                "Family": family,
                "Rows": len(group),
                "Algorithms": "; ".join(sorted({r["Algorithm"] for r in group})),
                "Median_Cycles": round(median(group, "Avg_Cycles"), 3),
                "Median_Energy_uJ": round(median(group, "Energy_uJ"), 3),
                "Median_CV_pct": round(median(group, "CoeffVar_pct"), 6),
                "Median_Entropy_ms": round(median(group, "Avg_Latency_Entropy_ms"), 3),
                "Min_Stack_KB": round(min(f(r, "Stack_Peak_Bytes") for r in group) / 1024.0, 3),
                "Max_Stack_KB": round(max(f(r, "Stack_Peak_Bytes") for r in group) / 1024.0, 3),
                "Failure64KB_Rows": sum(1 for r in group if f(r, "Failure_64KB_pct") > 0),
            }
        )
    write_csv(
        out_dir / "family_summary.csv",
        family_rows,
        [
            "Family",
            "Rows",
            "Algorithms",
            "Median_Cycles",
            "Median_Energy_uJ",
            "Median_CV_pct",
            "Median_Entropy_ms",
            "Min_Stack_KB",
            "Max_Stack_KB",
            "Failure64KB_Rows",
        ],
    )

    op_groups: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        op_groups[(family_for(row["Algorithm"]), row["Algorithm"], row["Operation"])].append(row)
    operation_rows = []
    for (family, algorithm, operation), group in sorted(op_groups.items()):
        operation_rows.append(
            {
                "Family": family,
                "Algorithm": algorithm,
                "Operation": operation,
                "Rows": len(group),
                "Median_Cycles": round(median(group, "Avg_Cycles"), 3),
                "Median_p99_Cycles": round(median(group, "p99_Cycles"), 3),
                "Median_CV_pct": round(median(group, "CoeffVar_pct"), 6),
                "Median_TAF": round(median(group, "Tail_Amplification_Factor"), 6),
                "Median_Energy_uJ": round(median(group, "Energy_uJ"), 3),
                "Median_Entropy_ms": round(median(group, "Avg_Latency_Entropy_ms"), 3),
                "Median_Stack_KB": round(median(group, "Stack_Peak_Bytes") / 1024.0, 3),
            }
        )
    write_csv(
        out_dir / "operation_summary.csv",
        operation_rows,
        [
            "Family",
            "Algorithm",
            "Operation",
            "Rows",
            "Median_Cycles",
            "Median_p99_Cycles",
            "Median_CV_pct",
            "Median_TAF",
            "Median_Energy_uJ",
            "Median_Entropy_ms",
            "Median_Stack_KB",
        ],
    )

    isa_groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        isa_groups[row["ISA"]].append(row)
    isa_rows = []
    for isa, group in sorted(isa_groups.items()):
        isa_rows.append(
            {
                "ISA": isa,
                "Rows": len(group),
                "Algorithms": len({r["Algorithm"] for r in group}),
                "Median_Cycles": round(median(group, "Avg_Cycles"), 3),
                "Median_CV_pct": round(median(group, "CoeffVar_pct"), 6),
                "Median_TAF": round(median(group, "Tail_Amplification_Factor"), 6),
                "Median_Energy_uJ": round(median(group, "Energy_uJ"), 3),
                "No64KBFailure_pct": round(pct(sum(1 for r in group if f(r, "Failure_64KB_pct") == 0.0), len(group)), 3),
            }
        )
    write_csv(
        out_dir / "isa_summary.csv",
        isa_rows,
        [
            "ISA",
            "Rows",
            "Algorithms",
            "Median_Cycles",
            "Median_CV_pct",
            "Median_TAF",
            "Median_Energy_uJ",
            "No64KBFailure_pct",
        ],
    )


def build_validation_report(rows: list[dict[str, str]], issues: list[str]) -> str:
    keys = Counter((r["Algorithm"], r["Operation"], r["ISA"], r["Board"]) for r in rows)
    iterations = Counter(r["Iterations"] for r in rows)
    lines = [
        "# Validation Report",
        "",
        "Generated from `results/final/validated_results.csv` by `scripts/analyze_results.py`.",
        "",
        "## Checks",
        "",
        f"- Rows checked: {len(rows)}",
        f"- Unique algorithm/operation/ISA/board keys: {len(keys)}",
        f"- Iteration-count distribution: {dict(sorted(iterations.items()))}",
        "- Required numeric fields parsed successfully.",
        "- Cycle fields are positive.",
        "- Percentiles are ordered as `min <= p50 <= p95 <= p99 <= max`.",
        "- Algorithm names match source-file provenance.",
        "",
        "## Result",
        "",
    ]
    if issues:
        lines.append("Validation failed:")
        lines.extend(f"- {issue}" for issue in issues)
    else:
        lines.append("Validation passed. This CSV is the trusted public result source.")
    lines.append("")
    return "\n".join(lines)


def svg_text(x: float, y: float, text: object, size: int = 13, anchor: str = "start", weight: str = "400") -> str:
    return (
        f'<text x="{x:.1f}" y="{y:.1f}" font-family="Arial, Helvetica, sans-serif" '
        f'font-size="{size}" text-anchor="{anchor}" font-weight="{weight}" fill="#1f2937">'
        f"{html.escape(str(text))}</text>"
    )


def write_svg(path: Path, width: int, height: int, body: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        *body,
        "</svg>",
        "",
    ]
    path.write_text("\n".join(content), encoding="utf-8")


def log_x(value: float, min_value: float, max_value: float, x0: float, x1: float) -> float:
    lo = math.log10(max(min_value, 1.0))
    hi = math.log10(max(max_value, min_value + 1.0))
    if hi == lo:
        return x1
    return x0 + (math.log10(max(value, 1.0)) - lo) / (hi - lo) * (x1 - x0)


def write_family_cycles_svg(rows: list[dict[str, str]], figure_dir: Path) -> None:
    groups = family_groups(rows)
    data = [(family, median(groups[family], "Avg_Cycles")) for family in FAMILY_ORDER if groups.get(family)]
    width, height = 980, 430
    x0, x1 = 230, 900
    y0, row_h = 88, 48
    values = [v for _, v in data]
    body = [
        svg_text(40, 38, "Median Cycle Cost by Algorithm Family", 24, weight="700"),
        svg_text(40, 62, "Log-scaled median Avg_Cycles from the trusted public CSV.", 13),
    ]
    for tick in [1e6, 1e7, 1e8, 1e9]:
        if min(values) <= tick <= max(values):
            x = log_x(tick, min(values), max(values), x0, x1)
            body.append(f'<line x1="{x:.1f}" y1="76" x2="{x:.1f}" y2="{height - 55}" stroke="#e5e7eb"/>')
            body.append(svg_text(x, height - 28, compact(tick), 11, "middle"))
    for i, (family, value) in enumerate(data):
        y = y0 + i * row_h
        color = FAMILY_COLORS[family]
        x = log_x(value, min(values), max(values), x0, x1)
        body.append(svg_text(40, y + 18, family, 14, weight="700"))
        body.append(f'<rect x="{x0}" y="{y}" width="{max(2, x - x0):.1f}" height="26" rx="5" fill="{color}"/>')
        body.append(svg_text(x + 10, y + 19, compact(value), 13))
    write_svg(figure_dir / "family_median_cycles.svg", width, height, body)


def write_stack_svg(rows: list[dict[str, str]], figure_dir: Path) -> None:
    groups = family_groups(rows)
    data = []
    for family in FAMILY_ORDER:
        group = groups.get(family, [])
        if group:
            data.append(
                (
                    family,
                    min(f(r, "Stack_Peak_Bytes") for r in group) / 1024.0,
                    max(f(r, "Stack_Peak_Bytes") for r in group) / 1024.0,
                )
            )
    width, height = 980, 430
    x0, x1 = 230, 900
    y0, row_h = 88, 48
    max_stack = max(hi for _, _, hi in data)
    body = [
        svg_text(40, 38, "Peak Stack Range by Algorithm Family", 24, weight="700"),
        svg_text(40, 62, "Min-to-max Stack_Peak_Bytes converted to KB.", 13),
    ]
    for tick in [64, 128, 256, 384]:
        if tick <= max_stack:
            x = x0 + tick / max_stack * (x1 - x0)
            body.append(f'<line x1="{x:.1f}" y1="76" x2="{x:.1f}" y2="{height - 55}" stroke="#e5e7eb"/>')
            body.append(svg_text(x, height - 28, f"{tick} KB", 11, "middle"))
    for i, (family, lo, hi) in enumerate(data):
        y = y0 + i * row_h
        color = FAMILY_COLORS[family]
        lo_x = x0 + lo / max_stack * (x1 - x0)
        hi_x = x0 + hi / max_stack * (x1 - x0)
        body.append(svg_text(40, y + 18, family, 14, weight="700"))
        body.append(f'<line x1="{lo_x:.1f}" y1="{y + 13:.1f}" x2="{hi_x:.1f}" y2="{y + 13:.1f}" stroke="{color}" stroke-width="13" stroke-linecap="round"/>')
        body.append(f'<circle cx="{lo_x:.1f}" cy="{y + 13:.1f}" r="7" fill="#ffffff" stroke="{color}" stroke-width="3"/>')
        body.append(f'<circle cx="{hi_x:.1f}" cy="{y + 13:.1f}" r="7" fill="#ffffff" stroke="{color}" stroke-width="3"/>')
        body.append(svg_text(hi_x + 12, y + 18, f"{lo:.1f}-{hi:.1f} KB", 13))
    write_svg(figure_dir / "stack_peak_ranges.svg", width, height, body)


def write_entropy_svg(rows: list[dict[str, str]], figure_dir: Path) -> None:
    groups = family_groups(rows)
    data = [(family, median(groups[family], "Avg_Latency_Entropy_ms")) for family in FAMILY_ORDER if groups.get(family)]
    width, height = 980, 430
    x0, x1 = 230, 900
    y0, row_h = 88, 48
    values = [v for _, v in data]
    min_v, max_v = max(min(values), 1.0), max(values)
    body = [
        svg_text(40, 38, "Post-Starvation Entropy Recovery by Family", 24, weight="700"),
        svg_text(40, 62, "Log-scaled median Avg_Latency_Entropy_ms. Watchdog markers are reference lines.", 13),
    ]
    for tick, label, color in [(1000, "1 s", "#d97706"), (5000, "5 s", "#b91c1c")]:
        if min_v <= tick <= max_v:
            x = log_x(tick, min_v, max_v, x0, x1)
            body.append(f'<line x1="{x:.1f}" y1="76" x2="{x:.1f}" y2="{height - 55}" stroke="{color}" stroke-dasharray="6 4"/>')
            body.append(svg_text(x, height - 28, label, 11, "middle"))
    for i, (family, value) in enumerate(data):
        y = y0 + i * row_h
        color = FAMILY_COLORS[family]
        x = log_x(value, min_v, max_v, x0, x1)
        label = f"{value / 1000:.1f}s" if value >= 1000 else f"{value:.0f}ms"
        body.append(svg_text(40, y + 18, family, 14, weight="700"))
        body.append(f'<rect x="{x0}" y="{y}" width="{max(2, x - x0):.1f}" height="26" rx="5" fill="{color}"/>')
        body.append(svg_text(x + 10, y + 19, label, 13))
    write_svg(figure_dir / "entropy_recovery_by_family.svg", width, height, body)


def write_quality_svg(rows: list[dict[str, str]], figure_dir: Path) -> None:
    groups = family_groups(rows)
    metrics = [
        ("CV < 0.2%", lambda r: f(r, "CoeffVar_pct") < 0.2, "#2563eb"),
        ("TAF <= 1.05", lambda r: f(r, "Tail_Amplification_Factor") <= 1.05, "#16a34a"),
        ("No 64KB fail", lambda r: f(r, "Failure_64KB_pct") == 0.0, "#d97706"),
    ]
    width, height = 1040, 470
    x0, x1 = 210, 960
    y0, row_h = 95, 52
    body = [
        svg_text(40, 38, "Validation-Oriented Quality Gates by Family", 24, weight="700"),
        svg_text(40, 62, "Percent of rows passing timing stability, stress-tail, and heap-cap checks.", 13),
    ]
    for tick in [0, 25, 50, 75, 100]:
        x = x0 + tick / 100.0 * (x1 - x0)
        body.append(f'<line x1="{x:.1f}" y1="82" x2="{x:.1f}" y2="{height - 58}" stroke="#e5e7eb"/>')
        body.append(svg_text(x, height - 30, f"{tick}%", 11, "middle"))
    for i, family in enumerate(FAMILY_ORDER):
        group = groups.get(family, [])
        if not group:
            continue
        y = y0 + i * row_h
        body.append(svg_text(40, y + 24, family, 14, weight="700"))
        for j, (name, predicate, color) in enumerate(metrics):
            rate = pct(sum(1 for r in group if predicate(r)), len(group))
            bar_y = y + j * 14
            width_px = rate / 100.0 * (x1 - x0)
            body.append(f'<rect x="{x0}" y="{bar_y}" width="{width_px:.1f}" height="10" rx="3" fill="{color}" opacity="0.88"/>')
            body.append(svg_text(x0 + width_px + 7, bar_y + 9, f"{rate:.0f}%", 10))
    legend_x = 690
    for idx, (name, _, color) in enumerate(metrics):
        x = legend_x + idx * 112
        body.append(f'<rect x="{x}" y="34" width="12" height="12" fill="{color}" rx="2"/>')
        body.append(svg_text(x + 17, 45, name, 11))
    write_svg(figure_dir / "quality_gates_by_family.svg", width, height, body)


def write_figures(rows: list[dict[str, str]], figure_dir: Path) -> None:
    write_family_cycles_svg(rows, figure_dir)
    write_stack_svg(rows, figure_dir)
    write_entropy_svg(rows, figure_dir)
    write_quality_svg(rows, figure_dir)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--summary-dir", type=Path, default=DEFAULT_SUMMARY_DIR)
    parser.add_argument("--figure-dir", type=Path, default=DEFAULT_FIGURE_DIR)
    args = parser.parse_args()

    rows = read_rows(args.csv)
    issues = validate(rows)
    summary = build_summary(rows, issues)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(summary, encoding="utf-8")
    write_derived_csvs(rows, args.summary_dir)
    (args.summary_dir / "validation_report.md").write_text(build_validation_report(rows, issues), encoding="utf-8")
    write_figures(rows, args.figure_dir)
    print(f"Wrote {args.out}")
    print(f"Wrote derived CSV summaries to {args.summary_dir}")
    print(f"Wrote SVG result figures to {args.figure_dir}")
    if issues:
        print(f"Validation issues: {len(issues)}")
        return 1
    print("Validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

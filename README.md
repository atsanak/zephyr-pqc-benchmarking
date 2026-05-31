# Zephyr PQC Benchmarking

Reproducible post-quantum cryptography benchmarking for embedded systems using Zephyr RTOS, QEMU, and PQClean reference implementations.

This repository is a cleaned public release of an embedded PQC measurement framework. It is organized for reviewers who want to inspect the source, understand the measurement methodology, reproduce a sample run, and verify the published result CSV without sorting through local build artifacts or experimental leftovers.

## Motivation

Post-quantum migration is not only a cryptographic standards problem. Embedded systems also need evidence about timing tails, memory headroom, entropy recovery, and stress behavior under RTOS-style constraints. This project measures KEM and signature operations in isolation so that deployment decisions can be made per operation rather than from a single average.

## System Architecture

The benchmark links PQClean reference C implementations into a Zephyr application and runs them on QEMU board targets. The framework separates algorithm registries, operation control, metric collection, CSV export, and offline analysis.

Architecture diagram:

`figures/architecture_diagram.png`

Detailed architecture notes:

`docs/architecture.md`

## Benchmarking Methodology

Each accepted result row represents one:

`algorithm + operation + ISA label + QEMU board`

Every accepted row uses 1000 timed iterations. The metric set includes cycle statistics, percentile tails, coefficient of variation, median absolute deviation, stack and heap-cap behavior, entropy and RNG demand, modelled energy, and cache/TLB stress response.

More detail:

`docs/methodology.md`

## Supported Algorithms

Final public results cover these 15 parameter sets:

- ML-KEM: `ml-kem-512`, `ml-kem-768`, `ml-kem-1024`
- HQC: `hqc-128`, `hqc-256`
- Classic McEliece: `mceliece348864f`
- ML-DSA: `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`
- Falcon: `falcon-512`, `falcon-1024`, `falcon-padded-512`, `falcon-padded-1024`
- SLH-DSA style SPHINCS+: `sphincs-sha2-128f-simple`, `sphincs-sha2-256f-simple`

The source tree may contain additional PQClean implementations for development, but only the rows in `results/final/validated_results.csv` are treated as public evidence.

## Supported QEMU Targets

The final dataset includes 13 QEMU targets:

- `qemu_x86_64`
- `qemu_x86`
- `qemu_riscv64`
- `qemu_riscv32`
- `qemu_riscv32e`
- `qemu_cortex_a53`
- `qemu_cortex_a9`
- `qemu_cortex_r5`
- `qemu_arc/qemu_arc_em`
- `qemu_arc/qemu_arc_hs`
- `qemu_xtensa`
- `qemu_malta`
- `qemu_leon3`

## Build Instructions

This repository does not vendor Zephyr itself. Use an existing Zephyr environment and set `ZEPHYR_BASE`.

```sh
export ZEPHYR_BASE=/path/to/zephyr
scripts/build_all.sh --quick
```

Build one selected algorithm and board:

```sh
export ZEPHYR_BASE=/path/to/zephyr
scripts/build_all.sh --algorithm ml-dsa-44 --board qemu_riscv32
```

Build the full final-result matrix:

```sh
export ZEPHYR_BASE=/path/to/zephyr
scripts/build_all.sh --full
```

The full matrix is intentionally expensive.

## Run Instructions

Run a sample benchmark:

```sh
export ZEPHYR_BASE=/path/to/zephyr
scripts/run_benchmarks.sh ml-kem-512 qemu_x86_64
```

Raw run logs are written under:

```text
PQClean/src/benchmark_outputs/
```

That directory is ignored by git.

Convert raw logs to the v2 CSV schema:

```sh
python3 PQClean/scripts/build_unified_csv_v2.py \
  --logs-dir PQClean/src/benchmark_outputs \
  --output results/raw/unified_benchmark_results.csv
```

Validate the v2 CSV schema:

```sh
python3 PQClean/scripts/validate_schema_v2.py \
  --csv results/raw/unified_benchmark_results.csv
```

## Results Summary

Trusted public result source:

`results/final/validated_results.csv`

Public dataset:

- 498 validated rows
- 66 columns
- 15 algorithm parameter sets
- 13 ISA labels
- 13 QEMU board targets
- 1000 timed iterations per accepted row
- No duplicate algorithm/operation/ISA/board keys
- No non-positive cycle rows
- No percentile-ordering failures

Headline results from the public CSV:

- 58.2% of rows have CV below 0.2%.
- 95.6% of rows have TAF at or below 1.05.
- 96.4% of rows report no allocation failure under the 64 KB heap cap.
- Median HQC/ML-KEM cycle ratio is 166.6x.
- Median HQC/ML-KEM modelled-energy ratio is 162.9x.

Generated summary:

`results/summaries/results_summary.md`

## CSV and Result Files

Only one benchmark CSV is trusted for public analysis:

`results/final/validated_results.csv`

The original project had multiple overlapping CSVs from local, server, partial, and older-schema runs. The audit found one complete internal 501-row CSV, then removed three duplicate/conflicting SPHINCS rows whose algorithm name did not match the source log provenance. The public CSV therefore contains 498 clean rows.

Audit details:

`results/summaries/result_file_audit.md`

## Reproducibility Notes

The reproducibility workflow is documented in:

`docs/reproducibility.md`

The key idea is:

1. Build one algorithm per Zephyr image.
2. Run the selected image on a QEMU board.
3. Capture raw benchmark logs.
4. Convert logs to CSV.
5. Validate and summarize the CSV.

## Limitations

- QEMU supports controlled cross-ISA comparison, not board-certified timing.
- Energy values are modelled from cycles and ISA coefficients, not measured with a physical power probe.
- Entropy behavior is measured in the Zephyr/QEMU environment and should be recalibrated on real hardware.
- Side-channel resistance and end-to-end TLS/protocol behavior are outside this repository's evidence boundary.

## License

Repository-specific benchmark harness code, scripts, and documentation are released under Apache-2.0. PQClean implementation directories retain their upstream per-implementation licenses in their local `LICENSE` files.

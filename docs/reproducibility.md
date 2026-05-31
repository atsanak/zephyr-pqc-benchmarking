# Reproducibility

## Environment

The original experiment used a Zephyr/QEMU/PQClean setup. To reproduce a sample run, install or activate a Zephyr development environment with:

- `west`
- CMake and Ninja
- Zephyr SDK
- QEMU support for the target board
- `ZEPHYR_BASE` pointing to a Zephyr checkout

This repository does not vendor the full Zephyr tree. Keeping Zephyr external avoids publishing build artifacts and unrelated upstream source.

## Sample Build

```sh
export ZEPHYR_BASE=/path/to/zephyr
scripts/build_all.sh --quick
```

This builds `ml-kem-512` for `qemu_x86_64`.

## Sample Run

```sh
export ZEPHYR_BASE=/path/to/zephyr
scripts/run_benchmarks.sh ml-kem-512 qemu_x86_64
```

The raw run log is written to:

```text
PQClean/src/benchmark_outputs/benchmark_output_ml-kem-512_qemu_x86_64.txt
```

## Convert Logs to CSV

```sh
python3 PQClean/scripts/build_unified_csv_v2.py \
  --logs-dir PQClean/src/benchmark_outputs \
  --output results/raw/unified_benchmark_results.csv
```

## Validate v2 CSV Schema

```sh
python3 PQClean/scripts/validate_schema_v2.py \
  --csv results/raw/unified_benchmark_results.csv
```

## Rebuild Public Summary

```sh
python3 scripts/analyze_results.py
```

This regenerates:

```text
results/summaries/results_summary.md
```


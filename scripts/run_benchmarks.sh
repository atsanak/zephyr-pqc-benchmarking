#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="${BUILD_ROOT:-$ROOT/build}"
OUTPUT_DIR="$ROOT/PQClean/src/benchmark_outputs"
ALGORITHM="${1:-ml-kem-512}"
BOARD="${2:-qemu_x86_64}"

usage() {
  cat <<'USAGE'
Usage:
  scripts/run_benchmarks.sh [algorithm] [board]

Example:
  scripts/run_benchmarks.sh ml-kem-512 qemu_x86_64
  scripts/run_benchmarks.sh ml-dsa-44 qemu_riscv32

The script builds one Zephyr/QEMU target and runs it through west.
Raw stdout is stored under PQClean/src/benchmark_outputs/, which is
ignored by git. Use PQClean/scripts/build_unified_csv_v2.py to turn a
set of raw logs into a unified CSV.
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

cmake_flag_for_algorithm() {
  case "$1" in
    ml-kem-512) echo "-DENABLE_ML_KEM_512=ON" ;;
    ml-kem-768) echo "-DENABLE_ML_KEM_768=ON" ;;
    ml-kem-1024) echo "-DENABLE_ML_KEM_1024=ON" ;;
    hqc-128) echo "-DENABLE_HQC_128=ON" ;;
    hqc-192) echo "-DENABLE_HQC_192=ON" ;;
    hqc-256) echo "-DENABLE_HQC_256=ON" ;;
    mceliece348864f) echo "-DENABLE_MCELIECE_348864F=ON" ;;
    ml-dsa-44) echo "-DENABLE_ML_DSA_44=ON" ;;
    ml-dsa-65) echo "-DENABLE_ML_DSA_65=ON" ;;
    ml-dsa-87) echo "-DENABLE_ML_DSA_87=ON" ;;
    falcon-512) echo "-DENABLE_FALCON_512=ON" ;;
    falcon-1024) echo "-DENABLE_FALCON_1024=ON" ;;
    falcon-padded-512) echo "-DENABLE_FALCON_PADDED_512=ON" ;;
    falcon-padded-1024) echo "-DENABLE_FALCON_PADDED_1024=ON" ;;
    sphincs-sha2-128f-simple) echo "-DENABLE_SPHINCS_SHA2_128F=ON" ;;
    sphincs-sha2-256f-simple) echo "-DENABLE_SPHINCS_SHA2_256F=ON" ;;
    *) echo "Unsupported algorithm: $1" >&2; return 2 ;;
  esac
}

safe_name() {
  echo "$1" | tr '/ ' '__'
}

command -v west >/dev/null 2>&1 || {
  echo "west is not on PATH. Activate a Zephyr environment first." >&2
  exit 127
}

if [[ -z "${ZEPHYR_BASE:-}" ]]; then
  echo "ZEPHYR_BASE is not set. Point it to a Zephyr checkout before building." >&2
  exit 2
fi

FLAG="$(cmake_flag_for_algorithm "$ALGORITHM")"
SAFE_BOARD="$(safe_name "$BOARD")"
BUILD_DIR="$BUILD_ROOT/${ALGORITHM}_${SAFE_BOARD}"
LOG_FILE="$OUTPUT_DIR/benchmark_output_${ALGORITHM}_${SAFE_BOARD}.txt"

mkdir -p "$OUTPUT_DIR"

echo "[run] algorithm=$ALGORITHM board=$BOARD"
west build -p auto -b "$BOARD" -d "$BUILD_DIR" "$ROOT/PQClean/src" -- "$FLAG"
west build -t run -d "$BUILD_DIR" 2>&1 | tee "$LOG_FILE"

echo "[run] raw log: $LOG_FILE"


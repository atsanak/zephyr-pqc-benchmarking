#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="$ROOT/PQClean/src"
BUILD_ROOT="${BUILD_ROOT:-$ROOT/build}"

ALGORITHMS=(
  ml-kem-512 ml-kem-768 ml-kem-1024
  hqc-128 hqc-256 mceliece348864f
  ml-dsa-44 ml-dsa-65 ml-dsa-87
  falcon-512 falcon-1024 falcon-padded-512 falcon-padded-1024
  sphincs-sha2-128f-simple sphincs-sha2-256f-simple
)

BOARDS=(
  qemu_x86_64 qemu_x86 qemu_riscv64 qemu_riscv32 qemu_riscv32e
  qemu_cortex_a53 qemu_cortex_a9 qemu_cortex_r5
  qemu_arc/qemu_arc_em qemu_arc/qemu_arc_hs
  qemu_xtensa qemu_malta qemu_leon3
)

usage() {
  cat <<'USAGE'
Usage:
  scripts/build_all.sh --quick
  scripts/build_all.sh --algorithm ml-kem-512 --board qemu_x86_64
  scripts/build_all.sh --full

Defaults:
  --quick builds ml-kem-512 on qemu_x86_64 only.
  --full builds every final-result algorithm on every supported QEMU board.

Required environment:
  west must be on PATH and ZEPHYR_BASE must point to a Zephyr checkout.
USAGE
}

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

build_one() {
  local algorithm="$1"
  local board="$2"
  local flag
  flag="$(cmake_flag_for_algorithm "$algorithm")"
  local build_dir="$BUILD_ROOT/${algorithm}_$(safe_name "$board")"

  echo "[build] algorithm=$algorithm board=$board build_dir=$build_dir"
  west build -p auto -b "$board" -d "$build_dir" "$APP_DIR" -- "$flag"
}

MODE="quick"
SELECT_ALGORITHM=""
SELECT_BOARD=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --quick) MODE="quick"; shift ;;
    --full) MODE="full"; shift ;;
    --algorithm) SELECT_ALGORITHM="${2:?missing algorithm}"; MODE="single"; shift 2 ;;
    --board) SELECT_BOARD="${2:?missing board}"; MODE="single"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

command -v west >/dev/null 2>&1 || {
  echo "west is not on PATH. Activate a Zephyr environment first." >&2
  exit 127
}

if [[ -z "${ZEPHYR_BASE:-}" ]]; then
  echo "ZEPHYR_BASE is not set. Point it to a Zephyr checkout before building." >&2
  exit 2
fi

case "$MODE" in
  quick)
    build_one "ml-kem-512" "qemu_x86_64"
    ;;
  single)
    build_one "${SELECT_ALGORITHM:-ml-kem-512}" "${SELECT_BOARD:-qemu_x86_64}"
    ;;
  full)
    for algorithm in "${ALGORITHMS[@]}"; do
      for board in "${BOARDS[@]}"; do
        build_one "$algorithm" "$board"
      done
    done
    ;;
esac


#!/usr/bin/env bash
set -euo pipefail

# Run a reproducible benchmark matrix by delegating each cell to run_benchmarks.sh.
# The default matrix is intentionally small; use --final-matrix for the public
# result-set algorithms and boards.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="${ROOT_DIR}/scripts/run_benchmarks.sh"

DEFAULT_ALGORITHMS=("ml-kem-512")
DEFAULT_BOARDS=("qemu_x86_64")

FINAL_ALGORITHMS=(
  "ml-kem-512" "ml-kem-768" "ml-kem-1024"
  "hqc-128" "hqc-256" "mceliece348864f"
  "ml-dsa-44" "ml-dsa-65" "ml-dsa-87"
  "falcon-512" "falcon-1024" "falcon-padded-512" "falcon-padded-1024"
  "sphincs-sha2-128f-simple" "sphincs-sha2-256f-simple"
)

FINAL_BOARDS=(
  "qemu_x86_64" "qemu_x86"
  "qemu_riscv64" "qemu_riscv32" "qemu_riscv32e"
  "qemu_cortex_a53" "qemu_cortex_a9" "qemu_cortex_r5"
  "qemu_arc/qemu_arc_em" "qemu_arc/qemu_arc_hs"
  "qemu_xtensa" "qemu_malta" "qemu_leon3"
)

ALGORITHMS=("${DEFAULT_ALGORITHMS[@]}")
BOARDS=("${DEFAULT_BOARDS[@]}")
DRY_RUN=false

usage() {
  cat <<'USAGE'
Usage:
  scripts/verify_matrix.sh [options]

Options:
  --final-matrix              Run the public-result algorithm and board matrix.
  --algorithm <name>          Run one algorithm. May be repeated.
  --board <name>              Run one board. May be repeated.
  --dry-run                   Print planned runs without executing them.
  -h, --help                  Show this help text.

Examples:
  scripts/verify_matrix.sh --dry-run
  scripts/verify_matrix.sh --algorithm ml-kem-512 --board qemu_x86_64
  scripts/verify_matrix.sh --final-matrix --dry-run
USAGE
}

clear_custom_if_default() {
  local kind="$1"
  if [[ "${kind}" == "algorithm" && "${ALGORITHMS[*]}" == "${DEFAULT_ALGORITHMS[*]}" ]]; then
    ALGORITHMS=()
  fi
  if [[ "${kind}" == "board" && "${BOARDS[*]}" == "${DEFAULT_BOARDS[*]}" ]]; then
    BOARDS=()
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --final-matrix)
      ALGORITHMS=("${FINAL_ALGORITHMS[@]}")
      BOARDS=("${FINAL_BOARDS[@]}")
      shift
      ;;
    --algorithm)
      [[ $# -ge 2 ]] || { echo "--algorithm requires a value" >&2; exit 2; }
      clear_custom_if_default "algorithm"
      ALGORITHMS+=("$2")
      shift 2
      ;;
    --board)
      [[ $# -ge 2 ]] || { echo "--board requires a value" >&2; exit 2; }
      clear_custom_if_default "board"
      BOARDS+=("$2")
      shift 2
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

echo "Algorithms: ${ALGORITHMS[*]}"
echo "Boards: ${BOARDS[*]}"
echo "Cells: $((${#ALGORITHMS[@]} * ${#BOARDS[@]}))"

for algorithm in "${ALGORITHMS[@]}"; do
  for board in "${BOARDS[@]}"; do
    if [[ "${DRY_RUN}" == "true" ]]; then
      printf 'DRY-RUN: %q %q %q\n' "${RUNNER}" "${algorithm}" "${board}"
    else
      "${RUNNER}" "${algorithm}" "${board}"
    fi
  done
done

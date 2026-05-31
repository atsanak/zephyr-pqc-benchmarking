# Architecture

The benchmark is a Zephyr application that links one selected PQClean reference implementation into a QEMU-targeted firmware image. The goal is operation-level evidence, not a protocol stack.

## Main Components

- `PQClean/src`: Zephyr application entry point, registries, benchmark orchestration, TEE abstraction hooks, and board configuration overlays.
- `PQClean/crypto_kem`: PQClean KEM implementations used by the registry.
- `PQClean/crypto_sign`: PQClean signature implementations used by the registry.
- `PQClean/common`: shared hash, AES, and random-byte support code.
- `PQClean/harness`: dynamic iteration, timing, and budget helpers.
- `PQClean/metrics`: cycle, energy, jitter, entropy, memory, stress, and RTOS-related metric collectors.
- `PQClean/scripts`: log-to-CSV extraction and schema validation helpers.
- `results/final`: trusted public CSV data.
- `scripts`: public-facing build, run, and result-analysis wrappers.

## Data Flow

1. CMake enables one algorithm parameter set.
2. Zephyr builds the application for a selected QEMU board.
3. The app runs KeyGen, Encaps/Sign, or Decaps/Verify in isolated measurement windows.
4. Metric modules collect timing, memory, entropy, modelled energy, and stress fields.
5. Raw QEMU logs are converted into a unified CSV schema.
6. Analysis scripts validate and summarize the final CSV.

The architecture diagram is available at `figures/architecture_diagram.png`, with the editable SVG retained beside it.

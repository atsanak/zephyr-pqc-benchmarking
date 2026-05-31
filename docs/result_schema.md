# Result Schema

The trusted public result source is `results/final/validated_results.csv`.
Each row represents one algorithm, one operation, one ISA label, and one QEMU
board target. The CSV has 66 columns grouped as follows.

## Identity

- `Algorithm_Type`: `KEM` or `DSA`.
- `Algorithm`: exact parameter-set name.
- `Variant`: implementation variant, normally `clean`.
- `FIPS_Standard`: standards or candidate-family context.
- `PK_Bytes`, `SK_Bytes`, `CT_or_Sig_Bytes`, `SS_Bytes`: algorithm size metadata.
- `Operation`: `keypair`, `encaps`, `decaps`, `sign`, or `verify`.
- `ISA`, `Board`: architecture label and Zephyr/QEMU board target.
- `Iterations`: timed sample count. The public CSV uses 1000 for every row.

## Timing

- `Avg_Cycles`, `Min_Cycles`, `Max_Cycles`: core timing distribution fields.
- `StdDev_Cycles`, `Jitter_Cycles`, `CoeffVar_pct`, `MAD_Cycles`: dispersion metrics.
- `p50_Cycles`, `p95_Cycles`, `p99_Cycles`: tail-latency fields used for scheduling interpretation.

## Energy

- `Energy_uJ`: modelled microjoule estimate derived from cycles and ISA coefficients.
- `StdDev_Energy_uJ`: propagated from timing variation.

Energy is not board-measured power. Treat it as a relative comparison inside the
dataset.

## Entropy and RNG

- `Entropy_Success_pct`: success rate after entropy-starvation trials.
- `Avg_Latency_Entropy_ms`: recovery latency after depletion.
- `RNG_Bytes_Consumed`, `RNG_Call_Count`, `RNG_Failures`: operation-level RNG demand.
- `RNG_Shannon_Entropy`, `RNG_Min_Entropy_H_inf`, `RNG_Bytes_Per_Call`: byte-distribution diagnostics.

## Memory

- `Cycles_At_128KB_RAM_Cap`, `Failure_128KB_pct`: 128 KB heap-cap probe.
- `Cycles_At_64KB_RAM_Cap`, `Failure_64KB_pct`: 64 KB heap-cap probe.
- `Stack_Used_Bytes`, `Stack_Peak_Bytes`, `Stack_Available_Bytes`: thread-stack headroom evidence.

## Stress

- `Cycles_Throttled_50pct`, `Latency_Throttled_50pct_ms`: analytic throttling fields.
- `Throttle_Slowdown_pct`: slowdown under the populated stress profile.
- `Cycles_Cache_TLB_Stress`: populated cache/TLB stress cycle field.
- `Tail_Amplification_Factor`: stressed-to-baseline tail-shape ratio.
- `p50_Stress_Cycles`, `p99_Stress_Cycles`, `Jitter_Stress_Cycles`: stressed distribution fields.
- `Min_Stress_Cycles`, `Max_Stress_Cycles`: stressed bounds.

The submitted public dataset uses cache/TLB stress as the empirical stress
profile.

## TEE Placeholders

Fields from `TEE_Mode` through `TEE_RNG_Bytes` are retained for integration
work, but they are not used as thesis or public benchmark evidence in this CSV.

## Provenance

- `Source_File`: raw benchmark log associated with the row.
- `Extraction_Timestamp`: timestamp recorded during CSV extraction.

Validation requires positive cycles, ordered percentiles, unique
algorithm/operation/ISA/board keys, and source-file provenance that matches the
algorithm name.

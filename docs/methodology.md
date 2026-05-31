# Methodology

The benchmark measures individual post-quantum cryptographic operations under Zephyr/QEMU using PQClean reference C implementations.

## Measurement Unit

Each accepted CSV row represents:

`algorithm parameter set + operation + ISA label + QEMU board`

KEM operations are:

- `keypair`
- `encaps`
- `decaps`

Signature operations are:

- `keypair`
- `sign`
- `verify`

## Metrics

The CSV records:

- Cycle statistics: mean, min, max, standard deviation, jitter, CV, p50, p95, p99, MAD.
- Memory: stack peak, stack availability, heap-cap behavior at 64 KB and 128 KB.
- Entropy: RNG bytes, RNG calls, entropy recovery latency, Shannon entropy, min-entropy.
- Modelled energy: microjoule estimates derived from cycle counts and ISA coefficients.
- Stress response: cache/TLB stress cycles, stressed p50/p99, jitter, and tail amplification factor.
- Provenance: source log file and extraction timestamp.

## Validation

The public dataset keeps only rows that pass these checks:

- Positive cycle counts.
- Ordered percentiles: `min <= p50 <= p95 <= p99 <= max`.
- No duplicate algorithm/operation/ISA/board keys.
- Algorithm name matches source-file provenance.
- 1000 timed iterations per accepted row.

Rows that are incomplete, duplicate, malformed, or source-mismatched are excluded from `results/final/validated_results.csv`.

## Limits

QEMU gives controlled cross-ISA comparison, but it is not physical silicon. Energy is modelled, not measured by a power probe. Entropy behavior uses the Zephyr/QEMU environment and should be recalibrated on real hardware.


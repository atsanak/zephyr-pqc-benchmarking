# Results Summary

This summary is generated from `results/final/validated_results.csv`.

## Dataset

- Rows: 498
- Algorithms: 15
- ISA labels: 13
- QEMU boards: 13
- Operations: decaps, encaps, keypair, sign, verify
- Timed iterations per accepted row: 1000

## Validation Checks

- No duplicate operation keys.
- No non-positive cycle rows.
- Percentile ordering passed for every row.
- Algorithm names match source-file provenance for every row.

## Headline Metrics

- Rows with CV < 0.2%: 290/498 (58.2%)
- Rows with TAF <= 1.05: 476/498 (95.6%)
- Rows with no 64 KB heap-cap failure: 480/498 (96.4%)

## Family Summary

| Family | Rows | Algorithms | Median cycles | Median CV (%) | Stack range (KB) |
| --- | ---: | --- | ---: | ---: | ---: |
| ML-KEM | 117 | ml-kem-1024, ml-kem-512, ml-kem-768 | 1,177,230 | 0.063 | 15.9-30.7 |
| HQC | 75 | hqc-128, hqc-256 | 196,109,137 | 0.000 | 54.6-181.1 |
| ML-DSA | 99 | ml-dsa-44, ml-dsa-65, ml-dsa-87 | 5,715,836 | 0.683 | 52.2-130.3 |
| Falcon | 147 | falcon-1024, falcon-512, falcon-padded-1024, falcon-padded-512 | 65,880,657 | 0.221 | 43.6-93.9 |
| SLH-DSA / SPHINCS+ | 42 | sphincs-sha2-128f-simple, sphincs-sha2-256f-simple | 38,151,388 | 0.002 | 12.4-18.4 |
| Classic McEliece | 18 | mceliece348864f | 203,775,328 | 0.036 | 424.5-425.0 |

## KEM Comparison

- Median HQC/ML-KEM cycle ratio: 166.6x
- Median HQC/ML-KEM modelled-energy ratio: 162.9x

## Notes

- Energy is modelled from cycle counts and ISA coefficients; it is not board-measured power.
- QEMU results support controlled cross-ISA comparison, not physical-board timing certification.
- `results/summaries/result_file_audit.md` explains which CSV files were included or excluded.
- `figures/results/` contains generated SVG figures from the same trusted CSV.

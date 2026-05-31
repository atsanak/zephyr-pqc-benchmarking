# Result File Audit

This repository intentionally does not publish every CSV found in the working project. The source tree contained several overlapping, partial, older-schema, or malformed result files from local and server experiments. The public repository keeps only the final explainable dataset and the minimal audit trail needed to understand it.

## Included

| Public file | Source | Decision |
| --- | --- | --- |
| `results/final/validated_results.csv` | Derived from `Papers/ACM_TACO/analysis_outputs/clean_benchmark_data.csv` | Included as the trusted public dataset after removing three duplicate/conflicting rows whose algorithm name did not match the source-file provenance. |
| `results/summaries/excluded_duplicate_rows.csv` | Same source as above | Included only as audit evidence for the three removed rows. These rows are not benchmark evidence. |
| `results/summaries/results_summary.md` | Generated from `results/final/validated_results.csv` | Included to give reviewers a quick, reproducible summary. |

## Excluded Source CSVs

| Original file | Rows | Columns | Audit decision |
| --- | ---: | ---: | --- |
| `Papers/ACM_TACO/analysis_outputs/clean_benchmark_data.csv` | 501 | 66 | Complete internal analysis CSV, but three rows duplicated `sphincs-sha2-128f-simple` on `qemu_x86_64` while pointing to `sphincs-sha2-192f-simple` source logs. Used only as the input for the cleaned public CSV. |
| `PQClean/unified_benchmark_results.pre_v2_backup.csv` | 501 | 66 | Pre-clean backup with the same row identities as the internal 501-row file. Excluded to avoid duplicate datasets. |
| `PQClean/unified_benchmark_results.csv` | 186 | 154 | Partial v2-schema experiment covering 11 algorithms and 10 ISA labels. Excluded because it is incomplete relative to the final dataset. |
| `server_results/unified_benchmark_results.csv` | 165 | 154 | Server-side partial DSA-focused v2-schema run covering 9 algorithms and 9 ISA labels. Excluded because it overlaps with, but does not replace, the final dataset. |
| `scripts/all_new.csv` | 166 | 44 | Older KEM-only schema and partial target coverage. Excluded as outdated. |
| `PQClean/hqc256andmcellice.csv` | 39 | 154 | Malformed/shifted CSV: fields such as `Algorithm`, `Operation`, and `ISA` contain numeric values. Excluded as invalid. |

## Public Dataset Validation

- Rows: 498
- Columns: 66
- Algorithms: 15
- ISA labels: 13
- QEMU boards: 13
- Timed iterations per accepted row: 1000
- Duplicate algorithm/operation/ISA/board keys: 0
- Rows with non-positive cycle counts: 0
- Rows failing percentile ordering: 0
- Rows with algorithm/source-file provenance mismatch: 0

## Interpretation Boundary

The public CSV is the trusted source for repository summaries. It supports comparative Zephyr/QEMU/PQClean benchmarking and deployment-oriented analysis. It does not claim board-calibrated power, physical TRNG certification, side-channel resistance, or end-to-end protocol timing.


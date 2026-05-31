# Results

The trusted public result source is:

`results/final/validated_results.csv`

This file contains 498 validated operation-level rows after the public audit removed three duplicate/conflicting SPHINCS rows from the internal 501-row analysis CSV. Each row represents one algorithm, operation, ISA, and QEMU board target.

The result summaries are:

- `results/summaries/results_summary.md`: generated metrics summary.
- `results/summaries/result_file_audit.md`: CSV/result provenance and inclusion decisions.
- `results/summaries/excluded_duplicate_rows.csv`: the three removed duplicate/conflicting rows, kept only for transparency.

Do not treat the excluded rows as benchmark evidence.


# ActionHound benchmark results

Reproduce with `python -m pip install '.[test]'` and `python benchmarks/run_bench.py`.

| Metric | Observed |
| --- | ---: |
| Labeled fixtures | 64 |
| GitHub Actions fixtures | 48 |
| GitLab CI fixtures | 16 |
| Workflow files across fixtures | 68 |
| Non-compliant fixtures | 32 |
| Hardened fixtures | 32 |
| True positives | 35 |
| False positives | 0 |
| False negatives | 0 |
| Precision | 100.00% |
| Recall | 100.00% |
| Findings on hardened fixtures | 0 |
| Median ms per workflow | 0.809 |
| Reports valid against SARIF 2.1.0 schema | 64/64 |

The paired synthetic fixtures are labeled by file and rule ID with expected
finding counts. The reported precision and recall describe this corpus alone.

Timing is the median of 960 warm wall-clock scans over 15
rounds per fixture. Each scan time is divided by its number of workflow files.
Composite actions are traversed during scanning. Fixture creation, rendering
and SARIF schema validation are outside the timed interval.

Measured with CPython 3.12.14, PyYAML 6.0.4
and jsonschema 4.25.1 on Linux x86_64.

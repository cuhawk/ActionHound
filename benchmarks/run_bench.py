#!/usr/bin/env python3
"""Measure scanner accuracy and wall-clock latency on the labeled corpus."""

import argparse
import json
import platform
from collections import Counter
from importlib.metadata import version
from pathlib import Path
from statistics import median
from tempfile import TemporaryDirectory
from time import perf_counter_ns

from jsonschema.validators import validator_for

from actionhound.sarif import to_sarif
from actionhound.scanner import scan
if __package__:
    from .corpus import FIXTURES, GITLAB, PROTECTED
else:
    from corpus import FIXTURES, GITLAB, PROTECTED

SCHEMA = Path(__file__).resolve().parents[1] / "tests/schema/sarif-2.1.0.json"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=15, help="Timed scans per fixture")
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("--rounds must be positive")

    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validator_class = validator_for(schema)
    validator_class.check_schema(schema)
    validator = validator_class(schema)
    true_positives = false_positives = false_negatives = clean_false_positives = 0
    clean_fixtures = valid_reports = github = gitlab = workflows = 0
    timings = []
    mismatches = []
    with TemporaryDirectory(prefix="actionhound-bench-") as directory:
        for fixture in FIXTURES:
            root = Path(directory) / fixture.name
            fixture.write(root)
            workflow_count = sum(path == GITLAB or path.startswith(".github/workflows/")
                                 for path in fixture.files)
            workflows += workflow_count
            gitlab += GITLAB in fixture.files
            github += GITLAB not in fixture.files
            findings = scan(root, protected_environments=PROTECTED)
            validator.validate(to_sarif(findings))
            valid_reports += 1
            expected = Counter(fixture.expected)
            detected = Counter((f.path, f.rule_id) for f in findings)
            true_positives += sum((detected & expected).values())
            false_positives += sum((detected - expected).values())
            false_negatives += sum((expected - detected).values())
            if not expected:
                clean_fixtures += 1
                clean_false_positives += sum(detected.values())
            if expected != detected:
                mismatches.append(f"- `{fixture.name}` expected {dict(expected)}, found {dict(detected)}")
            for _ in range(args.rounds):
                start = perf_counter_ns()
                scan(root, protected_environments=PROTECTED)
                timings.append((perf_counter_ns() - start) / (1_000_000 * workflow_count))

    precision = true_positives / (true_positives + false_positives)
    recall = true_positives / (true_positives + false_negatives)
    print(f"""# ActionHound benchmark results

Reproduce with `python -m pip install '.[test]'` and `python benchmarks/run_bench.py`.

| Metric | Observed |
| --- | ---: |
| Labeled fixtures | {len(FIXTURES)} |
| GitHub Actions fixtures | {github} |
| GitLab CI fixtures | {gitlab} |
| Workflow files across fixtures | {workflows} |
| Non-compliant fixtures | {len(FIXTURES) - clean_fixtures} |
| Hardened fixtures | {clean_fixtures} |
| True positives | {true_positives} |
| False positives | {false_positives} |
| False negatives | {false_negatives} |
| Precision | {precision:.2%} |
| Recall | {recall:.2%} |
| Findings on hardened fixtures | {clean_false_positives} |
| Median ms per workflow | {median(timings):.3f} |
| Reports valid against SARIF 2.1.0 schema | {valid_reports}/{len(FIXTURES)} |

The paired synthetic fixtures are labeled by file and rule ID with expected
finding counts. The reported precision and recall describe this corpus alone.

Timing is the median of {len(timings)} warm wall-clock scans over {args.rounds}
rounds per fixture. Each scan time is divided by its number of workflow files.
Composite actions are traversed during scanning. Fixture creation, rendering
and SARIF schema validation are outside the timed interval.

Measured with CPython {platform.python_version()}, PyYAML {version("PyYAML")}
and jsonschema {version("jsonschema")} on {platform.system()} {platform.machine()}.""")
    if mismatches:
        print("\n## Label mismatches\n\n" + "\n".join(mismatches))
    return int(bool(mismatches))


if __name__ == "__main__":
    raise SystemExit(main())

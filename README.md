# ActionHound

ActionHound scans GitHub Actions and GitLab CI configurations for trust-boundary
and software supply-chain risks. It writes Markdown and SARIF reports and
includes Semgrep and CodeQL rule packs for application security.

## Install and scan

```sh
python -m pip install .
actionhound scan /path/to/repository --sarif actionhound.sarif --markdown actionhound.md --fail-on high
```

The CLI prints a Markdown summary. It returns 0 on a successful scan, 1 when
a finding meets the optional `--fail-on` threshold, and 2 for an input or
output error. The severity order is low, medium, high, critical.

Pass `--trust-policy PATH` for each AWS IAM trust policy JSON file inside the
scan root to check GitHub OIDC subject restrictions. Pass
`--protected-environment NAME` for each GitHub environment whose deployment
protections you have verified. A job-level `id-token: write` grant can be
scoped to one of those environments using a literal environment name.

### Local call graph

The scanner follows job calls to `./.github/workflows/*.yml` or `*.yaml` and
step calls to composite actions under `./.github/actions/`. It follows local
`with` inputs into nested calls and carries the caller event and effective
permission ceiling into each callee. Findings point to the file and line
where the risk occurs. SARIF includes a deterministic
`primaryLocationLineHash/v1` based on the reported source line.

The scanner reads local files and uses recognizable expressions and command
patterns. Remote call resolution, step-output dataflow, shell execution, and
verification of protection settings or cloud policy are outside its analysis.

### Supply-chain rules

| ID | Finding |
| --- | --- |
| AH010 | Job container image lacks a SHA-256 digest |
| AH011 | A `workflow_run` job with write permissions or referenced secrets downloads artifacts |
| AH012 | Untrusted data is written to `GITHUB_ENV` or `GITHUB_PATH` |
| AH013 | Checkout step lacks `persist-credentials: false` |
| AH014 | A third-party action step uses a mutable reference |
| AH015 | `id-token: write` is granted outside a verified, job-level environment scope |

AH003 covers mutable GitHub-maintained actions, external reusable workflows,
and Docker action images. AH007 continues to cover other cross-workflow
artifact downloads. AH015 supersedes AH009. The previous GitLab include,
merge request shell re-evaluation, and shared cache checks are now AH016,
AH017, and AH018. The secrets-after-untrusted-checkout check is now AH019.

### Offline YAML patches

```sh
actionhound scan . --emit-diff actionhound.patch --pin-map pins.json
git apply --check actionhound.patch
```

Use a JSON object in `pins.json`. Each key is the exact mutable reference as it
appears in YAML, such as `actions/checkout@v4` or `registry.example/base:stable`.
Use a verified full commit SHA for action and reusable workflow refs, or a
`sha256:` digest for container images and `docker://` refs. Missing entries
leave the reference in place.

The patch narrows `write-all` to `contents: read` and sets flagged explicit
`id-token: write` grants to `none`. Review the patch against the permissions
your jobs need before applying it. Patches skip shared YAML anchors and
symlinked files. Scanning and patch generation work offline.

## Application rules

Run Semgrep Community Edition with `semgrep scan --config rules/semgrep /path/to/source`.
The packs cover common FastAPI and Express idioms. Review findings against
application-specific authorization, redirect allowlists, and state stores.
See the [CodeQL guide](rules/codeql/README.md).

## Development and benchmark

```sh
python -m pip install '.[test]'
python -m pytest
python benchmarks/run_bench.py
semgrep --metrics=off --test rules/semgrep
```

The YAML files under `examples/vulnerable_workflows/` are static fixtures.

On the [labeled benchmark corpus](benchmarks/RESULTS.md), ActionHound measured
100% precision and recall across 64 synthetic fixtures, with 0 findings on
the 32 hardened fixtures and a median scan time of 0.809 ms per workflow.
All 64 reports validated against the SARIF 2.1.0 schema.

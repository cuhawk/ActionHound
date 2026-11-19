# Codex Cloud Implementation Specification: ActionHound
Build a complete Python 3.12+ Supply Chain & CI/CD Security tool (`src/actionhound/`) + Semgrep/CodeQL rules:
- `src/actionhound/scanner.py`: YAML + shell-expression AST/regex analyzer for `.github/workflows/*.yml` and `.gitlab-ci.yml` covering: `pull_request_target` + unsafe checkout, `${{ github.event.* }}` expression injection in `run:`, mutable tag action pinning (suggesting exact SHA pinning), `permissions: write-all`, secret exfiltration to untrusted steps, and cache poisoning.
- `src/actionhound/sarif.py`: Standards-compliant SARIF 2.1.0 serializer + Markdown findings summary.
- `src/actionhound/cli.py`: CLI (`actionhound scan <dir> --sarif out.sarif --fail-on high`).
- `rules/semgrep/`: Valid Semgrep YAML rules for Python/FastAPI & Node/Express covering OAuth2 `redirect_uri` open redirects, missing CSRF `state`, JWT `alg=none`/weak validation, multi-tenant IDOR/BOLA, and SSRF.
- `rules/codeql/`: Documented CodeQL `.ql` starter queries for JS/TS tainted `postMessage` & Python SSRF sinks.
- `tests/` & `examples/vulnerable_workflows/`: 25+ `pytest` tests verifying rule precision (true positives + false-positive regression tests) and valid SARIF schema output.
- `.github/workflows/ci.yml`: Automated pytest CI workflow.

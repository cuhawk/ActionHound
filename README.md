# ActionHound

**Software Supply Chain & CI/CD Exploit Graph Scanner + Production OAuth/BOLA Rule Packs.**

## Core Capabilities
1. **GitHub Actions & GitLab CI Taint & Trust Scanner:** Detects `pull_request_target` checkout RCEs ("pwn requests"), untrusted `${{ github.event.* }}` script injections, unpinned third-party action tags, cache/artifact poisoning paths, and overly broad `id-token: write` / `permissions: write-all` configurations.
2. **SARIF 2.1.0 & SLSA Gate Output:** Drops directly into GitHub Code Scanning / CI security gates.
3. **Production AppSec Rule Packs (`rules/`):** Battle-tested **Semgrep** YAML & **CodeQL** query packs targeting OAuth 2.0/OIDC `redirect_uri`/state bypasses, multi-tenant IDOR/BOLA missing-tenant filters, and SSRF patterns.

## Install and scan

```sh
python -m pip install .
actionhound scan /path/to/repository --sarif actionhound.sarif --markdown actionhound.md --fail-on high
```

The CLI prints a Markdown summary and returns 0 on success, 1 when a finding
meets the requested severity threshold, and 2 for an input or output error.
The severity order is low, medium, high, critical. Exit codes change only when
you set `--fail-on` or an error occurs.

Pass `--trust-policy PATH` for each AWS IAM trust policy JSON file inside the
scan root to check GitHub OIDC subject restrictions.

The scanner reads local GitHub Actions and GitLab CI YAML. It checks direct
workflow expressions, action references, checkout and artifact inputs,
permissions, caches, remote GitLab includes, and explicit OIDC subject patterns
in the parsed files. Its rules flag constructs for review. The scanner does
not evaluate shell scripts, resolve remote templates, or query cloud-side IAM
policies.

## Application rules

Run Semgrep Community Edition with `semgrep scan --config rules/semgrep /path/to/source`.
The packs cover common FastAPI/Express and library idioms. Review findings
against application-specific authorization, redirect allowlists, and state
stores. See [CodeQL usage](rules/codeql/README.md) for the query packs.

## Development

```sh
python -m pip install '.[test]'
python -m pytest
```

The YAML files under `examples/vulnerable_workflows/` are static fixtures.

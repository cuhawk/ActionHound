# ActionHound

**Software Supply Chain & CI/CD Exploit Graph Scanner + Production OAuth/BOLA Rule Packs.**

## Core Capabilities
1. **GitHub Actions & GitLab CI Taint & Trust Scanner:** Detects `pull_request_target` checkout RCEs ("pwn requests"), untrusted `${{ github.event.* }}` script injections, unpinned third-party action tags, cache/artifact poisoning paths, and overly broad `id-token: write` / `permissions: write-all` configurations.
2. **SARIF 2.1.0 & SLSA Gate Output:** Drops directly into GitHub Code Scanning / CI security gates.
3. **Production AppSec Rule Packs (`rules/`):** Battle-tested **Semgrep** YAML & **CodeQL** query packs targeting OAuth 2.0/OIDC `redirect_uri`/state bypasses, multi-tenant IDOR/BOLA missing-tenant filters, and SSRF patterns.

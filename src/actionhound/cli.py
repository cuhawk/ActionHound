"""Command line interface for ActionHound."""

import argparse
import json
import sys
from pathlib import Path

from .remediation import emit_diff, load_pin_map
from .sarif import to_markdown, to_sarif
from .scanner import ScanError, scan

SEVERITIES = ("low", "medium", "high", "critical")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="actionhound")
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser("scan", help="Scan a CI/CD repository")
    scan_parser.add_argument("directory", type=Path)
    scan_parser.add_argument("--sarif", type=Path, help="Write a SARIF 2.1.0 report")
    scan_parser.add_argument("--markdown", type=Path, help="Write a Markdown report")
    scan_parser.add_argument("--trust-policy", type=Path, action="append", default=[],
                             help="Scan an AWS IAM trust policy JSON file inside the repository")
    scan_parser.add_argument("--emit-diff", type=Path, help="Write a unified YAML patch")
    scan_parser.add_argument("--pin-map", type=Path, help="JSON map of mutable refs to immutable pins")
    scan_parser.add_argument("--protected-environment", action="append", default=[],
                             help="Name of a GitHub environment verified to have protection rules")
    scan_parser.add_argument("--fail-on", choices=SEVERITIES)
    args = parser.parse_args(argv)

    try:
        findings = scan(args.directory, args.trust_policy,
                        protected_environments=args.protected_environment)
        if args.emit_diff:
            patch = emit_diff(args.directory, findings, load_pin_map(args.pin_map))
            args.emit_diff.write_text(patch, encoding="utf-8", newline="")
        summary = to_markdown(findings)
        if args.sarif:
            args.sarif.write_text(json.dumps(to_sarif(findings), indent=2) + "\n", encoding="utf-8")
        if args.markdown:
            args.markdown.write_text(summary, encoding="utf-8")
        print(summary, end="")
    except (ScanError, OSError) as exc:
        print(f"actionhound: {exc}", file=sys.stderr)
        return 2

    return int(bool(args.fail_on) and any(
        SEVERITIES.index(finding.rule.severity) >= SEVERITIES.index(args.fail_on)
        for finding in findings
    ))

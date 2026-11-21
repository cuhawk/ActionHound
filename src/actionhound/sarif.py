"""Build SARIF 2.1.0 and Markdown reports."""

from collections.abc import Iterable
from hashlib import sha256
from urllib.parse import quote

from . import __version__
from .scanner import RULES, Finding

LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def to_sarif(findings: Iterable[Finding]) -> dict:
    findings = sorted(findings)
    rule_ids = sorted({finding.rule_id for finding in findings})
    indices = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    rules = [
        {
            "id": rule_id,
            "shortDescription": {"text": RULES[rule_id].title},
            "help": {"text": RULES[rule_id].advice},
            "defaultConfiguration": {"level": LEVELS[RULES[rule_id].severity]},
            "properties": {"tags": ["security"]},
        }
        for rule_id in rule_ids
    ]
    results = [
        {
            "ruleId": finding.rule_id,
            "ruleIndex": indices[finding.rule_id],
            "level": LEVELS[finding.rule.severity],
            "message": {"text": f"{finding.rule.title}. {finding.rule.advice}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": quote(finding.path, safe="/")},
                    "region": {"startLine": finding.line, "startColumn": finding.column},
                },
            }],
            "partialFingerprints": {
                "primaryLocationLineHash/v1": sha256(
                    finding.source_line.strip().encode("utf-8")
                ).hexdigest(),
            } if finding.source_line else {},
            "properties": {"severity": finding.rule.severity},
        }
        for finding in findings
    ]
    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ActionHound", "version": __version__, "rules": rules}},
            "results": results,
        }],
    }


def to_markdown(findings: Iterable[Finding]) -> str:
    lines = ["# ActionHound findings", ""]
    findings = sorted(findings)
    if not findings:
        lines.append("No findings.")
    for finding in findings:
        safe_path = quote(finding.path, safe="/._-")
        lines.append(
            f"- **{finding.rule.severity.upper()} {finding.rule_id}** "
            f"`{safe_path}:{finding.line}:{finding.column}` — "
            f"{finding.rule.title}. {finding.rule.advice}"
        )
    return "\n".join(lines) + "\n"

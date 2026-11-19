from urllib.parse import quote

LEVELS = {"high": "error", "medium": "warning", "low": "note"}


def serialize(findings):
    findings = list(findings)
    rules = sorted({finding.rule for finding in findings})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ActionHound", "rules": [
                {"id": rule, "name": rule} for rule in rules
            ]}},
            "results": [{
                "ruleId": finding.rule,
                "level": LEVELS[finding.severity],
                "message": {"text": finding.message},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": quote(finding.path)},
                    "region": {"startLine": finding.line},
                }}],
            } for finding in findings],
        }],
    }


def markdown(findings):
    output = ["# ActionHound findings", ""]
    output.extend(
        f"- **{item.severity.upper()}** `{item.rule}` "
        f"`{item.path}:{item.line}` — {item.message}" for item in findings
    )
    return "\n".join(output)

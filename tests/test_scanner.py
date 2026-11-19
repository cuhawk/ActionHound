import json

import pytest
import yaml

from actionhound.sarif import markdown, serialize
from actionhound.scanner import Finding, scan, scan_file, scan_oidc

PIN = "a" * 40


@pytest.mark.parametrize(("uses", "expected"), [
    ("example/test@v4", {"mutable-action"}),
    ("example/test@main", {"mutable-action"}),
    ("example/test", {"mutable-action"}),
    (f"example/test@{PIN}", set()),
    ("./local", set()),
    ("docker://alpine:3", {"mutable-image"}),
    ("docker://alpine@sha256:" + "a" * 64, set()),
])
def test_pinning(tmp_path, uses, expected):
    assert rules_for(tmp_path, "push", [{"uses": uses}]) == expected


@pytest.mark.parametrize(("event", "value", "expected"), [
    ("pull_request_target", "${{ github.event.pull_request.head.sha }}", True),
    (["pull_request_target"], "${{ github.event.pull_request.head.ref }}", True),
    ({"pull_request_target": {}}, "${{ github.event.pull_request.head.sha }}", True),
    ("pull_request_target", "${{ github.sha }}", False),
    ("pull_request", "${{ github.event.pull_request.head.sha }}", False),
    ("push", "main", False),
])
def test_checkout(tmp_path, event, value, expected):
    rules = rules_for(tmp_path, event, [{"uses": f"actions/checkout@{PIN}", "with": {"ref": value}}])
    assert ("privileged-pr-checkout" in rules) == expected


@pytest.mark.parametrize(("command", "expected"), [
    ("echo ${{ github.event.issue.title }}", True),
    ("echo ${{ github.event['issue'].title }}", True),
    ("echo ${{ github.sha }}", False),
    ('echo "$ISSUE_TITLE"', False),
])
def test_expression(tmp_path, command, expected):
    assert ("script-expression" in rules_for(tmp_path, "push", [{"run": command}])) == expected


@pytest.mark.parametrize(("event", "action", "options", "expected"), [
    ("pull_request_target", "actions/cache", {}, {"cache-trust"}),
    ("push", "actions/cache", {}, set()),
    ("push", "actions/cache", {"restore-keys": "global"}, {"cache-trust"}),
    ("workflow_run", "actions/download-artifact", {}, {"artifact-trust"}),
    ("push", "actions/download-artifact", {}, set()),
])
def test_provenance(tmp_path, event, action, options, expected):
    assert rules_for(tmp_path, event, [{"uses": f"{action}@{PIN}", "with": options}]) == expected


def rules_for(tmp_path, event, steps):
    root = tmp_path / ".github/workflows"
    root.mkdir(parents=True)
    path = root / "test.yml"
    path.write_text(yaml.safe_dump({"on": event, "jobs": {"job": {"steps": steps}}}))
    return {row.rule for row in scan(tmp_path)}


@pytest.mark.parametrize(("operator", "subject", "expected"), [
    ("StringLike", "repo:org/*", True),
    ("StringLike", "repo:org/repo:ref:refs/heads/main", False),
    ("StringEquals", "repo:org/repo:ref:refs/heads/main", False),
])
def test_oidc(tmp_path, operator, subject, expected):
    path = tmp_path / "trust.json"
    path.write_text(json.dumps({"Statement": [{
        "Effect": "Allow", "Principal": {"Federated": "token.actions.githubusercontent.com"},
        "Condition": {operator: {"token.actions.githubusercontent.com:sub": subject}},
    }]}))
    assert bool(scan_oidc(path, tmp_path)) == expected


def test_gitlab(tmp_path):
    path = tmp_path / ".gitlab-ci.yml"
    path.write_text("job:\n  script: echo ok\n  cache: {key: default}\n")
    assert [row.rule for row in scan_file(path, tmp_path)] == ["shared-cache"]


def test_sarif():
    rows = [Finding("a b.yml", 2, "test", "high", "review")]
    report = serialize(rows)
    assert report["version"] == "2.1.0"
    entry = report["runs"][0]["results"][0]
    assert entry["level"] == "error"
    assert entry["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "a%20b.yml"
    assert "HIGH" in markdown(rows)


def test_no_gitlab_or_workflows(tmp_path):
    assert scan(tmp_path) == []

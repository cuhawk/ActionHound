from pathlib import Path
from textwrap import dedent

import pytest

from actionhound.scanner import ScanError, scan


def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(content).lstrip("\n"), encoding="utf-8")


def workflow(root, step, *, event="pull_request", extra=""):
    path = root / ".github/workflows/check.yml"
    indented_step = "\n".join(f"      {line}" for line in step.splitlines())
    write(path, f"on: {event}\n{extra}jobs:\n  test:\n    steps:\n{indented_step}\n")
    return path


@pytest.mark.parametrize(("ref", "expected"), [
    ("v4", True), ("main", True), ("a" * 40, False),
    ("A" * 40, False), ("a" * 39, True), ("g" * 40, True),
])
def test_action_pins(tmp_path, ref, expected):
    workflow(tmp_path, f"- uses: actions/checkout@{ref}\n  with: {{persist-credentials: false}}")
    assert bool(scan(tmp_path)) == expected


@pytest.mark.parametrize(("reference", "expected"), [
    ("./actions/local", False),
    ("./.github/workflows/reusable.yml", False),
    ("docker://example.invalid/test:latest", True),
    ("docker://example.invalid/test@sha256:" + "c" * 64, False),
    ("example/test/.github/workflows/reusable.yml@main", True),
])
def test_reference_formats(tmp_path, reference, expected):
    workflow(tmp_path, f"- uses: {reference}")
    assert bool(scan(tmp_path)) == expected


@pytest.mark.parametrize(("script", "expected"), [
    ("${{ github.event.pull_request.title }}", True),
    ("${{ github.event['issue']['body'] }}", True),
    ("${{ github.head_ref }}", True),
    ("${{ github.event.pull_request.head.sha }}", False),
    ("${{ github.event.number }}", False),
    ("${{ github.sha }}", False),
    ("${{ 'github.event.issue.title' }}", False),
    ('printf "%s" "$TITLE"', False),
])
def test_inline_data(tmp_path, script, expected):
    workflow(tmp_path, f"- run: |\n    # {script}")
    ids = {finding.rule_id for finding in scan(tmp_path)}
    assert ("AH002" in ids) == expected


@pytest.mark.parametrize(("event", "expected"), [
    ("pull_request_target", {"AH001"}),
    ("[push, pull_request_target]", {"AH001"}),
    ("{pull_request_target: {}}", {"AH001"}),
    ("pull_request", set()),
])
def test_checkout_boundary(tmp_path, event, expected):
    workflow(tmp_path, f"""- uses: actions/checkout@{'a'*40}
  with:
    persist-credentials: false
    ref: ${{{{ github.event.pull_request.head.sha }}}}""", event=event)
    assert {f.rule_id for f in scan(tmp_path)} == expected


def test_trusted_checkout(tmp_path):
    workflow(tmp_path, f"""- uses: actions/checkout@{'a'*40}
  with:
    persist-credentials: false
    ref: ${{{{ github.event.pull_request.base.sha }}}}""", event="pull_request_target")
    assert scan(tmp_path) == []


@pytest.mark.parametrize(("event", "expected"), [("pull_request_target", True), ("push", False)])
def test_cache_boundary(tmp_path, event, expected):
    workflow(tmp_path, "- uses: actions/cache@v4", event=event)
    assert ("AH006" in {f.rule_id for f in scan(tmp_path)}) == expected


@pytest.mark.parametrize(("inputs", "expected"), [
    ("    run-id: 1234", True), ("    repository: demo/other", True),
    ("    name: current-run", False),
])
def test_artifact_boundary(tmp_path, inputs, expected):
    workflow(tmp_path, f"- uses: actions/download-artifact@v4\n  with:\n{inputs}")
    assert ("AH007" in {f.rule_id for f in scan(tmp_path)}) == expected


def test_permissions_and_secret(tmp_path):
    workflow(tmp_path, """- uses: example/report@main
  env:
    TOKEN: ${{ secrets.REPORT_TOKEN }}""", extra="permissions: write-all\n")
    assert {f.rule_id for f in scan(tmp_path)} == {"AH004", "AH005", "AH014", "AH015"}


def test_job_permissions(tmp_path):
    path = tmp_path / ".github/workflows/check.yaml"
    write(path, """
        on: push
        jobs:
          bounded:
            environment: production
            permissions:
              id-token: write
          unbounded:
            permissions:
              id-token: write
    """)
    finding, = scan(tmp_path, protected_environments=["production"])
    assert (finding.rule_id, finding.path, finding.line) == (
        "AH015", ".github/workflows/check.yaml", 9
    )


@pytest.mark.parametrize(("subject", "expected"), [
    ("repo:example/*", {"AH008"}),
    ("repo:example/app:ref:refs/heads/main", set()),
])
def test_gitlab_oidc(tmp_path, subject, expected):
    write(tmp_path / ".gitlab-ci.yml", f"variables:\n  oidc_subject: '{subject}'")
    assert {f.rule_id for f in scan(tmp_path)} == expected


def test_gitlab_include_and_artifact(tmp_path):
    write(tmp_path / ".gitlab-ci.yml", """
        include:
          - project: demo/templates
            file: build.yml
            ref: main
        inspect:
          needs:
            - project: demo/tools
              job: build
              ref: main
              artifacts: true
    """)
    assert [(f.rule_id, f.line) for f in scan(tmp_path)] == [("AH016", 2), ("AH007", 7)]


@pytest.mark.parametrize(("policy", "expected"), [("pull-push", {"AH006"}), ("pull", set())])
def test_gitlab_cache(tmp_path, policy, expected):
    write(tmp_path / ".gitlab-ci.yml", f"""
        default:
          cache:
            unprotect: true
            policy: {policy}
        test:
          only: [merge_requests]
          script: echo test
    """)
    assert {f.rule_id for f in scan(tmp_path)} == expected


def test_invalid_yaml(tmp_path):
    write(tmp_path / ".gitlab-ci.yml", "build: [")
    with pytest.raises(ScanError, match=r"\.gitlab-ci\.yml"):
        scan(tmp_path)


def test_recursive_alias(tmp_path):
    write(tmp_path / ".gitlab-ci.yml", "variables: &loop {next: *loop}")
    assert scan(tmp_path) == []


def test_reject_symlink_outside_root(tmp_path):
    outside = tmp_path / "outside.yml"
    write(outside, "permissions: write-all")
    root = tmp_path / "repo"
    path = root / ".github/workflows/test.yml"
    path.parent.mkdir(parents=True)
    path.symlink_to(outside)
    assert scan(root) == []


@pytest.mark.parametrize(("fixture", "target", "expected"), [
    ("github.yml", ".github/workflows/fixture.yml", {"AH003", "AH004", "AH013", "AH015"}),
    ("gitlab.yml", ".gitlab-ci.yml", {"AH007"}),
])
def test_examples(tmp_path, fixture, target, expected):
    source = Path(__file__).parents[1] / "examples/vulnerable_workflows" / fixture
    write(tmp_path / target, source.read_text(encoding="utf-8"))
    assert {f.rule_id for f in scan(tmp_path)} == expected


def test_disabled_pr_target_example(tmp_path):
    source = Path(__file__).parents[1] / "examples/vulnerable_workflows/pull-request-target.yml"
    write(tmp_path / ".github/workflows/fixture.yml", source.read_text(encoding="utf-8"))
    assert {f.rule_id for f in scan(tmp_path)} == {"AH001", "AH003", "AH006"}


@pytest.mark.parametrize(("operator", "subject", "expected"), [
    ("StringLike", "repo:example/*", True),
    ("ForAnyValue:StringLike", "repo:example/app:ref:refs/heads/*", True),
    ("StringEquals", "repo:example/app:ref:refs/heads/main", False),
    ("StringEquals", None, True),
])
def test_aws_oidc_policy(tmp_path, operator, subject, expected):
    import json

    policy = tmp_path / "trust.json"
    policy.write_text(json.dumps({"Statement": [{
        "Effect": "Allow",
        "Principal": {"Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"},
        "Condition": {operator: {"token.actions.githubusercontent.com:sub": subject}} if subject else {},
    }]}), encoding="utf-8")
    assert {f.rule_id for f in scan(tmp_path, ["trust.json"])} == ({"AH008"} if expected else set())


def test_gitlab_shared_cache(tmp_path):
    write(tmp_path / ".gitlab-ci.yml", "test:\n  cache: {key: default}\n  script: echo ok")
    assert {f.rule_id for f in scan(tmp_path)} == {"AH018"}


def test_privileged_artifact_download(tmp_path):
    workflow(tmp_path, "- uses: actions/download-artifact@" + "a" * 40, event="workflow_run")
    assert {f.rule_id for f in scan(tmp_path)} == {"AH011"}

import json
import subprocess
from collections import Counter
from pathlib import Path

import pytest

from actionhound.cli import main
from actionhound.remediation import emit_diff
from actionhound.sarif import to_sarif
from actionhound.scanner import scan
from benchmarks.corpus import FIXTURES, PROTECTED
from test_scanner import workflow, write


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda fixture: fixture.name)
def test_corpus_labels(tmp_path, fixture):
    fixture.write(tmp_path)
    assert Counter((f.path, f.rule_id) for f in scan(
        tmp_path, protected_environments=PROTECTED
    )) == Counter(fixture.expected)


@pytest.mark.parametrize("source", ["github.event.pull_request.head.sha", "github.head_ref", "github.sha"])
def test_reusable_composite_checkout_boundary(tmp_path, source):
    write(tmp_path / ".github/workflows/main.yml", f"""
        on: pull_request_target
        jobs:
          call:
            uses: ./.github/workflows/check.yaml
            with:
              ref: ${{{{ {source} }}}}
    """)
    write(tmp_path / ".github/workflows/check.yaml", """
        on:
          workflow_call:
            inputs:
              ref:
                type: string
        jobs:
          check:
            runs-on: ubuntu-latest
            steps:
              - uses: ./.github/actions/checkout
                with:
                  revision: ${{ inputs['ref'] }}
              - run: echo Review
                env:
                  TOKEN: ${{ secrets.REVIEW_TOKEN }}
    """)
    sink = ".github/actions/checkout/action.yaml"
    write(tmp_path / sink, """
        inputs:
          revision:
            description: Checkout revision
        runs:
          using: composite
          steps:
            - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
              with:
                ref: ${{ inputs.revision }}
                persist-credentials: false
    """)
    actual = [(f.path, f.rule_id) for f in scan(tmp_path)]
    assert actual == ([(sink, "AH001"), (".github/workflows/check.yaml", "AH019")]
                      if source != "github.sha" else [])


def test_reusable_permissions_are_capped_by_every_caller(tmp_path):
    parent = tmp_path / ".github/workflows/main.yml"
    template = """
        on: workflow_run
        jobs:
          call:
            uses: ./.github/workflows/bridge.yml
            permissions: {cap}
    """
    write(parent, template.format(cap="{contents: read}"))
    write(tmp_path / ".github/workflows/bridge.yml", """
        on: workflow_call
        jobs:
          call:
            uses: ./.github/workflows/sink.yml
            permissions: {contents: write}
    """)
    write(tmp_path / ".github/workflows/sink.yml", """
        on: workflow_call
        permissions: {contents: write}
        jobs:
          inspect:
            steps:
              - uses: ./.github/actions/download
    """)
    path = ".github/actions/download/action.yml"
    write(tmp_path / path, """
        runs:
          using: composite
          steps:
            - run: gh run download 1234
              shell: bash
    """)
    assert scan(tmp_path) == []
    write(parent, template.format(cap="{contents: write}"))
    assert [(f.path, f.rule_id) for f in scan(tmp_path)] == [(path, "AH011")]


def test_distinct_caller_contexts_and_cycles(tmp_path):
    write(tmp_path / ".github/workflows/a-clean.yml", """
        on: push
        jobs:
          call:
            uses: ./.github/workflows/bridge.yml
            with: {label: safe}
    """)
    write(tmp_path / ".github/workflows/b-tainted.yml", """
        on: pull_request
        jobs:
          call:
            uses: ./.github/workflows/bridge.yml
            with:
              label: ${{ github.event.pull_request.title }}
    """)
    write(tmp_path / ".github/workflows/bridge.yml", """
        on: workflow_call
        jobs:
          circular:
            uses: ./.github/workflows/bridge.yml
          emit:
            steps:
              - uses: ./.github/actions/emit
                with:
                  label: ${{ inputs.label }}
    """)
    path = ".github/actions/emit/action.yml"
    write(tmp_path / path, """
        runs:
          using: composite
          steps:
            - uses: ./.github/actions/emit
            - run: echo "LABEL=$LABEL" >> "$GITHUB_ENV"
              shell: bash
              env:
                LABEL: ${{ inputs.label }}
    """)
    assert [(f.path, f.rule_id) for f in scan(tmp_path)] == [(path, "AH012")]


def test_resolver_does_not_read_outside_checkout(tmp_path):
    root = tmp_path / "repo"
    workflow(root, "- uses: ./.github/actions/escape")
    outside = tmp_path / "outside"
    write(outside / "action.yml", "invalid: [")
    actions = root / ".github/actions"
    actions.mkdir()
    (actions / "escape").symlink_to(outside, target_is_directory=True)
    assert scan(root) == []


@pytest.mark.parametrize(("line", "expected"), [
    ('printf "%s" "$TITLE" >> "$GITHUB_ENV"', True),
    ('printf "%s" "${TITLE}" |\ntee -a "$GITHUB_PATH"', True),
    ('$env:TITLE | Out-File -FilePath $env:GITHUB_PATH', True),
    ('echo "$TITLE" >> "$GITHUB_OUTPUT"', False),
    ('cat "$GITHUB_ENV" "$TITLE"', False),
    ("echo '$TITLE' >> \"$GITHUB_ENV\"", False),
    ('echo "$TITLE" >> \'$GITHUB_ENV\'', False),
    ('# echo "$TITLE" >> "$GITHUB_ENV"', False),
])
def test_environment_files(tmp_path, line, expected):
    script = "\n".join(f"    {part}" for part in line.splitlines())
    workflow(tmp_path, f"""- env:
    TITLE: ${{{{ github.event.pull_request.title }}}}
  run: |
{script}""")
    assert ("AH012" in {f.rule_id for f in scan(tmp_path)}) is expected


@pytest.mark.parametrize(("environment", "expected"), [
    ("production", False), ("{name: production}", False), ("PRODUCTION", False), ("staging", True),
    ("'${{ inputs.environment }}'", True), ("true", True),
])
def test_only_verified_environment_scopes_oidc(tmp_path, environment, expected):
    write(tmp_path / ".github/workflows/check.yml", f"""
        on: push
        jobs:
          publish:
            environment: {environment}
            permissions: {{id-token: write}}
            runs-on: ubuntu-latest
            steps: [{{run: echo ok}}]
    """)
    assert bool(scan(tmp_path, protected_environments=["production"])) is expected


def test_line_fingerprints_survive_moving_findings(tmp_path):
    path = workflow(tmp_path, "- uses: example/demo@v1\n- uses: example/demo@v2")
    first = to_sarif(scan(tmp_path))["runs"][0]["results"]
    before = path.read_text(encoding="utf-8")
    path.write_text("# header\n\n" + before, encoding="utf-8")
    second = to_sarif(scan(tmp_path))["runs"][0]["results"]
    key = "primaryLocationLineHash/v1"
    assert first[0]["partialFingerprints"][key] != first[1]["partialFingerprints"][key]
    for earlier, later in zip(first, second, strict=True):
        assert earlier["partialFingerprints"][key] == later["partialFingerprints"][key]
        assert (earlier["locations"][0]["physicalLocation"]["region"]["startLine"] + 2
                == later["locations"][0]["physicalLocation"]["region"]["startLine"])


@pytest.mark.parametrize("line_ending", ["\n", "\r\n"])
def test_cli_patch_applies_without_reformatting(tmp_path, line_ending):
    relative = Path(".github/workflows/patch target.yml")
    original = """# keep this comment
on: push
permissions: write-all # narrow the default
jobs:
  build:
    container: {image: 'registry.example:5000/base:stable'}
    permissions: {contents: write, id-token: write}
    runs-on: ubuntu-latest
    steps:
      - uses: example/demo@v1 # pinned offline
      - uses: actions/setup-node@v4"""
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    path.write_bytes(original.replace("\n", line_ending).encode())
    pins = tmp_path / "pins.json"
    pins.write_text(json.dumps({"example/demo@v1": "a" * 40,
                               "registry.example:5000/base:stable": "sha256:" + "b" * 64}))
    patch_path = tmp_path / "fixes.patch"
    assert main(["scan", str(tmp_path), "--emit-diff", str(patch_path), "--pin-map", str(pins)]) == 0
    patch = patch_path.read_bytes()
    assert path.read_bytes() == original.replace("\n", line_ending).encode()
    assert patch == emit_diff(tmp_path, scan(tmp_path), json.loads(pins.read_text())).encode()
    subprocess.run(["git", "apply", str(patch_path)], cwd=tmp_path, check=True, capture_output=True)
    result = path.read_bytes()
    assert b"# keep this comment" in result
    assert b"contents: write, id-token: none" in result
    assert b"actions/setup-node@v4" in result
    assert result.count(line_ending.encode()) == original.count("\n")
    assert {f.rule_id for f in scan(tmp_path)} == {"AH003"}


def test_patch_skips_shared_anchors(tmp_path):
    path = workflow(tmp_path, "- uses: &ref example/demo@v1\n- run: *ref")
    assert "AH014" in {f.rule_id for f in scan(tmp_path)}
    assert emit_diff(tmp_path, scan(tmp_path), {"example/demo@v1": "a" * 40}) == ""
    assert "&ref" in path.read_text()


def test_invalid_pin_does_not_write_patch(tmp_path, capsys):
    workflow(tmp_path, "- uses: example/demo@v1")
    pins = tmp_path / "pins.json"
    pins.write_text(json.dumps({"example/demo@v1": "main"}))
    patch = tmp_path / "patch"
    assert main(["scan", str(tmp_path), "--emit-diff", str(patch), "--pin-map", str(pins)]) == 2
    assert "full commit SHA" in capsys.readouterr().err
    assert not patch.exists()


@pytest.mark.parametrize(("value", "expected"), [
    ("false", False), ('"false"', False), ("true", True), ("null", True),
])
def test_checkout_credential_input(tmp_path, value, expected):
    workflow(tmp_path, f"""- uses: actions/checkout@{'a' * 40}
  with:
    persist-credentials: {value}""")
    assert ("AH013" in {f.rule_id for f in scan(tmp_path)}) is expected


def test_github_script_artifact_download(tmp_path):
    workflow(tmp_path, f"""- uses: actions/github-script@{'a' * 40}
  with:
    script: await github.rest.actions.downloadArtifact(options)""", event="workflow_run")
    assert {f.rule_id for f in scan(tmp_path)} == {"AH011"}

import json
from pathlib import Path

import jsonschema
import pytest

from actionhound.cli import main
from actionhound.sarif import to_markdown, to_sarif
from actionhound.scanner import Finding


@pytest.mark.parametrize("findings", [[], [
    Finding(".github/workflows/a# b.yml", 2, 3, "AH004"),
    Finding(".github/workflows/z.yml", 4, 1, "AH003"),
]])
def test_sarif_schema(findings):
    schema_path = Path(__file__).parent / "schema/sarif-2.1.0.json"
    report = to_sarif(findings)
    jsonschema.validate(report, json.loads(schema_path.read_text(encoding="utf-8")))
    run, = report["runs"]
    for finding, result in zip(findings, run["results"], strict=True):
        assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == finding.rule_id
        assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == finding.line
    if findings:
        assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].endswith("a%23%20b.yml")


@pytest.mark.parametrize(("threshold", "expected"), [("high", 1), ("critical", 0)])
def test_cli_gate(tmp_path, threshold, expected, capsys):
    workflow = tmp_path / ".github/workflows/test.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("permissions: write-all", encoding="utf-8")
    sarif = tmp_path / "out.sarif"
    markdown = tmp_path / "out.md"
    assert main(["scan", str(tmp_path), "--fail-on", threshold, "--sarif", str(sarif),
                 "--markdown", str(markdown)]) == expected
    assert "AH004" in capsys.readouterr().out
    assert "AH004" in markdown.read_text(encoding="utf-8")
    assert json.loads(sarif.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_cli_bad_directory(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "missing")]) == 2
    assert "Not a directory" in capsys.readouterr().err


def test_empty_markdown():
    assert "No findings." in to_markdown([])

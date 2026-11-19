"""Static workflow diagnostics. Workflow commands are never executed."""

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

EXPRESSION = re.compile(r"\$\{\{\s*github\.event(?:\.|\[)[^}]+\}\}")
SHA = re.compile(r"[a-fA-F0-9]{40}\Z")


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    rule: str
    severity: str
    message: str


def scan_file(path: Path, root: Path):
    text = path.read_text()
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a YAML mapping")
    location = path.relative_to(root).as_posix()
    lines = text.splitlines()
    results = set()

    def emit(rule, severity, message, fragment):
        line = next((i for i, text_line in enumerate(lines, 1)
                     if fragment and fragment in text_line), 1)
        results.add(Finding(location, line, rule, severity, message))

    if path.name == ".gitlab-ci.yml":
        for job in data.values():
            if not isinstance(job, dict) or "script" not in job:
                continue
            for command in as_list(job["script"]):
                command = str(command)
                if re.search(r'\b(?:eval|(?:ba)?sh\s+-c)\s+["\']?\$\{?CI_MERGE_REQUEST_', command):
                    emit("gitlab-script-input", "high",
                         "Merge request metadata reaches a shell interpreter.", command)
            cache = job.get("cache")
            if isinstance(cache, dict) and cache.get("key") in {"default", "$CI_PROJECT_NAME"}:
                emit("shared-cache", "medium", "Cache is shared across refs.", str(cache["key"]))
        return sorted(results)

    events = data.get("on", data.get(True, []))
    privileged_pr = "pull_request_target" in (
        events if isinstance(events, (list, dict)) else [events]
    )
    jobs = data.get("jobs", {})
    if not isinstance(jobs, dict):
        raise ValueError(f"{path}: jobs must be a mapping")

    def permissions(value):
        if value == "write-all":
            emit("write-all", "high", "Grant only required token permissions.", "write-all")
        if isinstance(value, dict) and value.get("id-token") == "write":
            emit("oidc-token", "medium",
                 "Review federated trust conditions for this OIDC-enabled job.", "id-token")

    permissions(data.get("permissions"))
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        permissions(job.get("permissions"))
        steps = [step for step in as_list(job.get("steps", [])) if isinstance(step, dict)]
        steps = ([job] if "uses" in job else []) + steps
        unsafe_checkout = False
        for step in steps:
            uses = step.get("uses", "")
            if not isinstance(uses, str):
                continue
            action, _, ref = uses.partition("@")
            if uses and not uses.startswith(("./", "docker://")) and not SHA.fullmatch(ref):
                emit("mutable-action", "medium", "Pin the action to a full commit SHA.", uses)
            if uses.startswith("docker://") and not re.search(r"@sha256:[a-fA-F0-9]{64}$", uses):
                emit("mutable-image", "medium", "Pin the image to a SHA-256 digest.", uses)
            options = step.get("with", {})
            if not isinstance(options, dict):
                options = {}
            checkout_ref = str(options.get("ref", "")) + str(options.get("repository", ""))
            if privileged_pr and action == "actions/checkout" and "github.event.pull_request.head" in checkout_ref:
                unsafe_checkout = True
                emit("privileged-pr-checkout", "high",
                     "Privileged workflow checks out pull request head content.", uses)
            if action.startswith("actions/cache") and (
                privileged_pr or options.get("restore-keys")
            ):
                emit("cache-trust", "medium", "Review cache provenance across trust boundaries.", uses)
            if action == "actions/download-artifact" and (
                privileged_pr or events == "workflow_run" or (
                    isinstance(events, (dict, list)) and "workflow_run" in events
                )
            ):
                emit("artifact-trust", "medium", "Review artifact provenance before use.", uses)
            command = step.get("run")
            if isinstance(command, str) and (match := EXPRESSION.search(command)):
                emit("script-expression", "high",
                     "Move event metadata into environment variables and quote expansions.",
                     match.group())
            if unsafe_checkout and "secrets." in str(step):
                emit("secret-after-checkout", "high",
                     "Secret is available after an untrusted checkout.", "secrets.")
    return sorted(results)


def scan_oidc(path: Path, root: Path):
    """Inspect standalone AWS trust policies kept alongside workflows."""
    import json

    text = path.read_text()
    data = json.loads(text)
    if not isinstance(data, dict):
        return []
    results = set()
    for statement in as_list(data.get("Statement", [])):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal", {})
        if not isinstance(principal, dict) or not any(
            "token.actions.githubusercontent.com" in str(provider)
            for provider in as_list(principal.get("Federated", []))
        ):
            continue
        condition = statement.get("Condition", {})
        if not isinstance(condition, dict):
            continue
        subject = "token.actions.githubusercontent.com:sub"
        subjects = [
            (operator, value)
            for operator, clauses in condition.items() if isinstance(clauses, dict)
            for value in as_list(clauses.get(subject, []))
        ]
        if not subjects or any(
            operator == "StringLike" and any(mark in str(value) for mark in "*?")
            for operator, value in subjects
        ):
            line = next((i for i, row in enumerate(text.splitlines(), 1)
                         if subject in row), 1)
            results.add(Finding(path.relative_to(root).as_posix(), line,
                                "oidc-wildcard", "high",
                                "Constrain GitHub OIDC subject to an explicit trust boundary."))
    return sorted(results)

def as_list(value):
    return value if isinstance(value, list) else [value]


def scan(root: Path, trust_policies=()):
    workflows = root / ".github" / "workflows"
    paths = [*workflows.glob("*.yml"), *workflows.glob("*.yaml")]
    gitlab = root / ".gitlab-ci.yml"
    if gitlab.is_file():
        paths.append(gitlab)
    findings = [finding for path in sorted(paths) for finding in scan_file(path, root)]
    for path in trust_policies:
        findings.extend(scan_oidc(root / path, root))
    return sorted(findings)

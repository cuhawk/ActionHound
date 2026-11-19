"""Scan local YAML without running workflow code or resolving remote includes."""

import json
import re
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Rule:
    severity: str
    title: str
    advice: str


RULES = {
    "AH001": Rule("critical", "Untrusted checkout in pull_request_target",
                  "Use pull_request for untrusted code or check out only the trusted base."),
    "AH002": Rule("high", "Untrusted expression in inline script",
                  "Pass data through an environment variable and quote its shell expansion."),
    "AH003": Rule("medium", "Action or reusable workflow is not SHA-pinned",
                  "Pin the reference to a verified full commit SHA."),
    "AH004": Rule("high", "All workflow permissions are writable",
                  "Grant only the permissions the workflow or job needs."),
    "AH005": Rule("high", "Secrets passed to a mutable external step",
                  "Pin and review the action before granting access to individual secrets."),
    "AH006": Rule("high", "Cache crosses a workflow trust boundary",
                  "Separate caches by trust level and avoid writable shared caches."),
    "AH007": Rule("high", "Cross-workflow artifact download",
                  "Validate the producer and content before consuming artifacts in a privileged job."),
    "AH008": Rule("high", "Wildcard OIDC trust subject",
                  "Restrict federation to a specific repository, ref, or protected environment."),
    "AH009": Rule("medium", "OIDC token permission lacks an explicit job boundary",
                  "Grant id-token: write only to deployment jobs with a protected environment."),
    "AH010": Rule("medium", "GitLab remote include has no immutable reference",
                  "Pin project includes to a verified full commit SHA and remote includes by integrity."),
    "AH012": Rule("medium", "GitLab cache key is shared across refs",
                  "Use a ref-specific cache key and enforce separate trust domains."),
    "AH013": Rule("high", "Secrets available after untrusted checkout",
                  "Run trusted steps with secrets in a separate job that never checks out the PR head."),
    "AH011": Rule("high", "Merge request job uses shell re-evaluation",
                  "Treat merge request variables as data and avoid shell re-evaluation."),
}


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    column: int
    rule_id: str

    @property
    def rule(self) -> Rule:
        return RULES[self.rule_id]


class ScanError(ValueError):
    """A source file could not be read or parsed."""


class WorkflowLoader(yaml.SafeLoader):
    """Use YAML 1.2 boolean spellings so the workflow 'on' key stays a string."""


WorkflowLoader.yaml_implicit_resolvers = {
    key: [(tag, regex) for tag, regex in values if tag != "tag:yaml.org,2002:bool"]
    for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|false)$", re.I), list("tTfF")
)


def _load(path):
    class MarkedDict(dict):
        pass

    class Loader(WorkflowLoader):
        def construct_mapping(self, node, deep=False):
            self.flatten_mapping(node)
            result = MarkedDict(super().construct_mapping(node, deep=deep))
            result.marks = {
                self.construct_object(key): (value.start_mark.line + 1, value.start_mark.column + 1)
                for key, value in node.value
            }
            return result

    def mapping(loader, node):
        data = MarkedDict()
        yield data
        constructed = loader.construct_mapping(node)
        data.update(constructed)
        data.marks = constructed.marks

    Loader.add_constructor("tag:yaml.org,2002:map", mapping)
    return yaml.load(path.read_text(encoding="utf-8"), Loader=Loader)


def _map(value):
    return value if isinstance(value, dict) else {}


def _items(value):
    return value if isinstance(value, list) else [value]


SHA = re.compile(r"[0-9a-f]{40}", re.I)
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
SECRET = re.compile(r"\$\{\{\s*secrets\b", re.I)
PR_HEAD = re.compile(
    r"\bgithub\.event\.pull_request\.head\b|\bgithub\.head_ref\b",
    re.I,
)
EVENT_DATA = re.compile(
    r"\bgithub\.(?:event|head_ref|ref_name)\b", re.I
)
EVENT_TRUSTED = re.compile(
    r"\bgithub\.event\.(?:number|pull_request\.(?:number|id|merged|head\.sha|base\.sha))"
    r"(?![\w.\[])",
    re.I,
)
EXPRESSION_TOKEN = re.compile(r"\[\s*'([\w-]+)'\s*\]|'(?:[^']|'')*'")


def _expression_code(expression):
    return EXPRESSION_TOKEN.sub(
        lambda token: "." + token[1] if token[1] is not None else "''", expression
    )


def _untrusted(script):
    return any(
        EVENT_DATA.search(EVENT_TRUSTED.sub("", _expression_code(expression)))
        for expression in EXPRESSION.findall(script)
    )


def _pr_head(value):
    if not isinstance(value, str):
        return False
    return bool(re.fullmatch(r"refs/pull/.+/head", value)) or any(
        PR_HEAD.search(_expression_code(expr)) for expr in EXPRESSION.findall(value)
    )


def _external_uses(value):
    if not isinstance(value, str) or value.startswith("./"):
        return False
    if value.startswith("docker://"):
        return not bool(re.search(r"@sha256:[0-9a-f]{64}$", value, re.I))
    name, _, ref = value.partition("@")
    return "/" in name and not SHA.fullmatch(ref)


def _github(doc, emit):
    triggers = doc.get("on", [])
    triggers = set(triggers) if isinstance(triggers, dict) else {
        item for item in _items(triggers) if isinstance(item, str)
    }
    privileged = triggers & {"pull_request_target", "workflow_run"}
    root_permissions = doc.get("permissions")
    if root_permissions == "write-all":
        emit("AH004", doc, "permissions")
    if _map(root_permissions).get("id-token") == "write" or root_permissions == "write-all":
        emit("AH009", doc, "permissions")

    for definition in _map(doc.get("jobs")).values():
        job = _map(definition)
        permissions = job.get("permissions", root_permissions)
        if job.get("permissions") == "write-all":
            emit("AH004", job, "permissions")
        if ("permissions" in job and not job.get("environment") and
                (_map(permissions).get("id-token") == "write" or permissions == "write-all")):
            emit("AH009", job, "permissions")

        unsafe_checkout = False
        for step_definition in [job, *_items(job.get("steps"))]:
            step = _map(step_definition)
            uses = step.get("uses", "")
            inputs = _map(step.get("with"))
            has_secrets = (
                bool(SECRET.search(str((inputs, step.get("env"), job.get("env"), doc.get("env"),
                                        step.get("run")))))
                or bool(step.get("secrets"))
            )
            if unsafe_checkout and has_secrets:
                emit("AH013", step, "uses" if "uses" in step else "run")
            if _external_uses(uses):
                emit("AH003", step, "uses")
                if has_secrets:
                    emit("AH005", step, "uses")
            if isinstance(step.get("run"), str) and _untrusted(step["run"]):
                emit("AH002", step, "run")
            if not isinstance(uses, str):
                continue
            action = uses.partition("@")[0].lower()
            if ("pull_request_target" in triggers and action == "actions/checkout" and
                    any(_pr_head(inputs.get(key)) for key in ("ref", "repository"))):
                marker = "ref" if _pr_head(inputs.get("ref")) else "repository"
                emit("AH001", inputs, marker)
                unsafe_checkout = True
            if (privileged or inputs.get("restore-keys")) and (
                action in {"actions/cache", "actions/cache/restore", "actions/cache/save"}
                or (action == "actions/setup-node" and inputs.get("cache"))
            ):
                emit("AH006", step, "uses")
            if action == "actions/download-artifact" and (
                privileged or "run-id" in inputs or "repository" in inputs
            ):
                emit("AH007", step, "uses")
            if "workflow_run" in triggers and action == "dawidd6/action-download-artifact":
                emit("AH007", step, "uses")


def _gitlab(doc, emit):
    for include_definition in _items(doc.get("include")):
        include = _map(include_definition)
        if (("project" in include and not SHA.fullmatch(str(include.get("ref", ""))))
                or ("remote" in include and not re.fullmatch(
                    r"sha256-[A-Za-z0-9+/]{43}=", str(include.get("integrity", ""))
                ))):
            emit("AH010", include, "project" if "project" in include else "remote")
        elif isinstance(include_definition, str) and include_definition.startswith(("https://", "http://")):
            emit("AH010", doc, "include")

    default = _map(doc.get("default"))
    for name, definition in doc.items():
        if name in {"default", "workflow", "variables", "include", "cache", "stages",
                    "image", "services", "before_script", "after_script", "spec"}:
            continue
        if str(name).startswith("."):
            continue
        job = _map(definition)
        if not job:
            continue
        selectors = str([job.get("rules"), job.get("only"), _map(doc.get("workflow")).get("rules")])
        merge_request = bool(re.search(r"merge_requests?|CI_MERGE_REQUEST_", selectors))
        for owner in (job, default, doc):
            if "cache" not in owner:
                continue
            for entry in _items(owner["cache"]):
                cache = _map(entry)
                if not cache or cache.get("policy") == "pull":
                    continue
                if merge_request and (cache.get("unprotect") is True or cache.get("fallback_keys")):
                    emit("AH006", owner, "cache")
                elif str(cache.get("key", "")) in {"default", "$CI_PROJECT_NAME"}:
                    emit("AH012", owner, "cache")
            break
        for key in ("before_script", "script", "after_script"):
            owner = job if key in job else default if key in default else doc
            for script in _items(owner.get(key)):
                if isinstance(script, str) and re.search(
                    r"""\b(?:eval|(?:ba)?sh\s+-c)\s+["']?\$(?:\{)?CI_MERGE_REQUEST_""", script
                ):
                    emit("AH011", owner, key)
        for need in _items(job.get("needs")):
            need = _map(need)
            if "project" in need and need.get("artifacts") is True:
                emit("AH007", need, "project")


OIDC_KEYS = {"sub", "subject", "subjects", "sub-pattern", "subject-pattern",
             "oidc-subject", "oidc-subject-pattern", "token.actions.githubusercontent.com:sub"}


def _oidc(doc, emit, seen):
    if isinstance(doc, (dict, list)):
        if id(doc) in seen:
            return
        seen.add(id(doc))
    if isinstance(doc, list):
        for value in doc:
            _oidc(value, emit, seen)
    elif isinstance(doc, dict):
        for key, value in doc.items():
            if str(key).lower().replace("_", "-") in OIDC_KEYS:
                if any(isinstance(item, str) and ("*" in item or "?" in item)
                       for item in _items(value)):
                    emit("AH008", doc, key)
            _oidc(value, emit, seen)


OIDC_SUBJECT = "token.actions.githubusercontent.com:sub"


def scan_oidc(path: Path, root: Path) -> list[Finding]:
    """Review explicit AWS IAM trust policies for GitHub federation."""
    relative = path.relative_to(root).as_posix()
    try:
        source = path.read_text(encoding="utf-8")
        policy = json.loads(source)
    except (UnicodeError, OSError, json.JSONDecodeError) as exc:
        raise ScanError(f"{relative}: {exc}") from exc
    if not isinstance(policy, dict):
        raise ScanError(f"{relative}: expected a JSON object")
    findings = set()
    for item in _items(policy.get("Statement")):
        statement = _map(item)
        if statement.get("Effect") != "Allow" or not any(
            isinstance(provider, str) and provider.endswith("token.actions.githubusercontent.com")
            for provider in _items(_map(statement.get("Principal")).get("Federated"))
        ):
            continue
        conditions = _map(statement.get("Condition"))
        subjects = [
            (operator, subject)
            for operator, clauses in conditions.items()
            if OIDC_SUBJECT in _map(clauses)
            for subject in _items(clauses[OIDC_SUBJECT])
        ]
        if not subjects or any(
            isinstance(subject, str) and ("*" in subject or "?" in subject)
            for operator, subject in subjects if operator.split(":")[-1].startswith("StringLike")
        ):
            marker = OIDC_SUBJECT if subjects else "Federated"
            line, column = next(
                ((number, text.index(marker) + 1) for number, text in enumerate(source.splitlines(), 1)
                 if marker in text),
                (1, 1),
            )
            findings.add(Finding(relative, line, column, "AH008"))
    return sorted(findings)


def scan(root: Path | str, trust_policies=()) -> list[Finding]:
    """Return deterministic, path-relative findings or raise ScanError."""
    root = Path(root)
    if not root.is_dir():
        raise ScanError(f"Not a directory: {root}")
    workflows = root / ".github" / "workflows"
    gitlab = root / ".gitlab-ci.yml"
    candidates = [*workflows.glob("*.yml"), *workflows.glob("*.yaml"), gitlab]
    findings = set()
    for path in sorted(candidates):
        if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
            continue
        relative = path.relative_to(root).as_posix()
        try:
            doc = _load(path)
        except (UnicodeError, OSError, yaml.YAMLError, RecursionError) as exc:
            raise ScanError(f"{relative}: {exc}") from exc
        if doc is None:
            continue
        if not isinstance(doc, dict):
            raise ScanError(f"{relative}: expected a YAML mapping")

        def emit(rule, owner, key):
            line, column = getattr(owner, "marks", {}).get(key, (1, 1))
            findings.add(Finding(relative, line, column, rule))

        (_gitlab if path == gitlab else _github)(doc, emit)
        _oidc(doc, emit, set())
    for policy in trust_policies:
        path = (root / policy).resolve()
        if not path.is_relative_to(root.resolve()):
            raise ScanError(f"Trust policy is outside the scan root: {policy}")
        findings.update(scan_oidc(path, root.resolve()))
    return sorted(findings)

"""Scan local YAML without running workflow code or resolving remote includes."""

import json
import re
from dataclasses import dataclass, field
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
    "AH010": Rule("medium", "Job container image is not pinned by digest",
                  "Pin the image to a verified SHA-256 digest."),
    "AH011": Rule("high", "Privileged workflow_run downloads an upstream artifact",
                  "Separate untrusted artifact processing from jobs with write permissions or secrets."),
    "AH012": Rule("high", "Untrusted write to a runner environment file",
                  "Validate the value and reject line breaks before writing to a runner environment file."),
    "AH013": Rule("medium", "Checkout persists credentials",
                  "Set persist-credentials: false on the checkout step."),
    "AH014": Rule("medium", "Third-party action is not SHA-pinned",
                  "Pin the action to a verified full commit SHA."),
    "AH015": Rule("medium", "OIDC token permission lacks a protected environment scope",
                  "Grant id-token: write only to jobs using a protected environment."),
    "AH016": Rule("medium", "GitLab remote include has no immutable reference",
                  "Pin project includes to a verified full commit SHA and remote includes by integrity."),
    "AH018": Rule("medium", "GitLab cache key is shared across refs",
                  "Use a ref-specific cache key and enforce separate trust domains."),
    "AH019": Rule("high", "Secrets available after untrusted checkout",
                  "Run trusted steps with secrets in a separate job that never checks out the PR head."),
    "AH017": Rule("high", "Merge request job uses shell re-evaluation",
                  "Treat merge request variables as data and avoid shell re-evaluation."),
}


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    column: int
    rule_id: str
    source_line: str = field(default="", compare=False, repr=False)

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


def _load(source):
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
    return yaml.load(source, Loader=Loader)


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


DIGEST = re.compile(r"@sha256:[0-9a-f]{64}\Z", re.I)


def _external_uses(value):
    if not isinstance(value, str) or value.startswith("./"):
        return False
    if value.startswith("docker://"):
        return not bool(DIGEST.search(value))
    name, _, ref = value.partition("@")
    return "/" in name and not SHA.fullmatch(ref)


INPUT_REF = re.compile(r"\binputs\.([\w-]+)", re.I)
ENV_REF = re.compile(r"\benv\.([\w-]+)", re.I)
SINGLE_QUOTED = re.compile(r"'[^'\n]*'")
SHELL_VAR = re.compile(r"\$env:([A-Za-z_]\w*)|\$\{?([A-Za-z_]\w*)", re.I)
ENV_WRITE = re.compile(
    r"""(?:>{1,2}\s*|\btee\s+(?:-a\s+)?|-(?:FilePath|Path)\s+)"?"""
    r"""(?:\$\{?GITHUB_(?:ENV|PATH)\b|\$env:GITHUB_(?:ENV|PATH)\b)""",
    re.I,
)
ARTIFACT_ACTIONS = {"actions/download-artifact", "dawidd6/action-download-artifact"}
GH_ARTIFACT_DOWNLOAD = re.compile(r"\bgh\s+run\s+download\b")
API_ARTIFACT_DOWNLOAD = re.compile(r"\bgithub\.(?:rest\.)?actions\.downloadArtifact\s*\(")


def _refs(pattern, value):
    return {
        match.lower()
        for expr in EXPRESSION.findall(value)
        for match in pattern.findall(_expression_code(expr))
    }


def _tainted(value, inputs, env, detect=_untrusted):
    return isinstance(value, str) and (
        detect(value) or bool(_refs(INPUT_REF, value) & inputs or _refs(ENV_REF, value) & env)
    )


def _environment(value, inherited, inputs):
    bindings = {str(key).lower(): val for key, val in _map(value).items()}
    return (inherited - bindings.keys()) | {
        key for key, val in bindings.items() if _tainted(val, inputs, inherited)
    }


def _writes_untrusted(script, inputs, env):
    script = re.sub(r"([|\\`])\r?\n", lambda match: "|" if match[1] == "|" else "", script)
    for line in script.splitlines():
        if line.lstrip().startswith("#"):
            continue
        # Shell variables wrapped in single quotes are literal. GitHub expressions
        # are evaluated before shell quoting takes effect.
        shell = SINGLE_QUOTED.sub("", EXPRESSION.sub("", line))
        if ENV_WRITE.search(shell) and (
            _tainted(line, inputs, env)
            or any((power or variable).lower() in env for power, variable in SHELL_VAR.findall(shell))
        ):
            return True
    return False


@dataclass(frozen=True)
class Permissions:
    # Each explicit mapping drops omitted scopes. Calls can only lower access.
    all_writable: bool = True
    writable: frozenset = frozenset()

    def limit(self, value):
        if value is None or value == "write-all":
            return self
        requested = frozenset(key for key, level in _map(value).items() if level == "write")
        return Permissions(False, requested if self.all_writable else requested & self.writable)

    def allows_write(self, scope):
        return self.all_writable or scope in self.writable

    def has_write(self):
        return self.all_writable or bool(self.writable)


def _triggers(doc):
    on = doc.get("on")
    return frozenset(item for item in (on if isinstance(on, dict) else _items(on))
                     if isinstance(item, str))


class GitHubScan:
    def __init__(self, root, load, protected_environments):
        self.root = root
        self.load = load
        self.protected_environments = {name.casefold() for name in protected_environments}
        self.visited = set()
        self.contexts = set()

    def target(self, uses, composite):
        prefix = "./.github/actions/" if composite else "./.github/workflows/"
        if not uses.startswith(prefix) or ".." in Path(uses).parts or "@" in uses:
            return None
        base = self.root / uses
        candidates = [base / "action.yml", base / "action.yaml"] if composite else [base]
        allowed = self.root / prefix
        for path in candidates:
            if (path.is_file() and path.resolve().is_relative_to(allowed)
                    and path.resolve().is_relative_to(self.root)):
                return path.resolve()
        return None

    def workflow(self, path, triggers=None, cap=Permissions(), inputs=frozenset(),
                 heads=frozenset(), stack=frozenset(), secrets=False):
        if path.resolve() in stack:
            return
        doc, emit = self.load(path)
        if doc is None:
            return
        declared = _triggers(doc)
        if triggers is not None and "workflow_call" not in declared:
            return
        self.visited.add(path.resolve())
        if triggers is None:
            triggers = declared
            dispatch = _map(_map(doc.get("on")).get("workflow_dispatch"))
            inputs = frozenset(str(key).lower() for key in _map(dispatch.get("inputs")))
        context = path.resolve(), triggers, cap, frozenset(inputs), frozenset(heads), secrets
        if context in self.contexts:
            return
        self.contexts.add(context)
        stack = stack | {path.resolve()}
        root_permissions = doc.get("permissions")
        if root_permissions == "write-all":
            emit("AH004", doc, "permissions")
        if cap.allows_write("id-token") and (
            _map(root_permissions).get("id-token") == "write" or root_permissions == "write-all"
        ):
            emit("AH015", doc, "permissions")
        root_env = _environment(doc.get("env"), set(), inputs)
        for definition in _map(doc.get("jobs")).values():
            job = _map(definition)
            value = job.get("permissions", root_permissions)
            effective = cap.limit(value)
            if job.get("permissions") == "write-all":
                emit("AH004", job, "permissions")
            environment = job.get("environment")
            if isinstance(environment, dict):
                environment = environment.get("name")
            protected = (isinstance(environment, str) and not EXPRESSION.search(environment)
                         and environment.casefold() in self.protected_environments)
            if ("permissions" in job and effective.allows_write("id-token")
                    and (_map(value).get("id-token") == "write" or value == "write-all")
                    and not protected):
                emit("AH015", job, "permissions")
            container = job.get("container")
            image = container.get("image") if isinstance(container, dict) else container
            if isinstance(image, str) and not DIGEST.search(image):
                emit("AH010", container if isinstance(container, dict) else job,
                     "image" if isinstance(container, dict) else "container")
            env = _environment(job.get("env"), root_env, inputs)
            inherited_secrets = secrets or bool(SECRET.search(str((doc.get("env"), job.get("env")))))
            self.steps(emit, [job, *_items(job.get("steps"))], triggers, effective,
                       inputs, heads, env, stack, inherited_secrets,
                       job_call=job, job_has_secrets=inherited_secrets or bool(SECRET.search(str(job))))

    def steps(self, emit, definitions, triggers, permissions, inputs, heads,
              env, stack, secrets, unsafe_checkout=False, job_call=None, job_has_secrets=False):
        for definition in definitions:
            step = _map(definition)
            uses = step.get("uses")
            arguments = _map(step.get("with"))
            values = step.get("run")
            step_env = _environment(step.get("env"), env, inputs)
            has_secrets = secrets or bool(step.get("secrets")) or bool(
                SECRET.search(str((arguments, step.get("env"), values)))
            )
            if unsafe_checkout and has_secrets and ("uses" in step or "run" in step):
                emit("AH019", step, "uses" if "uses" in step else "run")
            privileged_run = "workflow_run" in triggers and (
                permissions.has_write() or job_has_secrets or has_secrets
            )
            if isinstance(values, str):
                if _tainted(values, inputs, step_env):
                    emit("AH002", step, "run")
                if _writes_untrusted(values, inputs, step_env):
                    emit("AH012", step, "run")
                if privileged_run and GH_ARTIFACT_DOWNLOAD.search(values):
                    emit("AH011", step, "run")
            if not isinstance(uses, str):
                continue
            action = uses.partition("@")[0].lower()
            if _external_uses(uses):
                general_ref = (step is job_call
                               or action.startswith(("actions/", "github/", "docker://")))
                emit("AH003" if general_ref else "AH014", step, "uses")
                if has_secrets:
                    emit("AH005", step, "uses")
            if action == "actions/checkout":
                persist = arguments.get("persist-credentials")
                disabled = persist is False or isinstance(persist, str) and persist.lower() == "false"
                if not disabled:
                    emit("AH013", arguments if "persist-credentials" in arguments else step,
                         "persist-credentials" if "persist-credentials" in arguments else "uses")
                if "pull_request_target" in triggers:
                    for key in ("ref", "repository"):
                        if _tainted(arguments.get(key), heads | inputs, step_env, _pr_head):
                            emit("AH001", arguments, key)
                            unsafe_checkout = True
                            break
            if (triggers & {"pull_request_target", "workflow_run"} or arguments.get("restore-keys")) and (
                action in {"actions/cache", "actions/cache/restore", "actions/cache/save"}
                or (action == "actions/setup-node" and arguments.get("cache"))
            ):
                emit("AH006", step, "uses")
            if action in ARTIFACT_ACTIONS:
                if privileged_run:
                    emit("AH011", step, "uses")
                elif "pull_request_target" in triggers or {"run-id", "repository"} & arguments.keys():
                    emit("AH007", step, "uses")

            script = arguments.get("script")
            if (privileged_run and action == "actions/github-script" and isinstance(script, str)
                    and API_ARTIFACT_DOWNLOAD.search(script)):
                emit("AH011", arguments, "script")

            unsafe_checkout = self.call(
                uses, step is not job_call, arguments, triggers, permissions, inputs, heads,
                step_env, stack, has_secrets, unsafe_checkout, job_has_secrets,
            )
        return unsafe_checkout

    def call(self, uses, composite, arguments, triggers, permissions, inputs, heads,
             env, stack, secrets, unsafe_checkout, job_has_secrets):
        target = self.target(uses, composite)
        if target is None or target in stack or len(stack) >= 20:
            return unsafe_checkout
        called, emit = self.load(target)
        if called is None:
            return unsafe_checkout
        config = called if composite else _map(_map(called.get("on")).get("workflow_call"))
        bindings = {str(key).lower(): _map(value).get("default")
                    for key, value in _map(config.get("inputs")).items()}
        bindings.update((str(key).lower(), value) for key, value in arguments.items())
        supplied_inputs = frozenset(key for key, value in bindings.items() if _tainted(value, inputs, env))
        supplied_heads = frozenset(key for key, value in bindings.items()
                                   if _tainted(value, heads, set(), _pr_head))
        if not composite:
            self.workflow(target, triggers, permissions, supplied_inputs, supplied_heads, stack,
                          secrets=secrets)
            return unsafe_checkout
        runs = _map(called.get("runs"))
        if runs.get("using") != "composite":
            return unsafe_checkout
        return self.steps(
            emit, _items(runs.get("steps")), triggers, permissions, supplied_inputs, supplied_heads,
            env, stack | {target}, secrets, unsafe_checkout, job_has_secrets=job_has_secrets,
        )


def _gitlab(doc, emit):
    for include_definition in _items(doc.get("include")):
        include = _map(include_definition)
        if (("project" in include and not SHA.fullmatch(str(include.get("ref", ""))))
                or ("remote" in include and not re.fullmatch(
                    r"sha256-[A-Za-z0-9+/]{43}=", str(include.get("integrity", ""))
                ))):
            emit("AH016", include, "project" if "project" in include else "remote")
        elif isinstance(include_definition, str) and include_definition.startswith(("https://", "http://")):
            emit("AH016", doc, "include")

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
                    emit("AH018", owner, "cache")
            break
        for key in ("before_script", "script", "after_script"):
            owner = job if key in job else default if key in default else doc
            for script in _items(owner.get(key)):
                if isinstance(script, str) and re.search(
                    r"""\b(?:eval|(?:ba)?sh\s+-c)\s+["']?\$(?:\{)?CI_MERGE_REQUEST_""", script
                ):
                    emit("AH017", owner, key)
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
    lines = source.splitlines()
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
                ((number, text.index(marker) + 1) for number, text in enumerate(lines, 1)
                 if marker in text),
                (1, 1),
            )
            findings.add(Finding(relative, line, column, "AH008", lines[line - 1]))
    return sorted(findings)


def scan(root: Path | str, trust_policies=(), *, protected_environments=()) -> list[Finding]:
    """Return deterministic, path-relative findings or raise ScanError."""
    root = Path(root).resolve()
    if not root.is_dir():
        raise ScanError(f"Not a directory: {root}")
    workflows = root / ".github" / "workflows"
    gitlab = root / ".gitlab-ci.yml"
    findings = set()
    documents = {}

    def load(path):
        if path in documents:
            return documents[path]
        relative = path.relative_to(root).as_posix()
        try:
            source = path.read_text(encoding="utf-8")
            lines = source.splitlines()
            doc = _load(source)
        except (UnicodeError, OSError, yaml.YAMLError, RecursionError) as exc:
            raise ScanError(f"{relative}: {exc}") from exc
        if doc is not None and not isinstance(doc, dict):
            raise ScanError(f"{relative}: expected a YAML mapping")

        def emit(rule, owner, key):
            line, column = getattr(owner, "marks", {}).get(key, (1, 1))
            source_line = lines[line - 1] if line <= len(lines) else ""
            findings.add(Finding(relative, line, column, rule, source_line))

        documents[path] = doc, emit
        _oidc(doc, emit, set())
        return doc, emit

    graph = GitHubScan(root, load, protected_environments)
    callable_only = []
    for path in sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml"), gitlab]):
        if not path.is_file() or not path.resolve().is_relative_to(root):
            continue
        doc, emit = load(path)
        if doc is None:
            continue
        if path == gitlab:
            _gitlab(doc, emit)
        elif _triggers(doc) == {"workflow_call"}:
            callable_only.append(path)
        else:
            graph.workflow(path)
    # Check disconnected callable workflows too. Do not discard caller permission caps
    # by scanning bodies that already have a reachable calling context a second time.
    for path in callable_only:
        if path.resolve() not in graph.visited:
            graph.workflow(path)
    for policy in trust_policies:
        path = (root / policy).resolve()
        if not path.is_relative_to(root):
            raise ScanError(f"Trust policy is outside the scan root: {policy}")
        findings.update(scan_oidc(path, root))
    return sorted(findings)

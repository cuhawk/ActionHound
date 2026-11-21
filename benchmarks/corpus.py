"""Independently labeled, synthetic CI configurations. Never execute these files."""

from dataclasses import dataclass
from pathlib import Path

import yaml

WORKFLOW = ".github/workflows/main.yml"
REUSABLE = ".github/workflows/report.yml"
COMPOSITE = ".github/actions/report/action.yml"
GITLAB = ".gitlab-ci.yml"
SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
PR_TITLE = "${{ github.event.pull_request.title }}"
PR_HEAD = "${{ github.event.pull_request.head.sha }}"
INPUT = "${{ inputs.message }}"
PROTECTED = ("production",)
WORKFLOW_RUN = {"workflow_run": {"workflows": ["Build"], "types": ["completed"]}}


@dataclass(frozen=True)
class Fixture:
    name: str
    files: dict
    expected: tuple

    def write(self, root: Path):
        for name, document in self.files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def job(*steps, **settings):
    return {"runs-on": "ubuntu-latest", "steps": list(steps) or [{"run": "echo ok"}], **settings}


def github(definition, event="push", **settings):
    return {"on": event, "permissions": {"contents": "read"}, **settings, "jobs": {"check": definition}}


def checkout(**inputs):
    return {"uses": f"actions/checkout@{SHA}", "with": inputs}


def action(name, ref=SHA, **settings):
    return {"uses": f"{name}@{ref}", **settings}


def gitlab_job(**settings):
    return {"build": {"script": ["echo ok"], **settings}}


def pair(name, path, failing, hardened, *rules, bad_files=None, clean_files=None, sink=None):
    return (
        Fixture(f"{name}-noncompliant", {path: failing, **(bad_files or {})},
                tuple((sink or path, rule) for rule in rules)),
        Fixture(f"{name}-hardened", {path: hardened, **(clean_files or {})}, ()),
    )


def github_pairs():
    for name, bad, good in (
        ("container-scalar", "node:22", f"node@{DIGEST}"),
        ("container-object", {"image": "registry.example:5000/team/base:main"},
         {"image": f"registry.example:5000/team/base@{DIGEST}"}),
        ("container-implicit-tag", "alpine", f"alpine@{DIGEST}"),
    ):
        yield from pair(name, WORKFLOW, github(job(container=bad)), github(job(container=good)), "AH010")
    for action_name in ("actions/download-artifact", "dawidd6/action-download-artifact"):
        yield from pair(
            action_name.replace("/", "-"), WORKFLOW,
            github(job(action(action_name), permissions={"contents": "write"}), WORKFLOW_RUN),
            github(job(action(action_name), permissions={"actions": "read"}), WORKFLOW_RUN), "AH011",
        )
    yield from pair(
        "artifact-secrets", WORKFLOW,
        github(job(action("actions/download-artifact"), {"run": "echo auditing"},
                   env={"REPORT_TOKEN": "${{ secrets.REPORT_TOKEN }}"}), WORKFLOW_RUN),
        github(job(action("actions/download-artifact")), WORKFLOW_RUN), "AH011",
    )
    for variable in ("GITHUB_ENV", "GITHUB_PATH"):
        yield from pair(
            variable.lower(), WORKFLOW,
            github(job({"run": f'printf "%s\\n" "$TEXT" >> "${variable}"',
                        "env": {"TEXT": PR_TITLE}}), "pull_request"),
            github(job({"run": f'printf "%s\\n" "$TEXT" >> "${variable}"',
                        "env": {"TEXT": "trusted-fixed-value"}}), "pull_request"), "AH012",
        )
    yield from pair(
        "environment-file-tee", WORKFLOW,
        github(job({"run": f'printf "LABEL=%s\\n" "{PR_TITLE}" | tee -a "$GITHUB_ENV"'}), "pull_request"),
        github(job({"run": 'printf "LABEL=%s\\n" "verified" | tee -a "$GITHUB_ENV"'}), "pull_request"),
        "AH002", "AH012",
    )
    yield from pair(
        "checkout-default", WORKFLOW, github(job({"uses": f"actions/checkout@{SHA}"})),
        github(job(checkout(**{"persist-credentials": False}))), "AH013",
    )
    yield from pair(
        "checkout-explicit", WORKFLOW, github(job(checkout(**{"persist-credentials": True}))),
        github(job(checkout(**{"persist-credentials": False}))), "AH013",
    )
    yield from pair(
        "third-party-ref", WORKFLOW, github(job(action("example/publish", "release"))),
        github(job(action("example/publish"))), "AH014",
    )
    yield from pair(
        "first-party-ref", WORKFLOW, github(job(action("actions/setup-node", "v4"))),
        github(job(action("actions/setup-node"))), "AH003",
    )
    yield from pair(
        "docker-ref", WORKFLOW, github(job({"uses": "docker://registry.example/check:latest"})),
        github(job({"uses": f"docker://registry.example/check@{DIGEST}"})), "AH003",
    )
    oidc = {"id-token": "write"}
    yield from pair(
        "oidc-root", WORKFLOW, github(job(), permissions=oidc),
        github(job(environment="production", permissions=oidc)), "AH015",
    )
    yield from pair(
        "oidc-job", WORKFLOW, github(job(environment={"name": "staging"}, permissions=oidc)),
        github(job(environment={"name": "production"}, permissions=oidc)), "AH015",
    )
    yield from pair(
        "write-all", WORKFLOW, github(job(permissions="write-all")), github(job()), "AH004", "AH015",
    )
    yield from pair(
        "untrusted-checkout", WORKFLOW,
        github(job(checkout(ref=PR_HEAD, **{"persist-credentials": False})), "pull_request_target"),
        github(job(checkout(**{"persist-credentials": False})), "pull_request_target"), "AH001",
    )
    yield from pair(
        "cache-trust", WORKFLOW,
        github(job(action("actions/cache", **{"with": {"path": ".cache", "key": "shared"}})),
               "pull_request_target"),
        github(job(action("actions/cache", **{"with": {"path": ".cache", "key": "trusted"}})),
               "push"), "AH006",
    )
    yield from pair(
        "mutable-secret-action", WORKFLOW,
        github(job(action("example/report", "main", env={"TOKEN": "${{ secrets.REPORT }}"}))),
        github(job(action("example/report", env={"TOKEN": "${{ secrets.REPORT }}"}))),
        "AH005", "AH014",
    )
    yield from pair(
        "dispatch-input", WORKFLOW,
        github(job({"run": f'printf "%s" "{INPUT}"'}),
               {"workflow_dispatch": {"inputs": {"message": {"type": "string"}}}}),
        github(job({"run": 'printf "%s" "$MESSAGE"', "env": {"MESSAGE": INPUT}}),
               {"workflow_dispatch": {"inputs": {"message": {"type": "string"}}}}), "AH002",
    )
    declaration = {"workflow_call": {"inputs": {"message": {"type": "string"}}}}
    report = github(job({"run": f'printf "%s" "{INPUT}"'}), declaration)
    yield from pair(
        "workflow-input", WORKFLOW,
        github({"uses": "./" + REUSABLE, "with": {"message": PR_TITLE}}, "pull_request"),
        github({"uses": "./" + REUSABLE, "with": {"message": "fixed"}}, "pull_request"),
        "AH002", bad_files={REUSABLE: report}, clean_files={REUSABLE: report}, sink=REUSABLE,
    )
    composite = {
        "name": "Report", "description": "Emit a label",
        "inputs": {"message": {"description": "Label"}},
        "runs": {"using": "composite", "steps": [
            {"run": f'printf "%s" "{INPUT}"', "shell": "bash"},
        ]},
    }
    yield from pair(
        "composite-input", WORKFLOW,
        github(job(checkout(**{"persist-credentials": False}),
                   {"uses": "./.github/actions/report", "with": {"message": PR_TITLE}}), "pull_request"),
        github(job(checkout(**{"persist-credentials": False}),
                   {"uses": "./.github/actions/report", "with": {"message": "fixed"}}), "pull_request"),
        "AH002", bad_files={COMPOSITE: composite}, clean_files={COMPOSITE: composite}, sink=COMPOSITE,
    )
    # The callee has no explicit permissions and inherits the caller's ceiling.
    callee = {"on": declaration, "jobs": {"inspect": job(action("actions/download-artifact"))}}
    yield from pair(
        "workflow-artifact-permissions", WORKFLOW,
        github({"uses": "./" + REUSABLE, "permissions": {"contents": "write"}}, WORKFLOW_RUN),
        github({"uses": "./" + REUSABLE, "permissions": {"actions": "read"}}, WORKFLOW_RUN),
        "AH011", bad_files={REUSABLE: callee}, clean_files={REUSABLE: callee}, sink=REUSABLE,
    )


def gitlab_pairs():
    yield from pair(
        "gitlab-project-include", GITLAB,
        {**gitlab_job(), "include": [{"project": "example/ci", "file": "build.yml", "ref": "main"}]},
        {**gitlab_job(), "include": [{"project": "example/ci", "file": "build.yml", "ref": SHA}]}, "AH016",
    )
    url = "https://example.invalid/build.yml"
    yield from pair(
        "gitlab-remote-include", GITLAB, {**gitlab_job(), "include": url},
        {**gitlab_job(), "include": {"remote": url, "integrity": "sha256-" + "A" * 43 + "="}}, "AH016",
    )
    for key in ("default", "$CI_PROJECT_NAME"):
        yield from pair(
            f"gitlab-cache-{key}", GITLAB, gitlab_job(cache={"key": key}),
            gitlab_job(cache={"key": "$CI_COMMIT_REF_SLUG"}), "AH018",
        )
    yield from pair(
        "gitlab-cache-unprotect", GITLAB,
        gitlab_job(only=["merge_requests"], cache={"key": "$CI_COMMIT_REF_SLUG", "unprotect": True}),
        gitlab_job(only=["merge_requests"], cache={"key": "$CI_COMMIT_REF_SLUG", "policy": "pull"}),
        "AH006",
    )
    yield from pair(
        "gitlab-mr-reevaluation", GITLAB,
        gitlab_job(only=["merge_requests"], script=['sh -c "$CI_MERGE_REQUEST_TITLE"']),
        gitlab_job(only=["merge_requests"], script=['printf "%s" "$CI_MERGE_REQUEST_TITLE"']), "AH017",
    )
    yield from pair(
        "gitlab-artifact-project", GITLAB,
        gitlab_job(needs=[{"project": "example/ci", "job": "build", "ref": "main", "artifacts": True}]),
        {**gitlab_job(stage="deploy", needs=[{"job": "test", "artifacts": True}]),
         "test": {"stage": "test", "script": ["echo test"]}}, "AH007",
    )
    yield from pair(
        "gitlab-oidc-subject", GITLAB,
        {**gitlab_job(), "variables": {"oidc_subject": "project_path:example/*"}},
        {**gitlab_job(), "variables": {"oidc_subject": "project_path:example/ci:ref_type:branch:ref:main"}},
        "AH008",
    )


FIXTURES = (*github_pairs(), *gitlab_pairs())

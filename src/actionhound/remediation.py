"""Generate reviewable YAML patches using caller-supplied immutable references."""

import json
from collections import defaultdict
from difflib import unified_diff
from pathlib import Path

import yaml

from .scanner import DIGEST, SHA, ScanError, WorkflowLoader

PIN_RULES = {"AH003", "AH010", "AH014"}


def load_pin_map(path):
    if path is None:
        return {}
    try:
        pins = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, OSError, ValueError) as exc:
        raise ScanError(f"Pin map {path}: {exc}") from exc
    if not isinstance(pins, dict) or not all(isinstance(pin, str) for pin in pins.values()):
        raise ScanError("Pin map must be a JSON object mapping references to SHA strings")
    return pins


def _pinned_reference(value, pin, rule):
    if rule == "AH010" or value.startswith("docker://"):
        if not DIGEST.fullmatch("@" + pin):
            raise ScanError(f"Expected a SHA-256 digest for {value}")
        image = value.split("@", 1)[0]
        name, slash, basename = image.rpartition("/")
        return f"{name}{slash}{basename.split(':', 1)[0]}@{pin}"
    if not SHA.fullmatch(pin):
        raise ScanError(f"Expected a full commit SHA for {value}")
    return f"{value.split('@', 1)[0]}@{pin}"


def _location(node):
    mark = node.start_mark
    return mark.line + 1, mark.column + 1


def _children(node):
    if isinstance(node, yaml.MappingNode):
        return [child for pair in node.value for child in pair]
    if isinstance(node, yaml.SequenceNode):
        return node.value
    return []


def _locations(root):
    # Composed aliases share nodes. Exclude shared nodes and their descendants
    # so changing an anchor cannot silently change another field.
    seen = set()
    aliases = []
    locations = {}
    pending = [root]
    while pending:
        node = pending.pop()
        if id(node) in seen:
            aliases.append(node)
            continue
        seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                locations[_location(value)] = key.value, value
        pending.extend(_children(node))

    shared = set()
    while aliases:
        node = aliases.pop()
        if id(node) not in shared:
            shared.add(id(node))
            aliases.extend(_children(node))
    return {location: (key, node) for location, (key, node) in locations.items()
            if id(node) not in shared}


def _edits(doc, findings, pins):
    locations = _locations(doc)
    for finding in findings:
        key, node = locations.get((finding.line, finding.column), (None, None))
        if (finding.rule_id in PIN_RULES and isinstance(node, yaml.ScalarNode)
                and node.value in pins):
            yield node, json.dumps(_pinned_reference(node.value, pins[node.value], finding.rule_id))
        elif key == "permissions":
            if (finding.rule_id == "AH004" and isinstance(node, yaml.ScalarNode)
                    and node.value == "write-all"):
                yield node, "{contents: read}"
            elif finding.rule_id == "AH015" and isinstance(node, yaml.MappingNode):
                for scope, value in node.value:
                    if (scope.value == "id-token" and value.value == "write"
                            and locations.get(_location(value)) == ("id-token", value)):
                        yield value, "none"


def emit_diff(root, findings, pins):
    """Return a unified diff without modifying the scanned files."""
    by_path = defaultdict(list)
    for finding in findings:
        if finding.rule_id in PIN_RULES | {"AH004", "AH015"}:
            by_path[finding.path].append(finding)
    patch = []
    root = Path(root).resolve()
    for path, applicable in sorted(by_path.items()):
        source = root / path
        if source.resolve() != source:
            continue
        try:
            with source.open(encoding="utf-8", newline="") as stream:
                original = stream.read()
            doc = yaml.compose(original, Loader=WorkflowLoader)
        except (UnicodeError, yaml.YAMLError) as exc:
            raise ScanError(f"{path}: {exc}") from exc
        edits = {
            (node.start_mark.index, node.end_mark.index): replacement
            for node, replacement in _edits(doc, applicable, pins)
            if node.start_mark.line == node.end_mark.line and "&" not in original[
                node.start_mark.index:node.end_mark.index
            ]
        }
        updated = original
        for (start, end), replacement in sorted(edits.items(), reverse=True):
            updated = updated[:start] + replacement + updated[end:]
        if updated != original:
            diff = unified_diff(original.splitlines(keepends=True), updated.splitlines(keepends=True),
                                fromfile=f"a/{path}", tofile=f"b/{path}")
            patch.extend(
                line if line.endswith("\n") else line + "\n\\ No newline at end of file\n"
                for line in diff
            )
    return "".join(patch)

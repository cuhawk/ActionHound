import argparse
import json
from pathlib import Path

import yaml

from .sarif import LEVELS, markdown, serialize
from .scanner import scan


def main():
    parser = argparse.ArgumentParser(prog="actionhound")
    sub = parser.add_subparsers(required=True)
    command = sub.add_parser("scan")
    command.add_argument("directory", type=Path)
    command.add_argument("--sarif", type=Path)
    command.add_argument("--trust-policy", type=Path, action="append", default=[])
    command.add_argument("--fail-on", choices=LEVELS)
    args = parser.parse_args()
    if not args.directory.is_dir():
        parser.error("scan directory does not exist")
    try:
        findings = scan(args.directory, args.trust_policy)
        if args.sarif:
            args.sarif.write_text(json.dumps(serialize(findings), indent=2) + "\n")
    except (ValueError, OSError, yaml.YAMLError) as exc:
        parser.exit(2, f"actionhound: {exc}\n")
    print(markdown(findings))
    order = {"low": 1, "medium": 2, "high": 3}
    return int(bool(args.fail_on and any(
        order[item.severity] >= order[args.fail_on] for item in findings
    )))

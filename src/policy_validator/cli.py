"""CLI entry point for policy_validator."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .checker import Checker, ConfigLoadError, severity_counts
from .rules import Severity


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="policy-validator",
        description="Detect security misconfigurations in JSON/YAML config files.",
    )
    parser.add_argument("files", nargs="+", metavar="FILE", help="Config files to check")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "never"),
        default="HIGH",
        help="Exit with code 1 if a finding meets or exceeds this severity (default: HIGH)",
    )
    parser.add_argument(
        "--min-severity",
        choices=("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"),
        default="INFO",
        help="Only show findings at this severity or above (default: INFO)",
    )
    return parser


def severity_order(sev: Severity) -> int:
    return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(sev.value)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    checker = Checker()
    all_findings = []
    errors = []

    for filepath in args.files:
        try:
            findings = checker.check_file(Path(filepath))
            for f in findings:
                all_findings.append({"file": filepath, "finding": f})
        except ConfigLoadError as exc:
            errors.append(str(exc))

    min_sev = Severity(args.min_severity)
    filtered = [
        item for item in all_findings if severity_order(item["finding"].severity) <= severity_order(min_sev)
    ]

    if args.format == "json":
        output = {
            "files_checked": args.files,
            "findings": [{"file": item["file"], **item["finding"].as_dict()} for item in filtered],
            "errors": errors,
            "summary": severity_counts([item["finding"] for item in all_findings]),
        }
        print(json.dumps(output, indent=2))
    else:
        if errors:
            for err in errors:
                print(f"ERROR: {err}", file=sys.stderr)
        for item in filtered:
            f = item["finding"]
            print(f"[{f.severity.value}] {item['file']} | {f.rule_id} | {f.message}")
        counts = severity_counts([item["finding"] for item in all_findings])
        print("\nSummary: " + ", ".join(f"{k}={v}" for k, v in counts.items() if v > 0) or "No findings.")

    if errors:
        return 2

    if args.fail_on != "never":
        threshold = Severity(args.fail_on)
        for item in all_findings:
            if severity_order(item["finding"].severity) <= severity_order(threshold):
                return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

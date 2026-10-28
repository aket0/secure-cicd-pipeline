"""Core checker: load a config file and apply all security rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .rules import ALL_RULES, Finding, Severity

try:
    import yaml  # type: ignore[import-untyped]

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


class ConfigLoadError(Exception):
    pass


class Checker:
    """Run all security rules against a configuration dict."""

    def __init__(self, rules: list | None = None) -> None:
        self._rules = rules if rules is not None else ALL_RULES

    def check_dict(self, config: dict) -> list[Finding]:
        if not isinstance(config, dict):
            raise TypeError(f"Expected dict, got {type(config).__name__}")
        findings: list[Finding] = []
        for rule in self._rules:
            findings.extend(rule(config))
        return findings

    def check_file(self, path: Path | str) -> list[Finding]:
        config = load_config(path)
        return self.check_dict(config)

    def check_dict_blocking(self, config: dict, min_severity: Severity = Severity.HIGH) -> bool:
        """Return True if any finding meets or exceeds min_severity."""
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        threshold_idx = order.index(min_severity)
        for finding in self.check_dict(config):
            if order.index(finding.severity) <= threshold_idx:
                return True
        return False


def load_config(path: Path | str) -> dict[str, Any]:
    path = Path(path)
    if not path.exists():
        raise ConfigLoadError(f"File not found: {path}")
    suffix = path.suffix.lower()
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigLoadError(f"Cannot read {path}: {exc}") from exc

    if suffix in (".json",):
        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            raise ConfigLoadError(f"Invalid JSON in {path}: {exc}") from exc

    if suffix in (".yml", ".yaml"):
        if not _YAML_AVAILABLE:
            raise ConfigLoadError("PyYAML is not installed. Install it: pip install pyyaml")
        try:
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                raise ConfigLoadError(f"YAML root must be a mapping, got {type(data).__name__}")
            return data
        except yaml.YAMLError as exc:
            raise ConfigLoadError(f"Invalid YAML in {path}: {exc}") from exc

    raise ConfigLoadError(f"Unsupported file format: {suffix}. Use .json, .yml or .yaml")


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts

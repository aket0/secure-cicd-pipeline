"""Integration tests for the Checker class."""

import pytest

from policy_validator.checker import Checker, ConfigLoadError, severity_counts
from policy_validator.rules import Severity


class TestCheckerDict:
    def test_insecure_config_produces_findings(self, insecure_config):
        checker = Checker()
        findings = checker.check_dict(insecure_config)
        assert len(findings) > 0

    def test_secure_config_no_blocking_findings(self, secure_config):
        checker = Checker()
        findings = checker.check_dict(secure_config)
        blocking = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert blocking == []

    def test_invalid_input_raises(self):
        checker = Checker()
        with pytest.raises(TypeError):
            checker.check_dict("not a dict")  # type: ignore[arg-type]

    def test_blocking_insecure(self, insecure_config):
        checker = Checker()
        assert checker.check_dict_blocking(insecure_config, Severity.HIGH) is True

    def test_blocking_secure(self, secure_config):
        checker = Checker()
        assert checker.check_dict_blocking(secure_config, Severity.HIGH) is False


class TestCheckerFile:
    def test_load_json_file(self, insecure_config_file):
        checker = Checker()
        findings = checker.check_file(insecure_config_file)
        assert len(findings) > 0

    def test_missing_file_raises(self, tmp_path):
        checker = Checker()
        with pytest.raises(ConfigLoadError, match="not found"):
            checker.check_file(tmp_path / "nonexistent.json")

    def test_invalid_json_raises(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{this is not valid json")
        checker = Checker()
        with pytest.raises(ConfigLoadError, match="Invalid JSON"):
            checker.check_file(bad)

    def test_unsupported_extension_raises(self, tmp_path):
        f = tmp_path / "config.toml"
        f.write_text("[section]\nkey = 'value'")
        checker = Checker()
        with pytest.raises(ConfigLoadError, match="Unsupported"):
            checker.check_file(f)

    def test_secure_config_file_no_blocking(self, secure_config_file):
        checker = Checker()
        findings = checker.check_file(secure_config_file)
        blocking = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert blocking == []


class TestSeverityCounts:
    def test_counts_correctly(self, insecure_config):
        checker = Checker()
        findings = checker.check_dict(insecure_config)
        counts = severity_counts(findings)
        assert sum(counts.values()) == len(findings)
        assert counts.get("CRITICAL", 0) > 0

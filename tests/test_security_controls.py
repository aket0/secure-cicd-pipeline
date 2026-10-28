"""
Tests verifying that security controls BLOCK known-bad inputs.

These tests prove the pipeline gate works: if a dangerous configuration
reaches production, the check would have caught it.
"""

import pytest

from policy_validator.checker import Checker
from policy_validator.rules import Severity

CHECKER = Checker()


class TestBlockingControls:
    """Each test documents a control and proves it blocks the bad case."""

    def test_blocks_debug_mode_in_production(self):
        """SEC-001: Debug mode exposes internals; pipeline must reject it."""
        config = {"debug": True, "host": "127.0.0.1"}
        assert CHECKER.check_dict_blocking(config, Severity.HIGH), (
            "Pipeline should block: debug=True is a HIGH finding"
        )

    def test_blocks_disabled_tls(self):
        """SEC-003: Plaintext traffic; any production config disabling TLS must be rejected."""
        config = {"tls_disabled": True}
        assert CHECKER.check_dict_blocking(config, Severity.CRITICAL), (
            "Pipeline should block: tls_disabled=True is a CRITICAL finding"
        )

    def test_blocks_weak_password(self):
        """SEC-005: Default credentials; pipeline must reject common passwords."""
        for bad_pw in ("admin", "password", "123456", "root", ""):
            config = {"password": bad_pw}
            assert CHECKER.check_dict_blocking(config, Severity.CRITICAL), (
                f"Pipeline should block: password='{bad_pw}' is a CRITICAL finding"
            )

    def test_blocks_insecure_tls_version(self):
        """SEC-004: TLS 1.0/1.1 are deprecated; pipeline must reject them."""
        for version in ("TLSv1", "TLSv1.0", "TLSv1.1"):
            config = {"tls": {"min_version": version}}
            assert CHECKER.check_dict_blocking(config, Severity.HIGH), (
                f"Pipeline should block: TLS min_version='{version}' is a HIGH finding"
            )

    def test_does_not_block_secure_config(self):
        """A properly hardened config must pass the HIGH-severity gate."""
        secure = {
            "debug": False,
            "host": "127.0.0.1",
            "tls": {"enabled": True, "min_version": "TLSv1.2"},
            "password": "${DB_PASSWORD}",
            "secret_key": "${APP_SECRET}",
            "logging": {"level": "INFO"},
            "rate_limit": {"enabled": True},
        }
        assert not CHECKER.check_dict_blocking(secure, Severity.HIGH), (
            "A correctly hardened config must not trigger a blocking finding"
        )

    def test_false_positive_env_variable_password(self):
        """Passwords referencing env variables must not trigger SEC-005."""
        config = {"password": "${DB_PASSWORD}"}
        findings = CHECKER.check_dict(config)
        rule_005 = [f for f in findings if f.rule_id == "SEC-005"]
        assert rule_005 == [], "Password referencing ${ENV_VAR} must not be flagged as weak credential"

    def test_false_positive_env_variable_api_key(self):
        """API keys referencing env variables must not trigger SEC-006."""
        config = {"api_key": "${MY_API_KEY}"}
        findings = CHECKER.check_dict(config)
        rule_006 = [f for f in findings if f.rule_id == "SEC-006"]
        assert rule_006 == [], "api_key referencing ${ENV_VAR} must not be flagged as hardcoded secret"


class TestFindingSeverityHierarchy:
    """Verify severity levels are correctly assigned per rule."""

    @pytest.mark.parametrize(
        "config,expected_severity",
        [
            ({"tls_disabled": True}, Severity.CRITICAL),
            ({"password": "admin"}, Severity.CRITICAL),
            ({"debug": True}, Severity.HIGH),
            ({"tls": {"min_version": "TLSv1.1"}}, Severity.HIGH),
            ({"host": "0.0.0.0"}, Severity.MEDIUM),
            ({"logging": {"level": "DEBUG"}}, Severity.MEDIUM),
        ],
    )
    def test_severity_assigned(self, config, expected_severity):
        findings = CHECKER.check_dict(config)
        severities = {f.severity for f in findings}
        assert expected_severity in severities, (
            f"Expected {expected_severity.value} in findings for config {config}, got {severities}"
        )

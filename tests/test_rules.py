"""Unit tests for individual security rules."""

import pytest

from policy_validator.rules import (
    Severity,
    check_bind_address,
    check_debug_mode,
    check_hardcoded_secrets,
    check_logging,
    check_rate_limiting,
    check_tls,
    check_weak_credentials,
)


class TestDebugMode:
    def test_debug_true_flagged(self):
        findings = check_debug_mode({"debug": True})
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-001"
        assert findings[0].severity == Severity.HIGH

    def test_debug_string_true_flagged(self):
        findings = check_debug_mode({"DEBUG": "true"})
        assert any(f.rule_id == "SEC-001" for f in findings)

    def test_debug_false_clean(self):
        findings = check_debug_mode({"debug": False})
        assert findings == []

    def test_no_debug_key_clean(self):
        findings = check_debug_mode({"host": "localhost"})
        assert findings == []


class TestBindAddress:
    def test_all_interfaces_flagged(self):
        findings = check_bind_address({"host": "0.0.0.0"})
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-002"
        assert findings[0].severity == Severity.MEDIUM

    def test_ipv6_any_flagged(self):
        findings = check_bind_address({"bind": "::"})
        assert len(findings) == 1

    def test_localhost_clean(self):
        assert check_bind_address({"host": "127.0.0.1"}) == []

    def test_specific_ip_clean(self):
        assert check_bind_address({"host": "192.168.1.10"}) == []


class TestTLS:
    def test_tls_disabled_flag_critical(self):
        findings = check_tls({"tls_disabled": True})
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_tls_block_disabled_critical(self):
        findings = check_tls({"tls": {"enabled": False}})
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_tls_v1_flagged(self):
        findings = check_tls({"tls": {"enabled": True, "min_version": "TLSv1.0"}})
        assert any(f.rule_id == "SEC-004" for f in findings)

    def test_tls_v11_flagged(self):
        findings = check_tls({"tls": {"min_version": "TLSv1.1"}})
        assert any(f.rule_id == "SEC-004" for f in findings)

    def test_tls_v12_clean(self):
        findings = check_tls({"tls": {"enabled": True, "min_version": "TLSv1.2"}})
        assert findings == []

    def test_no_tls_key_clean(self):
        assert check_tls({"host": "localhost"}) == []


class TestWeakCredentials:
    @pytest.mark.parametrize(
        "password",
        [
            "admin",
            "password",
            "123456",
            "secret",
            "changeme",
            "root",
            "",
        ],
    )
    def test_weak_password_critical(self, password):
        findings = check_weak_credentials({"password": password})
        assert any(f.rule_id == "SEC-005" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_strong_password_clean(self):
        findings = check_weak_credentials({"password": "xK#9mP!vQ2@rN"})
        assert findings == []

    def test_env_variable_reference_clean(self):
        findings = check_weak_credentials({"password": "${DB_PASSWORD}"})
        assert findings == []

    def test_redacts_value_in_finding(self):
        findings = check_weak_credentials({"password": "admin"})
        assert all(f.value != "admin" for f in findings)


class TestHardcodedSecrets:
    def test_hardcoded_api_key_flagged(self):
        findings = check_hardcoded_secrets({"api_key": "sk-abcd1234efgh5678"})
        assert any(f.rule_id == "SEC-006" for f in findings)

    def test_env_variable_clean(self):
        findings = check_hardcoded_secrets({"api_key": "${API_KEY}"})
        assert findings == []

    def test_subshell_reference_clean(self):
        findings = check_hardcoded_secrets({"token": "$(vault read secret/token)"})
        assert findings == []


class TestLogging:
    def test_no_logging_config_info(self):
        findings = check_logging({"host": "localhost"})
        assert any(f.rule_id == "SEC-007" for f in findings)

    def test_debug_log_level_medium(self):
        findings = check_logging({"logging": {"level": "DEBUG"}})
        assert any(f.rule_id == "SEC-008" and f.severity == Severity.MEDIUM for f in findings)

    def test_info_log_level_clean(self):
        findings = check_logging({"logging": {"level": "INFO"}})
        assert findings == []


class TestRateLimiting:
    def test_no_rate_limit_info(self):
        findings = check_rate_limiting({"host": "localhost"})
        assert any(f.rule_id == "SEC-009" for f in findings)

    def test_rate_limit_present_clean(self):
        findings = check_rate_limiting({"rate_limit": {"enabled": True}})
        assert findings == []

"""Security rules applied to configuration files."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    field: str
    value: Any = None

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "field": self.field,
            "value": str(self.value) if self.value is not None else None,
        }


_WEAK_PASSWORDS = frozenset(
    {
        "",
        "password",
        "password1",
        "123456",
        "admin",
        "root",
        "secret",
        "changeme",
        "default",
        "test",
        "guest",
    }
)

_CREDENTIAL_PATTERN = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)\s*[:=]\s*\S+",
)


def check_debug_mode(config: dict) -> list[Finding]:
    findings = []
    for key in ("debug", "DEBUG", "dev_mode", "development"):
        val = config.get(key)
        if val is True or val == "true" or val == 1:
            findings.append(
                Finding(
                    rule_id="SEC-001",
                    severity=Severity.HIGH,
                    message=(
                        f"Debug/development mode is enabled via '{key}'. Must be disabled in production."
                    ),
                    field=key,
                    value=val,
                )
            )
    return findings


def check_bind_address(config: dict) -> list[Finding]:
    findings = []
    bind_keys = ("host", "bind", "listen", "bind_address", "server_host")
    for key in bind_keys:
        val = config.get(key)
        if val in ("0.0.0.0", "::"):  # nosec B104  # noqa: S104
            findings.append(
                Finding(
                    rule_id="SEC-002",
                    severity=Severity.MEDIUM,
                    message=(
                        f"Service bound to '{val}' via '{key}'. "
                        "Restrict to a specific interface unless publicly intended."
                    ),
                    field=key,
                    value=val,
                )
            )
    return findings


def check_tls(config: dict) -> list[Finding]:
    findings = []
    tls_disabled_keys = ("tls_disabled", "ssl_disabled", "insecure", "no_tls", "disable_tls")
    for key in tls_disabled_keys:
        val = config.get(key)
        if val is True or val == "true" or val == 1:
            findings.append(
                Finding(
                    rule_id="SEC-003",
                    severity=Severity.CRITICAL,
                    message=(
                        f"TLS/SSL is explicitly disabled via '{key}'."
                        " All traffic is transmitted in clear text."
                    ),
                    field=key,
                    value=val,
                )
            )

    tls_block = config.get("tls") or config.get("ssl") or {}
    if isinstance(tls_block, dict):
        if tls_block.get("enabled") is False:
            findings.append(
                Finding(
                    rule_id="SEC-003",
                    severity=Severity.CRITICAL,
                    message="TLS block is present but disabled (tls.enabled = false).",
                    field="tls.enabled",
                    value=False,
                )
            )
        min_ver = tls_block.get("min_version") or tls_block.get("minimum_version")
        if min_ver in ("TLSv1", "TLSv1.0", "TLSv1.1", "1.0", "1.1"):
            findings.append(
                Finding(
                    rule_id="SEC-004",
                    severity=Severity.HIGH,
                    message=f"Minimum TLS version '{min_ver}' is insecure. Use TLS 1.2 or higher.",
                    field="tls.min_version",
                    value=min_ver,
                )
            )
    return findings


def check_weak_credentials(config: dict) -> list[Finding]:
    findings = []
    credential_keys = (
        "password",
        "passwd",
        "db_password",
        "admin_password",
        "secret",
        "secret_key",
        "api_key",
        "token",
    )
    for key in credential_keys:
        val = config.get(key)
        if val is None:
            continue
        if not isinstance(val, str):
            continue
        if val.lower() in _WEAK_PASSWORDS:
            findings.append(
                Finding(
                    rule_id="SEC-005",
                    severity=Severity.CRITICAL,
                    message=(f"Weak or default credential in '{key}'. Replace with a strong, unique value."),
                    field=key,
                    value="[REDACTED]",
                )
            )
    return findings


def check_hardcoded_secrets(config: dict) -> list[Finding]:
    """Detect credential patterns in string values (shallow scan)."""
    findings = []
    for key, val in config.items():
        if not isinstance(val, str):
            continue
        if _CREDENTIAL_PATTERN.search(f"{key}={val}"):
            if not val.startswith("${") and not val.startswith("$("):
                findings.append(
                    Finding(
                        rule_id="SEC-006",
                        severity=Severity.HIGH,
                        message=(
                            f"Possible hardcoded credential in field '{key}'. "
                            "Use environment variables or a secrets manager."
                        ),
                        field=key,
                        value="[REDACTED]",
                    )
                )
    return findings


def check_logging(config: dict) -> list[Finding]:
    findings = []
    logging_block = config.get("logging") or config.get("log") or {}
    if not config.get("logging") and not config.get("log"):
        findings.append(
            Finding(
                rule_id="SEC-007",
                severity=Severity.LOW,
                message=("No logging configuration found. Ensure audit logs are enabled in production."),
                field="logging",
            )
        )
        return findings

    if isinstance(logging_block, dict):
        level = (logging_block.get("level") or "").upper()
        if level == "DEBUG":
            findings.append(
                Finding(
                    rule_id="SEC-008",
                    severity=Severity.MEDIUM,
                    message=("Log level is DEBUG. This may expose sensitive data in production logs."),
                    field="logging.level",
                    value=level,
                )
            )
    return findings


def check_rate_limiting(config: dict) -> list[Finding]:
    findings = []
    rate_keys = ("rate_limit", "rate_limiting", "throttle", "ratelimit")
    has_rate_limit = any(config.get(k) for k in rate_keys)
    if not has_rate_limit:
        findings.append(
            Finding(
                rule_id="SEC-009",
                severity=Severity.INFO,
                message=(
                    "No rate limiting configuration found. Consider adding rate limits to prevent abuse."
                ),
                field="rate_limit",
            )
        )
    return findings


ALL_RULES = [
    check_debug_mode,
    check_bind_address,
    check_tls,
    check_weak_credentials,
    check_hardcoded_secrets,
    check_logging,
    check_rate_limiting,
]

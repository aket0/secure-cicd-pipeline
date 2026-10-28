# Security Policy

## Scope

This document defines the security controls enforced by the CI/CD pipeline for `policy-validator`.

## Blocking Controls

The following findings cause the pipeline to **fail and block merges**:

| Rule ID | Severity | Description                          |
|---------|----------|--------------------------------------|
| SEC-001 | HIGH     | Debug mode enabled                   |
| SEC-003 | CRITICAL | TLS/SSL explicitly disabled          |
| SEC-004 | HIGH     | Insecure minimum TLS version         |
| SEC-005 | CRITICAL | Weak or default credential           |
| SEC-006 | HIGH     | Possible hardcoded secret            |

Any Bandit finding at severity HIGH (level 2) or above also blocks the pipeline.

Any `pip-audit` finding for a known CVE blocks the pipeline.

`gitleaks` findings (secrets in Git history) block the pipeline.

## Non-Blocking Controls

| Rule ID | Severity | Description                          |
|---------|----------|--------------------------------------|
| SEC-002 | MEDIUM   | Service bound to 0.0.0.0             |
| SEC-007 | LOW      | No logging configuration             |
| SEC-008 | MEDIUM   | Debug log level                      |
| SEC-009 | INFO     | No rate limiting configuration       |

These generate findings and are visible in reports, but do not block merges.
They must be reviewed and addressed before production deployment.

## Responsible Disclosure

If you discover a security vulnerability in this project, please report it privately via GitHub's Security Advisory feature or by email before public disclosure.

## Dependency Updates

Dependencies are audited weekly (scheduled workflow). CVEs in production dependencies
trigger an immediate patch requirement. Dev-only dependencies are patched within 30 days.

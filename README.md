# secure-cicd-pipeline

A Python security policy validator with a fully hardened GitHub Actions CI/CD pipeline.

## Problem Solved

Configuration files are a common source of security vulnerabilities: debug modes left on,
weak credentials, disabled TLS, and hardcoded secrets frequently reach production because
there is no automated gate to catch them. This project provides:

1. A **Python tool** that detects security misconfigurations in JSON/YAML config files.
2. A **CI/CD pipeline** that automatically runs SAST, secret detection, dependency audits,
   and enforces a blocking security policy on every pull request.

## Architecture

```
secure-cicd-pipeline/
├── src/policy_validator/
│   ├── rules.py        # Security rules (SEC-001 … SEC-009)
│   ├── checker.py      # Rule runner + file loader
│   └── cli.py          # CLI entry point
├── tests/
│   ├── test_rules.py           # Unit tests per rule
│   ├── test_checker.py         # Integration tests
│   └── test_security_controls.py  # Proof that controls block bad cases
├── examples/
│   ├── secure_config.json      # Clean configuration example
│   └── insecure_config.json    # Deliberately broken for demo
├── .github/workflows/
│   ├── ci.yml          # PR gate: lint, test, SAST, dep-audit, secrets
│   └── security.yml    # Weekly: full audit + Trivy filesystem scan
└── docs/
    ├── security-policy.md   # Blocking rules and thresholds
    └── false-positives.md   # Documented exceptions
```

## Technologies

| Tool       | Purpose                          |
|------------|----------------------------------|
| Python 3.11+ | Application language            |
| pytest     | Unit + integration tests         |
| ruff       | Linting and formatting           |
| bandit     | SAST (static security analysis)  |
| pip-audit  | Dependency vulnerability audit   |
| gitleaks   | Secret detection in Git history  |
| Trivy      | Filesystem scan (weekly)         |

## Prerequisites

- Python 3.11 or later
- `make` (optional but recommended)
- Git

## Installation

```bash
git clone https://github.com/aket0/secure-cicd-pipeline.git
cd secure-cicd-pipeline

# Create virtual environment and install dev dependencies
make install-dev

# Or manually:
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Local Usage

```bash
# Activate the virtual environment first
source .venv/bin/activate

# Check a configuration file
policy-validator examples/insecure_config.json

# Check with JSON output
policy-validator --format json examples/insecure_config.json

# Check multiple files, fail on CRITICAL only
policy-validator --fail-on CRITICAL examples/*.json

# Compare secure vs insecure
policy-validator examples/secure_config.json examples/insecure_config.json
```

## Running Tests

```bash
# All tests with coverage
make test

# Or directly:
source .venv/bin/activate
pytest --cov=policy_validator --cov-report=term-missing
```

Expected output: **all tests pass**, coverage ≥ 80%.

## Security Controls

### Pipeline Gates (block on fail)

| Control        | Tool       | Threshold                              |
|----------------|------------|----------------------------------------|
| Linting        | ruff       | Any error                              |
| Unit tests     | pytest     | Any failure or coverage < 80%          |
| SAST           | bandit     | Any HIGH (level 2+) finding            |
| Dep audit      | pip-audit  | Any known CVE                          |
| Secret scan    | gitleaks   | Any secret detected in history         |

### Rules Enforced by the Validator

| Rule    | Severity | Description                              |
|---------|----------|------------------------------------------|
| SEC-001 | HIGH     | Debug mode enabled                       |
| SEC-002 | MEDIUM   | Service bound to 0.0.0.0                 |
| SEC-003 | CRITICAL | TLS/SSL disabled                         |
| SEC-004 | HIGH     | Insecure TLS version (< 1.2)             |
| SEC-005 | CRITICAL | Weak or default credential               |
| SEC-006 | HIGH     | Hardcoded secret                         |
| SEC-007 | LOW      | No logging configured                    |
| SEC-008 | MEDIUM   | Debug log level                          |
| SEC-009 | INFO     | No rate limiting configured              |

## Observed Results (local)

Tests run against actual code — no simulated results:

```
pytest --cov=policy_validator --cov-report=term-missing
# 30+ tests, all passing
# Coverage: ≥ 80%
```

Run `make all` to reproduce linting, SAST, dep-audit, and tests locally.

## Known Limits

- YAML support requires `pyyaml` (`pip install policy-validator[yaml]`).
- Bandit and gitleaks run in GitHub Actions; local runs require separate install.
- The validator performs a **shallow** scan of the top-level config dict. Nested credentials
  are not detected beyond one level of nesting.
- SARIF upload to the GitHub Security tab requires `security-events: write` permission
  (already configured in the workflow).
- Trivy scan runs only on the weekly schedule, not on every PR.

## Improvement Paths

- Add recursive (deep) config scanning.
- Support environment-variable expansion for context-aware checks.
- Add YAML anchor/alias resolution.
- Integrate Semgrep for broader SAST coverage.
- Add Trivy on every PR (image scan after Dockerfile is added).
- Generate CycloneDX SBOM from dependencies.

## Publishing Commands (when ready)

```bash
# Verify state before pushing
git status
git log --oneline
git diff HEAD

# Publish
git push -u origin main
```

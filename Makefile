.PHONY: help venv install install-dev test lint sast dep-audit clean all

PYTHON   := python3
VENV     := .venv
BIN      := $(VENV)/bin
PIP      := $(BIN)/pip
PYTEST   := $(BIN)/pytest
RUFF     := $(BIN)/ruff
BANDIT   := $(BIN)/bandit
AUDIT    := $(BIN)/pip-audit

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "  venv         Create virtual environment"
	@echo "  install      Install runtime dependencies"
	@echo "  install-dev  Install all dev dependencies (tests + security tools)"
	@echo "  test         Run tests with coverage"
	@echo "  lint         Run ruff (linting + format check)"
	@echo "  sast         Run bandit (SAST)"
	@echo "  dep-audit    Run pip-audit (dependency vulnerabilities)"
	@echo "  clean        Remove venv and caches"
	@echo "  all          install-dev + lint + sast + dep-audit + test"

venv:
	$(PYTHON) -m venv $(VENV)

install: venv
	$(PIP) install -e .

install-dev: venv
	$(PIP) install -e ".[dev]"

test: install-dev
	$(PYTEST) --cov=policy_validator --cov-report=term-missing

lint: install-dev
	$(RUFF) check src/ tests/
	$(RUFF) format --check src/ tests/

sast: install-dev
	$(BANDIT) -r src/ -f txt

dep-audit: install-dev
	$(AUDIT) --requirement <($(PIP) freeze)

clean:
	rm -rf $(VENV) __pycache__ .pytest_cache htmlcov .coverage coverage.xml
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

all: install-dev lint sast dep-audit test

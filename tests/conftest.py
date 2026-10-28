"""Shared fixtures for all test modules."""

import json
from pathlib import Path

import pytest


@pytest.fixture
def insecure_config() -> dict:
    return {
        "debug": True,
        "host": "0.0.0.0",
        "tls_disabled": True,
        "password": "admin",
        "secret_key": "changeme",
        "logging": {"level": "DEBUG"},
    }


@pytest.fixture
def secure_config() -> dict:
    return {
        "debug": False,
        "host": "127.0.0.1",
        "tls": {"enabled": True, "min_version": "TLSv1.2"},
        "password": "${DB_PASSWORD}",
        "secret_key": "${APP_SECRET}",
        "logging": {"level": "INFO"},
        "rate_limit": {"enabled": True, "requests_per_minute": 100},
    }


@pytest.fixture
def insecure_config_file(tmp_path: Path, insecure_config: dict) -> Path:
    p = tmp_path / "insecure.json"
    p.write_text(json.dumps(insecure_config))
    return p


@pytest.fixture
def secure_config_file(tmp_path: Path, secure_config: dict) -> Path:
    p = tmp_path / "secure.json"
    p.write_text(json.dumps(secure_config))
    return p

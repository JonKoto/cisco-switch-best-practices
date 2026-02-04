"""Shared fixtures for tests."""

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture()
def compliant_config() -> str:
    return (FIXTURES_DIR / "compliant.cfg").read_text()


@pytest.fixture()
def noncompliant_config() -> str:
    return (FIXTURES_DIR / "noncompliant.cfg").read_text()

"""Tests for the CLI interface."""

from pathlib import Path

from click.testing import CliRunner

from cisco_audit.cli import cli

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_file_compliant():
    runner = CliRunner()
    result = runner.invoke(cli, ["file", str(FIXTURES_DIR / "compliant.cfg")])
    assert result.exit_code == 0
    assert "No findings" in result.output


def test_file_noncompliant():
    runner = CliRunner()
    result = runner.invoke(cli, ["file", str(FIXTURES_DIR / "noncompliant.cfg")])
    assert result.exit_code == 1
    assert "SEC-001" in result.output


def test_file_json_format():
    runner = CliRunner()
    result = runner.invoke(
        cli, ["file", str(FIXTURES_DIR / "noncompliant.cfg"), "--format", "json"]
    )
    assert result.exit_code == 1
    import json

    data = json.loads(result.output)
    assert "findings" in data
    assert "summary" in data
    assert data["hostname"] == "NONCOMPLIANT-SW01"


def test_file_filter_rules():
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["file", str(FIXTURES_DIR / "noncompliant.cfg"), "--rules", "security"],
    )
    # Should still have findings (security ones)
    assert result.exit_code == 1
    assert "SEC-" in result.output


def test_file_not_found():
    runner = CliRunner()
    result = runner.invoke(cli, ["file", "/nonexistent/path.cfg"])
    assert result.exit_code != 0

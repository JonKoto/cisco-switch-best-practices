"""Click-based CLI for the Cisco audit tool."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

import cisco_audit.rules.management  # noqa: F401
import cisco_audit.rules.network  # noqa: F401

# Ensure rule modules are imported.
import cisco_audit.rules.security  # noqa: F401
from cisco_audit.auditor import audit_config
from cisco_audit.connector import fetch_running_config
from cisco_audit.models import AuditReport
from cisco_audit.rules import get_all_rules


def _filter_rules(categories: tuple[str, ...] | None):
    """Return rules filtered by category, or all rules if no filter."""
    all_rules = get_all_rules()
    if not categories:
        return all_rules
    return [r for r in all_rules if r.category in categories]


def _output_text(report: AuditReport) -> None:
    """Print a human-readable report to stdout."""
    click.echo(f"Audit Report for: {report.hostname}")
    click.echo(f"Timestamp: {report.timestamp.isoformat()}")
    click.echo(f"{'=' * 60}")

    if not report.findings:
        click.echo("No findings. Configuration is compliant.")
        return

    for i, f in enumerate(report.findings, 1):
        click.echo(f"\n[{i}] {f.rule_id} ({f.severity.value})")
        click.echo(f"    {f.description}")
        click.echo(f"    Remediation: {f.remediation}")
        if f.config_line:
            click.echo(f"    Config: {f.config_line}")

    click.echo(f"\n{'=' * 60}")
    click.echo("Summary:")
    for key, val in report.summary.items():
        click.echo(f"  {key}: {val}")


def _output_json(report: AuditReport) -> None:
    """Print the report as JSON to stdout."""
    data = json.loads(report.model_dump_json())
    data["summary"] = report.summary
    click.echo(json.dumps(data, indent=2))


@click.group()
def cli():
    """Cisco IOS/IOS-XE configuration audit tool."""


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format", "fmt", type=click.Choice(["text", "json"]), default="text"
)
@click.option(
    "--rules",
    "categories",
    multiple=True,
    help="Rule categories: security, management, network",
)
def file(path: str, fmt: str, categories: tuple[str, ...]):
    """Audit a local configuration file."""
    config_text = Path(path).read_text()
    rules = _filter_rules(categories if categories else None)
    report = audit_config(config_text, rules=rules)

    if fmt == "json":
        _output_json(report)
    else:
        _output_text(report)

    if report.findings:
        sys.exit(1)


@cli.command()
@click.argument("host")
@click.option("-u", "--username", required=True, help="SSH username")
@click.option(
    "-p", "--password", required=True, prompt=True,
    hide_input=True, help="SSH password",
)
@click.option("--port", default=22, help="SSH port")
@click.option(
    "--enable-secret", default=None,
    help="Enable secret for privileged EXEC",
)
@click.option(
    "--format", "fmt", type=click.Choice(["text", "json"]), default="text"
)
@click.option(
    "--rules",
    "categories",
    multiple=True,
    help="Rule categories: security, management, network",
)
def ssh(
    host: str,
    username: str,
    password: str,
    port: int,
    enable_secret: str | None,
    fmt: str,
    categories: tuple[str, ...],
):
    """Audit a live device via SSH."""
    try:
        config_text = fetch_running_config(
            host=host,
            username=username,
            password=password,
            port=port,
            enable_secret=enable_secret,
        )
    except Exception as e:
        click.echo(f"Error connecting to {host}: {e}", err=True)
        sys.exit(2)

    rules = _filter_rules(categories if categories else None)
    report = audit_config(config_text, rules=rules)

    if fmt == "json":
        _output_json(report)
    else:
        _output_text(report)

    if report.findings:
        sys.exit(1)

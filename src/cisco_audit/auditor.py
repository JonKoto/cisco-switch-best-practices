"""Orchestrates rules against parsed configurations."""

from __future__ import annotations

import cisco_audit.rules.management  # noqa: F401
import cisco_audit.rules.network  # noqa: F401

# Ensure all rule modules are imported so rules are registered.
import cisco_audit.rules.security  # noqa: F401
from cisco_audit.models import AuditReport
from cisco_audit.parser import extract_hostname, parse_config
from cisco_audit.rules import Rule, get_all_rules


def audit_config(config_text: str, rules: list[Rule] | None = None) -> AuditReport:
    """Run audit rules against a raw IOS configuration and return a report."""
    parsed = parse_config(config_text)
    hostname = extract_hostname(config_text)

    if rules is None:
        rules = get_all_rules()

    findings = []
    for rule in rules:
        findings.extend(rule.check(parsed))

    return AuditReport(hostname=hostname, findings=findings)

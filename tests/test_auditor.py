"""Tests for the auditor module."""

from cisco_audit.auditor import audit_config
from cisco_audit.models import Severity


def test_audit_compliant_config(compliant_config):
    report = audit_config(compliant_config)
    assert report.hostname == "COMPLIANT-SW01"
    assert len(report.findings) == 0
    assert report.summary["TOTAL"] == 0


def test_audit_noncompliant_config(noncompliant_config):
    report = audit_config(noncompliant_config)
    assert report.hostname == "NONCOMPLIANT-SW01"
    assert len(report.findings) > 0
    assert report.summary["TOTAL"] > 0


def test_audit_with_filtered_rules(noncompliant_config):
    from cisco_audit.rules import get_all_rules

    security_rules = [r for r in get_all_rules() if r.category == "security"]
    report = audit_config(noncompliant_config, rules=security_rules)
    assert all(f.rule_id.startswith("SEC-") for f in report.findings)


def test_audit_summary_counts(noncompliant_config):
    report = audit_config(noncompliant_config)
    summary = report.summary
    assert set(summary.keys()) == {"LOW", "MEDIUM", "HIGH", "CRITICAL", "TOTAL"}
    assert summary["TOTAL"] == sum(summary[s.value] for s in Severity)


def test_audit_report_has_timestamp(compliant_config):
    report = audit_config(compliant_config)
    assert report.timestamp is not None

"""Management-related audit rules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cisco_audit.models import Finding, Severity
from cisco_audit.rules import Rule, register_rule

if TYPE_CHECKING:
    from ciscoconfparse2 import CiscoConfParse


@register_rule
class NTPServerRule(Rule):
    id = "MGT-001"
    name = "NTP Server Configured"
    severity = Severity.MEDIUM
    category = "management"

    def check(self, parsed: CiscoConfParse) -> list[Finding]:
        if not parsed.find_objects(r"^ntp server"):
            return [
                Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    description=(
                        "No NTP server is configured. Time"
                        " synchronization is critical for"
                        " logging and forensics."
                    ),
                    remediation=(
                        "Configure 'ntp server <address>'"
                        " in global configuration mode."
                    ),
                )
            ]
        return []


@register_rule
class LoggingHostRule(Rule):
    id = "MGT-002"
    name = "Logging Host Configured"
    severity = Severity.MEDIUM
    category = "management"

    def check(self, parsed: CiscoConfParse) -> list[Finding]:
        if not parsed.find_objects(r"^logging host"):
            return [
                Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    description=(
                        "No remote logging host is configured."
                        " Logs are only stored locally and"
                        " may be lost."
                    ),
                    remediation=(
                        "Configure 'logging host <address>'"
                        " in global configuration mode."
                    ),
                )
            ]
        return []


@register_rule
class NoSNMPv1v2Rule(Rule):
    id = "MGT-003"
    name = "No SNMP v1/v2c Community"
    severity = Severity.HIGH
    category = "management"

    def check(self, parsed: CiscoConfParse) -> list[Finding]:
        findings: list[Finding] = []
        communities = parsed.find_objects(r"^snmp-server community")
        for comm in communities:
            findings.append(
                Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    description=(
                        "SNMP v1/v2c community string configured."
                        " These versions transmit community"
                        " strings in cleartext."
                    ),
                    remediation=(
                        "Migrate to SNMPv3 with authentication"
                        " and encryption. Remove"
                        " 'snmp-server community' entries."
                    ),
                    config_line=comm.text.strip(),
                )
            )
        return findings


@register_rule
class BannerMOTDRule(Rule):
    id = "MGT-004"
    name = "Banner MOTD"
    severity = Severity.LOW
    category = "management"

    def check(self, parsed: CiscoConfParse) -> list[Finding]:
        if not parsed.find_objects(r"^banner motd"):
            return [
                Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    description=(
                        "No login banner (MOTD) is configured."
                        " A legal notice banner is recommended."
                    ),
                    remediation=(
                        "Configure 'banner motd <delimiter>"
                        " <message> <delimiter>'"
                        " in global configuration mode."
                    ),
                )
            ]
        return []

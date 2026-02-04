"""Security-related audit rules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cisco_audit.models import Finding, Severity
from cisco_audit.rules import Rule, register_rule

if TYPE_CHECKING:
    from ciscoconfparse2 import CiscoConfParse


@register_rule
class EnableSecretRule(Rule):
    id = "SEC-001"
    name = "Enable Secret"
    severity = Severity.CRITICAL
    category = "security"

    def check(self, parsed: CiscoConfParse) -> list[Finding]:
        if not parsed.find_objects(r"^enable secret"):
            return [
                Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    description=(
                        "No 'enable secret' configured. The privileged EXEC"
                        " password may be unset or using the weaker"
                        " 'enable password'."
                    ),
                    remediation=(
                        "Configure 'enable secret <password>'"
                        " in global configuration mode."
                    ),
                )
            ]
        return []


@register_rule
class ServicePasswordEncryptionRule(Rule):
    id = "SEC-002"
    name = "Service Password-Encryption"
    severity = Severity.HIGH
    category = "security"

    def check(self, parsed: CiscoConfParse) -> list[Finding]:
        if not parsed.find_objects(r"^service password-encryption"):
            return [
                Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    description=(
                        "'service password-encryption' is not enabled."
                        " Passwords may appear in cleartext in the"
                        " configuration."
                    ),
                    remediation=(
                        "Configure 'service password-encryption'"
                        " in global configuration mode."
                    ),
                )
            ]
        return []


@register_rule
class SSHv2Rule(Rule):
    id = "SEC-003"
    name = "SSH Version 2"
    severity = Severity.HIGH
    category = "security"

    def check(self, parsed: CiscoConfParse) -> list[Finding]:
        if not parsed.find_objects(r"^ip ssh version 2"):
            return [
                Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    description=(
                        "SSH version 2 is not explicitly configured."
                        " SSHv1 is vulnerable to known attacks."
                    ),
                    remediation=(
                        "Configure 'ip ssh version 2'"
                        " in global configuration mode."
                    ),
                )
            ]
        return []


@register_rule
class NoTelnetVTYRule(Rule):
    id = "SEC-004"
    name = "No Telnet on VTY Lines"
    severity = Severity.CRITICAL
    category = "security"

    def check(self, parsed: CiscoConfParse) -> list[Finding]:
        findings: list[Finding] = []
        vty_lines = parsed.find_objects(r"^line vty")
        for vty in vty_lines:
            children_text = [c.text.strip() for c in vty.children]
            transport_input = [
                c for c in children_text if c.startswith("transport input")
            ]
            vty_name = vty.text.strip()
            if not transport_input:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        description=(
                            f"VTY line '{vty_name}' has no"
                            " 'transport input' configured,"
                            " telnet may be allowed."
                        ),
                        remediation=(
                            "Configure 'transport input ssh'"
                            " under the VTY line."
                        ),
                        config_line=vty_name,
                    )
                )
            else:
                for ti in transport_input:
                    if "telnet" in ti or ti == "transport input all":
                        findings.append(
                            Finding(
                                rule_id=self.id,
                                severity=self.severity,
                                description=(
                                    f"VTY line '{vty_name}' allows"
                                    " telnet. Telnet transmits"
                                    " credentials in cleartext."
                                ),
                                remediation=(
                                    "Configure 'transport input ssh'"
                                    " under the VTY line."
                                ),
                                config_line=vty_name,
                            )
                        )
        return findings


@register_rule
class AAANewModelRule(Rule):
    id = "SEC-005"
    name = "AAA New-Model"
    severity = Severity.HIGH
    category = "security"

    def check(self, parsed: CiscoConfParse) -> list[Finding]:
        if not parsed.find_objects(r"^aaa new-model"):
            return [
                Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    description=(
                        "AAA new-model is not enabled. Authentication,"
                        " authorization, and accounting services"
                        " are not active."
                    ),
                    remediation=(
                        "Configure 'aaa new-model'"
                        " in global configuration mode."
                    ),
                )
            ]
        return []


@register_rule
class NoIPHTTPServerRule(Rule):
    id = "SEC-006"
    name = "No IP HTTP Server"
    severity = Severity.MEDIUM
    category = "security"

    def check(self, parsed: CiscoConfParse) -> list[Finding]:
        findings: list[Finding] = []
        if parsed.find_objects(r"^ip http server"):
            findings.append(
                Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    description=(
                        "HTTP server is enabled. This exposes an"
                        " unencrypted management interface."
                    ),
                    remediation=(
                        "Configure 'no ip http server'"
                        " in global configuration mode."
                    ),
                    config_line="ip http server",
                )
            )
        return findings


@register_rule
class VTYACLRule(Rule):
    id = "SEC-007"
    name = "VTY Access-Class"
    severity = Severity.HIGH
    category = "security"

    def check(self, parsed: CiscoConfParse) -> list[Finding]:
        findings: list[Finding] = []
        vty_lines = parsed.find_objects(r"^line vty")
        for vty in vty_lines:
            children_text = [c.text.strip() for c in vty.children]
            has_acl = any(
                c.startswith("access-class") for c in children_text
            )
            vty_name = vty.text.strip()
            if not has_acl:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        description=(
                            f"VTY line '{vty_name}' has no access-class"
                            " configured. Management access"
                            " is unrestricted."
                        ),
                        remediation=(
                            "Configure 'access-class <ACL> in'"
                            " under the VTY line to restrict"
                            " management access."
                        ),
                        config_line=vty_name,
                    )
                )
        return findings

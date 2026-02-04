"""Network-related audit rules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cisco_audit.models import Finding, Severity
from cisco_audit.rules import Rule, register_rule

if TYPE_CHECKING:
    from ciscoconfparse2 import CiscoConfParse


@register_rule
class STPModeRule(Rule):
    id = "NET-001"
    name = "Spanning-Tree Mode Rapid-PVST"
    severity = Severity.MEDIUM
    category = "network"

    def check(self, parsed: CiscoConfParse) -> list[Finding]:
        if not parsed.find_objects(r"^spanning-tree mode rapid-pvst"):
            return [
                Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    description=(
                        "Spanning-tree mode is not set to rapid-pvst."
                        " Rapid-PVST provides faster convergence."
                    ),
                    remediation=(
                        "Configure 'spanning-tree mode rapid-pvst'"
                        " in global configuration mode."
                    ),
                )
            ]
        return []


@register_rule
class BPDUGuardRule(Rule):
    id = "NET-002"
    name = "BPDU Guard Default"
    severity = Severity.HIGH
    category = "network"

    def check(self, parsed: CiscoConfParse) -> list[Finding]:
        if not parsed.find_objects(
            r"^spanning-tree portfast bpduguard default"
        ):
            return [
                Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    description=(
                        "BPDU guard is not enabled globally."
                        " Access ports may be vulnerable to"
                        " STP manipulation attacks."
                    ),
                    remediation=(
                        "Configure 'spanning-tree portfast"
                        " bpduguard default'"
                        " in global configuration mode."
                    ),
                )
            ]
        return []


@register_rule
class VTPModeRule(Rule):
    id = "NET-003"
    name = "VTP Mode Transparent or Off"
    severity = Severity.MEDIUM
    category = "network"

    def check(self, parsed: CiscoConfParse) -> list[Finding]:
        vtp_objs = parsed.find_objects(r"^vtp mode")
        if not vtp_objs:
            return [
                Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    description=(
                        "VTP mode is not explicitly configured."
                        " Default server mode may propagate"
                        " VLAN changes unexpectedly."
                    ),
                    remediation=(
                        "Configure 'vtp mode transparent'"
                        " or 'vtp mode off'"
                        " in global configuration mode."
                    ),
                )
            ]
        for obj in vtp_objs:
            text = obj.text.strip().lower()
            if "transparent" not in text and "off" not in text:
                return [
                    Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        description=(
                            f"VTP mode is set to '{text}'."
                            " Server or client mode may propagate"
                            " VLAN changes unexpectedly."
                        ),
                        remediation=(
                            "Configure 'vtp mode transparent'"
                            " or 'vtp mode off'"
                            " in global configuration mode."
                        ),
                        config_line=obj.text.strip(),
                    )
                ]
        return []

"""Rule registry and base class for audit rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from cisco_audit.models import Finding, Severity

if TYPE_CHECKING:
    from ciscoconfparse2 import CiscoConfParse

_REGISTRY: list[type[Rule]] = []


class Rule(ABC):
    id: str
    name: str
    severity: Severity
    category: str

    @abstractmethod
    def check(self, parsed: CiscoConfParse) -> list[Finding]: ...


def register_rule(cls: type[Rule]) -> type[Rule]:
    _REGISTRY.append(cls)
    return cls


def get_all_rules() -> list[Rule]:
    return [cls() for cls in _REGISTRY]

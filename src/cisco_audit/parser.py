"""Wrapper around ciscoconfparse2 for structured IOS config parsing."""

from __future__ import annotations

import re

from ciscoconfparse2 import CiscoConfParse


def parse_config(config_text: str) -> CiscoConfParse:
    """Parse a raw IOS configuration string into a CiscoConfParse object."""
    lines = config_text.splitlines()
    return CiscoConfParse(lines)


def extract_hostname(config_text: str) -> str:
    """Extract the hostname from a raw configuration string."""
    match = re.search(r"^hostname\s+(\S+)", config_text, re.MULTILINE)
    if match:
        return match.group(1)
    return "unknown"

"""Tests for the configuration parser."""

from cisco_audit.parser import extract_hostname, parse_config


def test_parse_config_returns_ciscoconfparse(compliant_config):
    parsed = parse_config(compliant_config)
    assert parsed is not None
    results = parsed.find_objects(r"^hostname")
    assert len(results) == 1


def test_extract_hostname(compliant_config):
    assert extract_hostname(compliant_config) == "COMPLIANT-SW01"


def test_extract_hostname_missing():
    assert extract_hostname("!\nno hostname set\n!") == "unknown"


def test_parse_finds_interfaces(compliant_config):
    parsed = parse_config(compliant_config)
    interfaces = parsed.find_objects(r"^interface")
    assert len(interfaces) >= 2

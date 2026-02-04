"""Tests for individual audit rules."""

from cisco_audit.parser import parse_config
from cisco_audit.rules.management import (
    BannerMOTDRule,
    LoggingHostRule,
    NoSNMPv1v2Rule,
    NTPServerRule,
)
from cisco_audit.rules.network import (
    BPDUGuardRule,
    STPModeRule,
    VTPModeRule,
)
from cisco_audit.rules.security import (
    AAANewModelRule,
    EnableSecretRule,
    NoIPHTTPServerRule,
    NoTelnetVTYRule,
    ServicePasswordEncryptionRule,
    SSHv2Rule,
    VTYACLRule,
)

# --- Security Rules ---


class TestEnableSecretRule:
    def test_compliant(self, compliant_config):
        parsed = parse_config(compliant_config)
        findings = EnableSecretRule().check(parsed)
        assert len(findings) == 0

    def test_noncompliant(self, noncompliant_config):
        parsed = parse_config(noncompliant_config)
        findings = EnableSecretRule().check(parsed)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-001"


class TestServicePasswordEncryption:
    def test_compliant(self, compliant_config):
        parsed = parse_config(compliant_config)
        findings = ServicePasswordEncryptionRule().check(parsed)
        assert len(findings) == 0

    def test_noncompliant(self, noncompliant_config):
        parsed = parse_config(noncompliant_config)
        findings = ServicePasswordEncryptionRule().check(parsed)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-002"


class TestSSHv2Rule:
    def test_compliant(self, compliant_config):
        parsed = parse_config(compliant_config)
        findings = SSHv2Rule().check(parsed)
        assert len(findings) == 0

    def test_noncompliant(self, noncompliant_config):
        parsed = parse_config(noncompliant_config)
        findings = SSHv2Rule().check(parsed)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-003"


class TestNoTelnetVTYRule:
    def test_compliant(self, compliant_config):
        parsed = parse_config(compliant_config)
        findings = NoTelnetVTYRule().check(parsed)
        assert len(findings) == 0

    def test_noncompliant(self, noncompliant_config):
        parsed = parse_config(noncompliant_config)
        findings = NoTelnetVTYRule().check(parsed)
        assert len(findings) >= 1
        assert all(f.rule_id == "SEC-004" for f in findings)


class TestAAANewModelRule:
    def test_compliant(self, compliant_config):
        parsed = parse_config(compliant_config)
        findings = AAANewModelRule().check(parsed)
        assert len(findings) == 0

    def test_noncompliant(self, noncompliant_config):
        parsed = parse_config(noncompliant_config)
        findings = AAANewModelRule().check(parsed)
        assert len(findings) == 1


class TestNoIPHTTPServerRule:
    def test_compliant(self, compliant_config):
        parsed = parse_config(compliant_config)
        findings = NoIPHTTPServerRule().check(parsed)
        assert len(findings) == 0

    def test_noncompliant(self, noncompliant_config):
        parsed = parse_config(noncompliant_config)
        findings = NoIPHTTPServerRule().check(parsed)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-006"


class TestVTYACLRule:
    def test_compliant(self, compliant_config):
        parsed = parse_config(compliant_config)
        findings = VTYACLRule().check(parsed)
        assert len(findings) == 0

    def test_noncompliant(self, noncompliant_config):
        parsed = parse_config(noncompliant_config)
        findings = VTYACLRule().check(parsed)
        assert len(findings) >= 1
        assert all(f.rule_id == "SEC-007" for f in findings)


# --- Management Rules ---


class TestNTPServerRule:
    def test_compliant(self, compliant_config):
        parsed = parse_config(compliant_config)
        findings = NTPServerRule().check(parsed)
        assert len(findings) == 0

    def test_noncompliant(self, noncompliant_config):
        parsed = parse_config(noncompliant_config)
        findings = NTPServerRule().check(parsed)
        assert len(findings) == 1


class TestLoggingHostRule:
    def test_compliant(self, compliant_config):
        parsed = parse_config(compliant_config)
        findings = LoggingHostRule().check(parsed)
        assert len(findings) == 0

    def test_noncompliant(self, noncompliant_config):
        parsed = parse_config(noncompliant_config)
        findings = LoggingHostRule().check(parsed)
        assert len(findings) == 1


class TestNoSNMPv1v2Rule:
    def test_compliant(self, compliant_config):
        parsed = parse_config(compliant_config)
        findings = NoSNMPv1v2Rule().check(parsed)
        assert len(findings) == 0

    def test_noncompliant(self, noncompliant_config):
        parsed = parse_config(noncompliant_config)
        findings = NoSNMPv1v2Rule().check(parsed)
        assert len(findings) == 2  # public + private


class TestBannerMOTDRule:
    def test_compliant(self, compliant_config):
        parsed = parse_config(compliant_config)
        findings = BannerMOTDRule().check(parsed)
        assert len(findings) == 0

    def test_noncompliant(self, noncompliant_config):
        parsed = parse_config(noncompliant_config)
        findings = BannerMOTDRule().check(parsed)
        assert len(findings) == 1


# --- Network Rules ---


class TestSTPModeRule:
    def test_compliant(self, compliant_config):
        parsed = parse_config(compliant_config)
        findings = STPModeRule().check(parsed)
        assert len(findings) == 0

    def test_noncompliant(self, noncompliant_config):
        parsed = parse_config(noncompliant_config)
        findings = STPModeRule().check(parsed)
        assert len(findings) == 1


class TestBPDUGuardRule:
    def test_compliant(self, compliant_config):
        parsed = parse_config(compliant_config)
        findings = BPDUGuardRule().check(parsed)
        assert len(findings) == 0

    def test_noncompliant(self, noncompliant_config):
        parsed = parse_config(noncompliant_config)
        findings = BPDUGuardRule().check(parsed)
        assert len(findings) == 1


class TestVTPModeRule:
    def test_compliant(self, compliant_config):
        parsed = parse_config(compliant_config)
        findings = VTPModeRule().check(parsed)
        assert len(findings) == 0

    def test_noncompliant(self, noncompliant_config):
        parsed = parse_config(noncompliant_config)
        findings = VTPModeRule().check(parsed)
        assert len(findings) == 1

    def test_vtp_server_mode(self):
        config = "!\nvtp mode server\n!\n"
        parsed = parse_config(config)
        findings = VTPModeRule().check(parsed)
        assert len(findings) == 1

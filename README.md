# Cisco Switch Best Practices — Compliance Auditing Tool

A Python CLI tool and library that audits Cisco IOS/IOS-XE switch configurations against security and operational best-practice rules.

## Installation

```bash
pip install -e ".[dev]"
```

To include web interface dependencies:

```bash
pip install -e ".[web]"
```

## Usage

### Audit a configuration file

```bash
cisco-audit file path/to/config.cfg
cisco-audit file path/to/config.cfg --format json
cisco-audit file path/to/config.cfg --rules security --rules management
```

### Audit a live device via SSH

```bash
cisco-audit ssh 192.168.1.1 -u admin -p
cisco-audit ssh 192.168.1.1 -u admin -p --format json
```

### Launch the web interface

```bash
cisco-audit web
cisco-audit web --port 8080 --debug
```

The web UI is available at `http://127.0.0.1:5000` and provides file upload, SSH audit, and audit history with a SQLite backend.

## Rules

| ID | Category | Name | Severity |
|----|----------|------|----------|
| SEC-001 | security | Enable Secret | CRITICAL |
| SEC-002 | security | Service Password-Encryption | HIGH |
| SEC-003 | security | SSH Version 2 | HIGH |
| SEC-004 | security | No Telnet on VTY Lines | CRITICAL |
| SEC-005 | security | AAA New-Model | HIGH |
| SEC-006 | security | No IP HTTP Server | MEDIUM |
| SEC-007 | security | VTY Access-Class | HIGH |
| MGT-001 | management | NTP Server Configured | MEDIUM |
| MGT-002 | management | Logging Host Configured | MEDIUM |
| MGT-003 | management | No SNMP v1/v2c Community | HIGH |
| MGT-004 | management | Banner MOTD | LOW |
| NET-001 | network | Spanning-Tree Mode Rapid-PVST | MEDIUM |
| NET-002 | network | BPDU Guard Default | HIGH |
| NET-003 | network | VTP Mode Transparent or Off | MEDIUM |

## Development

```bash
pytest                    # Run all tests
ruff check src/ tests/    # Lint
ruff format src/ tests/   # Format
```

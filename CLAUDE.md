# Cisco Switch Best Practices — Compliance Auditing Tool

## Build/Dev Commands
- Install: `pip install -e ".[dev]"`
- Test: `pytest`
- Single test: `pytest tests/test_rules.py::TestEnableSecretRule`
- Lint: `ruff check src/ tests/`
- Format: `ruff format src/ tests/`

## Architecture
- `src/cisco_audit/models.py` — Pydantic models (Finding, AuditReport, Severity enum)
- `src/cisco_audit/rules/` — Rule engine with `@register_rule` decorator and base `Rule` class
- `src/cisco_audit/parser.py` — ciscoconfparse2 wrapper
- `src/cisco_audit/auditor.py` — Orchestrates rules against parsed configs
- `src/cisco_audit/connector.py` — Netmiko SSH connector
- `src/cisco_audit/cli.py` — Click CLI (`cisco-audit file` / `cisco-audit ssh` / `cisco-audit web`)
- `src/cisco_audit/web/` — Flask web frontend (app factory, SQLAlchemy models, routes, templates)

## Adding a New Rule
1. Create a class in the appropriate rules module (security.py, management.py, network.py)
2. Inherit from `Rule`, set `id`, `name`, `severity`, `category`
3. Implement `check(parsed) -> list[Finding]`
4. Decorate with `@register_rule`

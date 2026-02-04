"""Flask app factory for the Cisco audit web frontend."""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def create_app(config: dict | None = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)

    if config:
        app.config.update(config)

    if "SQLALCHEMY_DATABASE_URI" not in app.config:
        db_dir = Path(os.environ.get("CISCO_AUDIT_DB_DIR", "~/.cisco_audit")).expanduser()
        db_dir.mkdir(parents=True, exist_ok=True)
        db_path = os.environ.get("CISCO_AUDIT_DB", str(db_dir / "history.db"))
        app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"

    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = "cisco-audit-dev-key"

    db.init_app(app)

    from cisco_audit.web.routes import bp

    app.register_blueprint(bp)

    with app.app_context():
        from cisco_audit.web import models as _models  # noqa: F401, F811

        db.create_all()

    return app

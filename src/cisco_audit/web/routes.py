"""Flask blueprint with route handlers for the web frontend."""

from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for

from cisco_audit.auditor import audit_config
from cisco_audit.connector import fetch_running_config
from cisco_audit.models import AuditReport
from cisco_audit.web import db
from cisco_audit.web.models import AuditRecord, FindingRecord

bp = Blueprint("main", __name__)


def _save_report(
    report: AuditReport, source: str, source_detail: str
) -> AuditRecord:
    """Persist an AuditReport to the database and return the record."""
    summary = report.summary
    record = AuditRecord(
        hostname=report.hostname,
        source=source,
        source_detail=source_detail,
        timestamp=report.timestamp,
        count_low=summary["LOW"],
        count_medium=summary["MEDIUM"],
        count_high=summary["HIGH"],
        count_critical=summary["CRITICAL"],
        count_total=summary["TOTAL"],
    )
    db.session.add(record)
    db.session.flush()

    for finding in report.findings:
        fr = FindingRecord(
            audit_id=record.id,
            rule_id=finding.rule_id,
            severity=finding.severity.value,
            description=finding.description,
            remediation=finding.remediation,
            config_line=finding.config_line,
        )
        db.session.add(fr)

    db.session.commit()
    return record


@bp.route("/")
def index():
    recent = (
        AuditRecord.query.order_by(AuditRecord.timestamp.desc()).limit(5).all()
    )
    return render_template("index.html", audits=recent)


@bp.route("/upload", methods=["GET"])
def upload_form():
    return render_template("upload.html")


@bp.route("/upload", methods=["POST"])
def upload():
    uploaded = request.files.get("config_file")
    if not uploaded or not uploaded.filename:
        flash("No file selected.", "danger")
        return redirect(url_for("main.upload_form"))

    config_text = uploaded.read().decode("utf-8", errors="replace")
    if not config_text.strip():
        flash("Uploaded file is empty.", "danger")
        return redirect(url_for("main.upload_form"))

    report = audit_config(config_text)
    record = _save_report(report, "file", uploaded.filename)
    flash(
        f"Audit complete: {record.count_total} finding(s) for {record.hostname}.",
        "success",
    )
    return redirect(url_for("main.report", record_id=record.id))


@bp.route("/ssh", methods=["GET"])
def ssh_form():
    return render_template("ssh.html")


@bp.route("/ssh", methods=["POST"])
def ssh():
    host = request.form.get("host", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    port_str = request.form.get("port", "22").strip()
    enable_secret = request.form.get("enable_secret", "").strip() or None

    if not host or not username or not password:
        flash("Host, username, and password are required.", "danger")
        return redirect(url_for("main.ssh_form"))

    try:
        port = int(port_str)
    except ValueError:
        flash("Port must be a number.", "danger")
        return redirect(url_for("main.ssh_form"))

    try:
        config_text = fetch_running_config(
            host=host,
            username=username,
            password=password,
            port=port,
            enable_secret=enable_secret,
        )
    except Exception as exc:
        flash(f"SSH connection failed: {exc}", "danger")
        return redirect(url_for("main.ssh_form"))

    report = audit_config(config_text)
    source_detail = f"{host}:{port}"
    record = _save_report(report, "ssh", source_detail)
    flash(
        f"Audit complete: {record.count_total} finding(s) for {record.hostname}.",
        "success",
    )
    return redirect(url_for("main.report", record_id=record.id))


@bp.route("/report/<int:record_id>")
def report(record_id: int):
    record = db.session.get(AuditRecord, record_id)
    if record is None:
        flash("Audit record not found.", "danger")
        return redirect(url_for("main.history"))
    return render_template("report.html", record=record)


@bp.route("/report/<int:record_id>/delete", methods=["POST"])
def delete_report(record_id: int):
    record = db.session.get(AuditRecord, record_id)
    if record is None:
        flash("Audit record not found.", "danger")
    else:
        db.session.delete(record)
        db.session.commit()
        flash("Audit record deleted.", "success")
    return redirect(url_for("main.history"))


@bp.route("/history")
def history():
    page = request.args.get("page", 1, type=int)
    pagination = AuditRecord.query.order_by(
        AuditRecord.timestamp.desc()
    ).paginate(page=page, per_page=20, error_out=False)
    return render_template("history.html", pagination=pagination)

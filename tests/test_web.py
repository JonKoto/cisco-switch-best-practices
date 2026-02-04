"""Tests for the Flask web frontend."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from cisco_audit.web import create_app
from cisco_audit.web import db as _db
from cisco_audit.web.models import AuditRecord, FindingRecord

FIXTURES = Path(__file__).parent / "fixtures"
NONCOMPLIANT = (FIXTURES / "noncompliant.cfg").read_text()
COMPLIANT = (FIXTURES / "compliant.cfg").read_text()


@pytest.fixture()
def app():
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SECRET_KEY": "test",
        }
    )
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def db(app):
    with app.app_context():
        yield _db


class TestIndexPage:
    def test_index_renders(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"Dashboard" in resp.data

    def test_index_shows_recent_audits(self, client, db):
        record = AuditRecord(
            hostname="SW01",
            source="file",
            source_detail="test.cfg",
            count_total=3,
        )
        db.session.add(record)
        db.session.commit()

        resp = client.get("/")
        assert b"SW01" in resp.data


class TestUpload:
    def test_upload_form_renders(self, client):
        resp = client.get("/upload")
        assert resp.status_code == 200
        assert b"Upload" in resp.data

    def test_upload_valid_file(self, client, db):
        data = {"config_file": (io.BytesIO(NONCOMPLIANT.encode()), "noncomp.cfg")}
        resp = client.post("/upload", data=data, content_type="multipart/form-data")
        assert resp.status_code == 302

        with client.application.app_context():
            records = AuditRecord.query.all()
            assert len(records) == 1
            assert records[0].hostname == "NONCOMPLIANT-SW01"
            assert records[0].count_total > 0
            assert len(records[0].findings) > 0

    def test_upload_compliant_file(self, client, db):
        data = {"config_file": (io.BytesIO(COMPLIANT.encode()), "compliant.cfg")}
        resp = client.post("/upload", data=data, content_type="multipart/form-data")
        assert resp.status_code == 302

        with client.application.app_context():
            records = AuditRecord.query.all()
            assert len(records) == 1
            assert records[0].count_total == 0

    def test_upload_empty_file(self, client):
        data = {"config_file": (io.BytesIO(b""), "empty.cfg")}
        resp = client.post(
            "/upload", data=data, content_type="multipart/form-data", follow_redirects=True
        )
        assert resp.status_code == 200
        assert b"empty" in resp.data.lower()

    def test_upload_no_file(self, client):
        resp = client.post(
            "/upload", data={}, content_type="multipart/form-data", follow_redirects=True
        )
        assert resp.status_code == 200
        assert b"No file" in resp.data


class TestSSH:
    def test_ssh_form_renders(self, client):
        resp = client.get("/ssh")
        assert resp.status_code == 200
        assert b"SSH" in resp.data

    def test_ssh_success(self, client, db, monkeypatch):
        monkeypatch.setattr(
            "cisco_audit.web.routes.fetch_running_config",
            lambda **kwargs: NONCOMPLIANT,
        )
        resp = client.post(
            "/ssh",
            data={
                "host": "10.0.0.1",
                "port": "22",
                "username": "admin",
                "password": "secret",
            },
        )
        assert resp.status_code == 302

        with client.application.app_context():
            records = AuditRecord.query.all()
            assert len(records) == 1
            assert records[0].source == "ssh"
            assert records[0].source_detail == "10.0.0.1:22"

    def test_ssh_connection_failure(self, client, monkeypatch):
        monkeypatch.setattr(
            "cisco_audit.web.routes.fetch_running_config",
            lambda **kwargs: (_ for _ in ()).throw(ConnectionError("timeout")),
        )
        resp = client.post(
            "/ssh",
            data={
                "host": "10.0.0.1",
                "port": "22",
                "username": "admin",
                "password": "secret",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"SSH connection failed" in resp.data

    def test_ssh_missing_fields(self, client):
        resp = client.post(
            "/ssh",
            data={"host": "", "username": "", "password": ""},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"required" in resp.data.lower()


class TestReport:
    def test_report_detail(self, client, db):
        data = {"config_file": (io.BytesIO(NONCOMPLIANT.encode()), "test.cfg")}
        client.post("/upload", data=data, content_type="multipart/form-data")

        with client.application.app_context():
            record = AuditRecord.query.first()
            record_id = record.id

        resp = client.get(f"/report/{record_id}")
        assert resp.status_code == 200
        assert b"NONCOMPLIANT-SW01" in resp.data

    def test_report_not_found(self, client):
        resp = client.get("/report/999", follow_redirects=True)
        assert resp.status_code == 200
        assert b"not found" in resp.data.lower()

    def test_report_delete(self, client, db):
        data = {"config_file": (io.BytesIO(NONCOMPLIANT.encode()), "test.cfg")}
        client.post("/upload", data=data, content_type="multipart/form-data")

        with client.application.app_context():
            record_id = AuditRecord.query.first().id

        resp = client.post(f"/report/{record_id}/delete", follow_redirects=True)
        assert resp.status_code == 200
        assert b"deleted" in resp.data.lower()

        with client.application.app_context():
            assert AuditRecord.query.count() == 0
            assert FindingRecord.query.count() == 0


class TestHistory:
    def test_history_empty(self, client):
        resp = client.get("/history")
        assert resp.status_code == 200
        assert b"No audit records" in resp.data

    def test_history_with_records(self, client, db):
        record = AuditRecord(
            hostname="SW02",
            source="file",
            source_detail="sw02.cfg",
            count_total=5,
        )
        db.session.add(record)
        db.session.commit()

        resp = client.get("/history")
        assert resp.status_code == 200
        assert b"SW02" in resp.data

    def test_history_pagination(self, client, db):
        for i in range(25):
            db.session.add(
                AuditRecord(
                    hostname=f"SW-{i:02d}",
                    source="file",
                    source_detail=f"sw{i}.cfg",
                    count_total=i,
                )
            )
        db.session.commit()

        resp1 = client.get("/history?page=1")
        assert resp1.status_code == 200
        # Page 1 should have 20 items
        assert b"Next" in resp1.data

        resp2 = client.get("/history?page=2")
        assert resp2.status_code == 200
        assert b"Previous" in resp2.data

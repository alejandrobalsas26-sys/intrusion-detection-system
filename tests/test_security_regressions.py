"""Regression coverage for persistence, authorization and authentication failures."""

import json
import logging
import socket
import sqlite3
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from unittest.mock import MagicMock

import pyotp
import pytest

import auth.core as auth
import dashboard.queries as queries
import fim.monitor as fim
from auth.crypto import crypto
from dashboard import create_app
from detection.correlation import CorrelationEngine, rule_network_then_fim, rule_recon_then_auth
from detection.intel import ThreatIntel
from detection.normalize import NormalizedEvent, from_audit_row
from logs.integrity import seal_audit_log, verify_audit_log
from logs.logger import SQLiteAuditHandler
from logs.maintenance import purge_old_events
from network.detectors import DetectionEvent


@pytest.fixture
def store(tmp_path, monkeypatch):
    db = str(tmp_path / "ids.sqlite3")
    monkeypatch.setattr(auth, "DB_PATH", db)
    monkeypatch.setattr(fim, "DB_PATH", db)
    monkeypatch.setattr(queries, "DB_PATH", db)
    monkeypatch.setenv("MFA_BACKOFF_MODE", "reject")
    for module, name in ((auth, "auth_core"), (fim, "fim_monitor")):
        logger = logging.Logger(name)
        logger.addHandler(SQLiteAuditHandler(db, str(tmp_path / "failsafe.log")))
        monkeypatch.setattr(module, "logger", logger)
        monkeypatch.setattr(module, "send_security_alert", MagicMock())
    auth._bootstrap_auth_db()
    secret = pyotp.random_base32()
    with closing(sqlite3.connect(db)) as conn, conn:
        cursor = conn.execute(
            "INSERT INTO users (username, encrypted_secret, role) VALUES ('alice', ?, 'admin')",
            (crypto.encrypt(secret),),
        )
        user_id = cursor.lastrowid
    return db, secret, user_id


def execute(db, statement, params=()):
    with closing(sqlite3.connect(db)) as conn, conn:
        return conn.execute(statement, params).fetchall()


def test_totp_concurrent_consumption_has_one_winner(store):
    _, secret, _ = store
    token = pyotp.TOTP(secret).now()
    with ThreadPoolExecutor(max_workers=2) as pool:
        events = list(pool.map(lambda _: auth.verify_token("alice", token), range(2)))
    assert sorted(event.event_name for event in events) == ["AUTH_SUCCESS", "REPLAY_ATTACK"]


def test_totp_digits_can_repeat_in_a_later_interval(store, monkeypatch):
    db, _, _ = store
    now = int(time.time() // 30) * 30 + 1
    monkeypatch.setattr(pyotp.TOTP, "at", lambda self, timestamp: "123456")
    monkeypatch.setattr(auth.time, "time", lambda: now)
    assert auth.verify_token("alice", "123456").event_name == "AUTH_SUCCESS"
    assert auth.verify_token("alice", "123456").event_name == "REPLAY_ATTACK"
    monkeypatch.setattr(auth.time, "time", lambda: now + 60)
    assert auth.verify_token("alice", "123456").event_name == "AUTH_SUCCESS"
    assert len(execute(db, "SELECT * FROM totp_consumptions")) == 2


def test_invalid_attempt_does_not_reserve_a_future_valid_code(store, monkeypatch):
    db, _, _ = store
    monkeypatch.setattr(pyotp.TOTP, "at", lambda self, timestamp: "654321")
    assert auth.verify_token("alice", "123456").event_name == "AUTH_FAILURE"
    execute(db, "UPDATE auth_attempts SET timestamp = datetime('now', '-10 seconds')")
    monkeypatch.setattr(pyotp.TOTP, "at", lambda self, timestamp: "123456")
    assert auth.verify_token("alice", "123456").event_name == "AUTH_SUCCESS"


def test_reject_backoff_expires_at_cooldown_not_failure_window(store):
    db, secret, user_id = store
    execute(
        db,
        "INSERT INTO auth_attempts (user_id, success, token_fingerprint) VALUES (?, 0, 'wrong')",
        (user_id,),
    )
    token = pyotp.TOTP(secret).now()
    limited = auth.verify_token("alice", token)
    assert limited.event_name == "RATE_LIMITED"
    assert 0 < limited.context["backoff_applied_seconds"] <= 2
    execute(db, "UPDATE auth_attempts SET timestamp = datetime('now', '-3 seconds')")
    assert auth.verify_token("alice", token).event_name == "AUTH_SUCCESS"


def test_recovery_code_concurrent_consumption_has_one_winner(store):
    db, _, user_id = store
    hashed, salt = auth._hash_recovery_code("ABCD1234")
    execute(
        db,
        "INSERT INTO recovery_codes (user_id, hashed_code, salt) VALUES (?, ?, ?)",
        (user_id, hashed, salt),
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        events = list(pool.map(lambda _: auth.use_recovery_code("alice", "ABCD1234"), range(2)))
    assert sum(event.event_name == "AUTH_SUCCESS" for event in events) == 1
    assert execute(db, "SELECT * FROM recovery_codes") == []


def test_http_account_backoff_reports_remaining_retry_after(store):
    db, secret, user_id = store
    execute(
        db,
        "INSERT INTO auth_attempts (user_id, success, token_fingerprint) VALUES (?, 0, 'wrong')",
        (user_id,),
    )
    app = create_app()
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    response = app.test_client().post(
        "/login", data={"username": "alice", "totp_code": pyotp.TOTP(secret).now()}
    )
    assert response.status_code == 429
    assert 0 < int(response.headers["Retry-After"]) <= 2


def test_existing_auth_schema_migrates_without_reenrollment(store):
    db, secret, user_id = store
    execute(db, "DROP TABLE auth_attempts")
    execute(
        db,
        "CREATE TABLE auth_attempts (id INTEGER PRIMARY KEY, user_id INTEGER, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, success BOOLEAN, token_fingerprint TEXT)",
    )
    execute(
        db, "CREATE UNIQUE INDEX idx_replay_protection ON auth_attempts(user_id, token_fingerprint)"
    )
    auth._bootstrap_auth_db()
    columns = {row[1] for row in execute(db, "PRAGMA table_info(auth_attempts)")}
    assert "totp_step" in columns
    assert auth.verify_token("alice", pyotp.TOTP(secret).now()).event_name == "AUTH_SUCCESS"
    assert execute(db, "SELECT id FROM users WHERE username = 'alice'")[0][0] == user_id


def authenticated_client():
    app = create_app()
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    client = app.test_client()
    with client.session_transaction() as session:
        session.permanent = True
        session.update(user_id="alice", authenticated_at=time.time(), role="admin")
    return app, client


def test_session_obeys_live_role_and_revocation(store):
    db, _, _ = store
    _, client = authenticated_client()
    assert client.get("/api/users").status_code == 200
    auth.set_user_role("alice", "viewer")
    assert client.get("/api/users").status_code == 403
    auth.revoke_user("alice")
    assert client.get("/api/incidents").status_code == 401
    assert execute(db, "SELECT is_active FROM users WHERE username = 'alice'") == [(0,)]


def test_session_absolute_lifetime_survives_active_requests(store, monkeypatch):
    app, client = authenticated_client()
    with client.session_transaction() as session:
        started = session["authenticated_at"]
    assert app.config["SESSION_REFRESH_EACH_REQUEST"] is False
    for elapsed in (300, 600, 899):
        monkeypatch.setattr(
            "dashboard.security.time.time", lambda elapsed=elapsed: started + elapsed
        )
        assert client.get("/api/users").status_code == 200
    monkeypatch.setattr("dashboard.security.time.time", lambda: started + 900)
    assert client.get("/api/users").status_code == 401


@pytest.mark.parametrize("stamp", [None, float("nan"), float("inf"), "123"])
def test_session_without_valid_authentication_time_is_rejected(store, stamp):
    _, client = authenticated_client()
    with client.session_transaction() as session:
        session["authenticated_at"] = stamp
    assert client.get("/api/users").status_code == 401


def test_open_sse_stream_stops_after_revocation(store, monkeypatch):
    db, _, _ = store
    _, client = authenticated_client()
    monkeypatch.setattr("dashboard.routes.time.sleep", lambda seconds: None)
    response = client.get("/events/stream", buffered=False)
    iterator = iter(response.response)
    assert next(iterator)
    execute(db, "UPDATE users SET is_active = 0 WHERE username = 'alice'")
    assert list(iterator) == []
    response.close()


def test_created_files_all_persist_in_both_event_stores(store, tmp_path):
    db, _, _ = store
    watched = tmp_path / "protected"
    watched.mkdir()
    config = tmp_path / "fim.json"
    config.write_text(json.dumps({"critical_dirs": [{"path": str(watched)}]}))
    fim.initialize_baselines(str(config))
    for index in range(3):
        (watched / f"new{index}.txt").write_text("payload")
    fim.check_integrity()
    assert len(execute(db, "SELECT * FROM fim_events WHERE event_type = 'CREATED'")) == 3
    rows = execute(
        db,
        "SELECT context_data FROM audit_events WHERE module_source = 'fim_monitor' AND context_data IS NOT NULL",
    )
    assert len(rows) == 3
    assert all(json.loads(row[0])["host_id"] == socket.gethostname() for row in rows)
    assert len(execute(db, "SELECT * FROM file_baselines")) == 3
    fim.check_integrity()
    assert len(execute(db, "SELECT * FROM fim_events")) == 3
    assert not (tmp_path / "failsafe.log").exists()


def test_failed_created_audit_insert_does_not_silently_baseline(store, tmp_path):
    db, _, _ = store
    watched = tmp_path / "protected"
    watched.mkdir()
    config = tmp_path / "fim.json"
    config.write_text(json.dumps({"critical_dirs": [{"path": str(watched)}]}))
    fim.initialize_baselines(str(config))
    (watched / "new.txt").write_text("payload")
    execute(
        db,
        "CREATE TRIGGER reject_created BEFORE INSERT ON audit_events WHEN NEW.context_data LIKE '%CREATED%' BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
    )
    fim.check_integrity()
    assert execute(db, "SELECT * FROM file_baselines") == []
    assert execute(db, "SELECT * FROM fim_events") == []
    execute(db, "DROP TRIGGER reject_created")
    fim.check_integrity()
    assert len(execute(db, "SELECT * FROM fim_events")) == 1


@pytest.mark.parametrize("where", ["1=1", "id <= 2", "id = 1"])
def test_manual_deletion_of_sealed_rows_is_detected(store, where):
    db, _, _ = store
    for index in range(3):
        execute(
            db,
            "INSERT INTO audit_events (timestamp, level, module_source, message) VALUES (?, 'INFO', 'test', ?)",
            (time.time(), str(index)),
        )
    seal_audit_log(db)
    execute(db, "DELETE FROM audit_events WHERE " + where)
    assert not verify_audit_log(db).ok


def test_partial_retention_still_detects_modified_surviving_row(store):
    db, _, _ = store
    for index in range(3):
        timestamp = time.time() - 100 * 86400 if index == 1 else time.time()
        execute(
            db,
            "INSERT INTO audit_events (timestamp, level, module_source, message) VALUES (?, 'INFO', 'test', ?)",
            (timestamp, str(index)),
        )
    seal_audit_log(db)
    assert purge_old_events(90, db).audit_events == 1
    result = verify_audit_log(db)
    assert result.ok and result.partial == 1 and result.verified == 1
    execute(db, "UPDATE audit_events SET message = 'tampered' WHERE id = 3")
    assert not verify_audit_log(db).ok


def test_smtp_starttls_uses_certificate_and_hostname_verification(monkeypatch):
    import alerts.email_alert as email

    monkeypatch.setenv("EMAIL_SENDER", "sender@example.com")
    monkeypatch.setenv("EMAIL_PASSWORD", "test-password")
    monkeypatch.setenv("ALERT_RECEIVER", "receiver@example.com")
    smtp = MagicMock()
    monkeypatch.setattr(email.smtplib, "SMTP", lambda *args, **kwargs: smtp)
    email.send_security_alert("CRITICAL", "test", "test message")
    context = smtp.__enter__.return_value.starttls.call_args.kwargs["context"]
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def chain_events():
    recon = NormalizedEvent(
        100,
        "CRITICAL",
        "network",
        "syn_scan",
        "recon",
        "2001:db8::9",
        context={"host_id": "host-a", "source_ip": "2001:db8::9"},
    )
    failure = NormalizedEvent(
        110,
        "WARNING",
        "auth",
        "AUTH_FAILURE",
        "failure",
        "alice",
        context={"host_id": "host-a", "source_ip": "2001:db8::9"},
    )
    tamper = NormalizedEvent(
        120, "CRITICAL", "fim", "FIM_MODIFIED", "tamper", "/file", context={"host_id": "host-a"}
    )
    return recon, failure, tamper


def test_correlation_requires_known_matching_host_and_source():
    recon, failure, tamper = chain_events()
    assert rule_recon_then_auth([recon, failure])
    assert rule_network_then_fim([recon, tamper])
    failure.context["source_ip"] = "2001:db8::8"
    assert rule_recon_then_auth([recon, failure]) == []
    tamper.context["host_id"] = "host-b"
    assert rule_network_then_fim([recon, tamper]) == []
    recon.context.clear()
    assert rule_recon_then_auth([recon, failure]) == []
    assert rule_network_then_fim([recon, tamper]) == []


def test_live_sensor_keeps_domain_and_ipv6_for_ioc_incidents(store, tmp_path, monkeypatch):
    import network.sensor as sensor

    db, _, _ = store
    logger = logging.Logger("network_sensor")
    logger.addHandler(SQLiteAuditHandler(db, str(tmp_path / "failsafe.log")))
    monkeypatch.setattr(sensor, "logger", logger)
    monkeypatch.setenv("NETWORK_MONITOR_CONSENT", "true")
    monkeypatch.setattr(sensor, "_check_os_privileges", lambda: True)
    event = DetectionEvent(
        level="CRITICAL",
        module_source="network",
        detector_name="dns_watchlist",
        message="matched DNS",
        timestamp=time.time(),
        context={"source_ip": "2001:db8::9", "domain": "evil.example"},
    )
    detector = MagicMock()
    detector.process_packet.return_value = event
    monkeypatch.setattr(sensor, "build_default_detectors", lambda: [detector])
    monkeypatch.setattr(
        sensor, "send_security_alert", MagicMock(side_effect=RuntimeError("SMTP down"))
    )
    callbacks = {}

    class CaptureThread:
        def __init__(self, **kwargs):
            callbacks.update(kwargs["kwargs"])

        def start(self):
            pass

    monkeypatch.setattr(sensor.threading, "Thread", CaptureThread)
    sensor.start_sensor()
    callbacks["prn"](object())
    row = execute(
        db,
        "SELECT id, timestamp, level, module_source, message, context_data FROM audit_events WHERE module_source='network_sensor' AND context_data IS NOT NULL",
    )[0]
    normalized = from_audit_row(
        dict(
            zip(
                ("id", "timestamp", "level", "module_source", "message", "context_data"),
                row,
                strict=True,
            )
        )
    )
    assert normalized.entity == "2001:db8::9"
    assert normalized.event_name == "dns_watchlist"
    assert normalized.context["domain"] == "evil.example"
    domain_list = tmp_path / "domains.txt"
    domain_list.write_text("evil.example\n")
    monkeypatch.setenv("IOC_DOMAIN_LIST_PATH", str(domain_list))
    assert ThreatIntel.from_env().has_indicators()
    engine = CorrelationEngine(db_path=db)
    assert engine.sweep() == 1
    entities = json.loads(
        execute(db, "SELECT entities FROM incidents WHERE rule_name='ioc_match'")[0][0]
    )
    assert "evil.example" in entities

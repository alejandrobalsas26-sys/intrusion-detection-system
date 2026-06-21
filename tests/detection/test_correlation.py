"""Integration tests for the correlation engine and event deduplicator."""

import contextlib
import json
import sqlite3
import time
import unittest
from pathlib import Path

from detection.correlation import (
    CorrelationEngine,
    rule_auth_success_after_failures,
    rule_brute_force,
    rule_network_then_fim,
    rule_password_spray,
    rule_recon_then_auth,
    rule_replay_attack,
)
from detection.dedup import EventDeduplicator
from detection.normalize import NormalizedEvent

REPO_ROOT = Path(__file__).parent.parent.parent


def _make_event(name, entity, severity="WARNING", category="auth", ts=None):
    return NormalizedEvent(
        timestamp=ts if ts is not None else time.time(),
        severity=severity,
        category=category,
        event_name=name,
        message=f"{name} for {entity}",
        entity=entity,
    )


class TestCorrelationRules(unittest.TestCase):
    def test_brute_force_fires_at_threshold(self):
        base = time.time()
        events = [
            _make_event("AUTH_FAILURE", "alice", ts=base + i) for i in range(5)
        ]
        incidents = rule_brute_force(events, threshold=5, window_seconds=300)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].rule_name, "brute_force_burst")
        self.assertIn("alice", incidents[0].entities)
        self.assertIn("T1110", incidents[0].mitre_techniques)

    def test_brute_force_below_threshold_is_silent(self):
        base = time.time()
        events = [_make_event("AUTH_FAILURE", "alice", ts=base + i) for i in range(4)]
        self.assertEqual(rule_brute_force(events, threshold=5, window_seconds=300), [])

    def test_brute_force_ignores_failures_outside_window(self):
        base = time.time()
        events = [
            _make_event("AUTH_FAILURE", "alice", ts=base + i * 400) for i in range(5)
        ]
        self.assertEqual(rule_brute_force(events, threshold=5, window_seconds=300), [])

    def test_replay_attack_is_single_event_incident(self):
        events = [_make_event("REPLAY_ATTACK", "eve", severity="CRITICAL")]
        incidents = rule_replay_attack(events)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].severity, "CRITICAL")

    def test_recon_then_auth_chain(self):
        base = time.time()
        events = [
            _make_event("syn_scan", "10.0.0.9", severity="CRITICAL",
                        category="network", ts=base),
            _make_event("AUTH_FAILURE", "alice", ts=base + 60),
        ]
        incidents = rule_recon_then_auth(events, window_seconds=1800)
        self.assertEqual(len(incidents), 1)
        # Cross-category chain must include both entities
        self.assertIn("10.0.0.9", incidents[0].entities)
        self.assertIn("alice", incidents[0].entities)

    def test_recon_without_followup_is_silent(self):
        events = [
            _make_event("syn_scan", "10.0.0.9", severity="CRITICAL", category="network")
        ]
        self.assertEqual(rule_recon_then_auth(events), [])

    def test_network_then_fim_chain(self):
        base = time.time()
        events = [
            _make_event("arp_spoofing", "10.0.0.7", severity="CRITICAL",
                        category="network", ts=base),
            _make_event("FIM_MODIFIED", "/etc/passwd", severity="CRITICAL",
                        category="fim", ts=base + 120),
        ]
        incidents = rule_network_then_fim(events, window_seconds=1800)
        self.assertEqual(len(incidents), 1)
        # Cross-category incidents score higher than either event alone
        self.assertGreater(incidents[0].risk_score, max(e.risk_score for e in events))


class TestPasswordSprayRule(unittest.TestCase):
    def test_fires_when_many_distinct_users_fail(self):
        base = time.time()
        events = [
            _make_event("AUTH_FAILURE", f"user{i}", ts=base + i) for i in range(5)
        ]
        incidents = rule_password_spray(events, user_threshold=5, window_seconds=300)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].rule_name, "password_spray")
        self.assertIn("T1110.003", incidents[0].mitre_techniques)
        self.assertEqual(len(incidents[0].entities), 5)

    def test_silent_below_user_threshold(self):
        base = time.time()
        events = [
            _make_event("AUTH_FAILURE", f"user{i}", ts=base + i) for i in range(4)
        ]
        self.assertEqual(rule_password_spray(events, user_threshold=5), [])

    def test_silent_when_users_spread_outside_window(self):
        base = time.time()
        events = [
            _make_event("AUTH_FAILURE", f"user{i}", ts=base + i * 100) for i in range(5)
        ]
        self.assertEqual(
            rule_password_spray(events, user_threshold=5, window_seconds=120), []
        )

    def test_single_user_burst_is_not_spray(self):
        """A single user failing many times is brute force, not spray."""
        base = time.time()
        events = [_make_event("AUTH_FAILURE", "alice", ts=base + i) for i in range(10)]
        self.assertEqual(rule_password_spray(events, user_threshold=5), [])


class TestAuthSuccessAfterFailuresRule(unittest.TestCase):
    def test_fires_on_success_after_failure_burst(self):
        base = time.time()
        events = [_make_event("AUTH_FAILURE", "alice", ts=base + i) for i in range(5)]
        events.append(
            _make_event("AUTH_SUCCESS", "alice", severity="INFO", ts=base + 6)
        )
        incidents = rule_auth_success_after_failures(
            events, threshold=5, window_seconds=600
        )
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].rule_name, "auth_success_after_failures")
        self.assertIn("T1078", incidents[0].mitre_techniques)
        # The success event must be part of the incident chain.
        self.assertTrue(
            any(e.event_name == "AUTH_SUCCESS" for e in incidents[0].events)
        )

    def test_silent_without_enough_prior_failures(self):
        base = time.time()
        events = [_make_event("AUTH_FAILURE", "alice", ts=base + i) for i in range(3)]
        events.append(_make_event("AUTH_SUCCESS", "alice", severity="INFO", ts=base + 4))
        self.assertEqual(
            rule_auth_success_after_failures(events, threshold=5), []
        )

    def test_silent_when_failures_outside_window(self):
        base = time.time()
        events = [_make_event("AUTH_FAILURE", "alice", ts=base + i) for i in range(5)]
        events.append(
            _make_event("AUTH_SUCCESS", "alice", severity="INFO", ts=base + 5000)
        )
        self.assertEqual(
            rule_auth_success_after_failures(events, threshold=5, window_seconds=600), []
        )

    def test_silent_when_success_is_for_different_user(self):
        base = time.time()
        events = [_make_event("AUTH_FAILURE", "alice", ts=base + i) for i in range(5)]
        events.append(_make_event("AUTH_SUCCESS", "bob", severity="INFO", ts=base + 6))
        self.assertEqual(
            rule_auth_success_after_failures(events, threshold=5, window_seconds=600), []
        )


class TestCorrelationEngineEndToEnd(unittest.TestCase):
    def setUp(self):
        self.db_dir = Path("tests/temp_detection")
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = str(self.db_dir / "test_corr.sqlite3")
        # Fresh DB per test
        db_file = Path(self.db_path)
        if db_file.exists():
            db_file.unlink()
        with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
            with open(REPO_ROOT / "logs" / "schema.sql", encoding="utf-8") as f:
                conn.executescript(f.read())

    def tearDown(self):
        for f in self.db_dir.glob("*"):
            try:
                f.unlink()
            except OSError:
                pass

    def _insert_audit(self, ts, level, module, message, context=None):
        with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                "INSERT INTO audit_events (timestamp, level, module_source, message, "
                "context_data) VALUES (?, ?, ?, ?, ?)",
                (ts, level, module, message, json.dumps(context) if context else None),
            )
            conn.commit()

    def test_sweep_creates_incident_and_is_idempotent(self):
        base = time.time()
        for i in range(6):
            self._insert_audit(
                base + i,
                "WARNING",
                "auth_core",
                "Authentication failed for user 'alice'.",
                {"reason_code": "INVALID_TOKEN"},
            )

        engine = CorrelationEngine(db_path=self.db_path, lookback_seconds=3600)
        created = engine.sweep()
        self.assertGreaterEqual(created, 1)

        # Idempotency: same data, second sweep must create nothing new.
        self.assertEqual(engine.sweep(), 0)

        with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM incidents").fetchall()
        self.assertEqual(len(rows), 1)
        incident = dict(rows[0])
        self.assertEqual(incident["rule_name"], "brute_force_burst")
        self.assertEqual(incident["status"], "open")
        self.assertIn("alice", json.loads(incident["entities"]))
        self.assertIn("T1110", json.loads(incident["mitre_techniques"]))
        self.assertGreater(incident["risk_score"], 0)

    def test_sweep_with_no_events_is_quiet(self):
        engine = CorrelationEngine(db_path=self.db_path)
        self.assertEqual(engine.sweep(), 0)

    def test_sweep_detects_password_spray_end_to_end(self):
        base = time.time()
        for i in range(6):
            self._insert_audit(
                base + i,
                "WARNING",
                "auth_core",
                f"Authentication failed for user 'spray_user_{i}'.",
                {"reason_code": "INVALID_TOKEN"},
            )
        engine = CorrelationEngine(db_path=self.db_path, lookback_seconds=3600)
        self.assertGreaterEqual(engine.sweep(), 1)

        with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM incidents WHERE rule_name = 'password_spray'"
            ).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertIn("T1110.003", json.loads(rows[0]["mitre_techniques"]))

    def test_sweep_detects_success_after_failures_end_to_end(self):
        base = time.time()
        for i in range(5):
            self._insert_audit(
                base + i,
                "WARNING",
                "auth_core",
                "Authentication failed for user 'victim'.",
                {"reason_code": "INVALID_TOKEN"},
            )
        self._insert_audit(
            base + 6,
            "INFO",
            "auth_core",
            "User 'victim' authenticated successfully.",
            {"reason_code": "VALID_TOKEN"},
        )
        engine = CorrelationEngine(db_path=self.db_path, lookback_seconds=3600)
        engine.sweep()

        with contextlib.closing(sqlite3.connect(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM incidents WHERE rule_name = 'auth_success_after_failures'"
            ).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertIn("T1078", json.loads(rows[0]["mitre_techniques"]))

    def test_broken_rule_does_not_abort_sweep(self):
        base = time.time()
        self._insert_audit(
            base, "CRITICAL", "auth_core", "Replay attack detected for user 'eve'.", {}
        )

        def broken_rule(events):
            raise RuntimeError("boom")

        from detection.correlation import rule_replay_attack as ok_rule

        engine = CorrelationEngine(
            db_path=self.db_path, rules=(broken_rule, ok_rule)
        )
        self.assertEqual(engine.sweep(), 1)


class TestEventDeduplicator(unittest.TestCase):
    def test_first_sighting_is_not_duplicate(self):
        dedup = EventDeduplicator(window_seconds=60)
        fp = EventDeduplicator.fingerprint("syn_scan", "10.0.0.9", "CRITICAL")
        self.assertFalse(dedup.is_duplicate(fp, now=100.0))

    def test_repeat_inside_window_is_duplicate(self):
        dedup = EventDeduplicator(window_seconds=60)
        fp = EventDeduplicator.fingerprint("syn_scan", "10.0.0.9", "CRITICAL")
        dedup.is_duplicate(fp, now=100.0)
        self.assertTrue(dedup.is_duplicate(fp, now=130.0))

    def test_repeat_after_window_is_fresh(self):
        dedup = EventDeduplicator(window_seconds=60)
        fp = EventDeduplicator.fingerprint("syn_scan", "10.0.0.9", "CRITICAL")
        dedup.is_duplicate(fp, now=100.0)
        self.assertFalse(dedup.is_duplicate(fp, now=161.0))

    def test_distinct_events_do_not_collide(self):
        dedup = EventDeduplicator(window_seconds=60)
        fp_a = EventDeduplicator.fingerprint("syn_scan", "10.0.0.9")
        fp_b = EventDeduplicator.fingerprint("syn_scan", "10.0.0.10")
        self.assertFalse(dedup.is_duplicate(fp_a, now=100.0))
        self.assertFalse(dedup.is_duplicate(fp_b, now=100.0))

    def test_memory_bound_under_unique_flood(self):
        dedup = EventDeduplicator(window_seconds=60, max_entries=100)
        for i in range(500):
            dedup.is_duplicate(f"fp-{i}", now=100.0 + i * 0.01)
        self.assertLessEqual(len(dedup._seen), 200)


if __name__ == "__main__":
    unittest.main()

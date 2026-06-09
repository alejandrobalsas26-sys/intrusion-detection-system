"""Sliding-window correlation engine.

Reads recent `audit_events` rows, normalizes them, applies correlation rules,
and persists resulting incidents to the additive `incidents` table. Re-running
a sweep over the same data is idempotent: each incident carries a stable
`dedupe_key` and is inserted with INSERT OR IGNORE.

Rules implemented:
  * brute_force_burst      — >= threshold AUTH_FAILUREs for one user in a window
  * replay_attack          — any REPLAY_ATTACK event escalates immediately
  * recon_then_auth        — network recon followed by authentication failures
  * network_then_fim       — network attack followed by file-integrity violation
"""

import contextlib
import hashlib
import json
import os
import sqlite3
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from detection.normalize import NormalizedEvent, from_audit_row
from detection.scoring import incident_score
from logs.logger import get_logger

logger = get_logger("detection_engine")

_SEVERITY_ORDER = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}

BRUTE_FORCE_THRESHOLD = int(os.getenv("CORRELATION_BRUTE_FORCE_THRESHOLD", "5"))
BRUTE_FORCE_WINDOW = int(os.getenv("CORRELATION_BRUTE_FORCE_WINDOW_SECONDS", "300"))
CHAIN_WINDOW = int(os.getenv("CORRELATION_CHAIN_WINDOW_SECONDS", "1800"))


@dataclass
class IncidentCandidate:
    rule_name: str
    title: str
    summary: str
    events: list[NormalizedEvent] = field(default_factory=list)

    @property
    def severity(self) -> str:
        worst = max(self.events, key=lambda e: _SEVERITY_ORDER.get(e.severity, 0))
        return worst.severity

    @property
    def entities(self) -> list[str]:
        seen: list[str] = []
        for e in self.events:
            if e.entity and e.entity not in seen:
                seen.append(e.entity)
        return seen

    @property
    def mitre_techniques(self) -> list[str]:
        seen: list[str] = []
        for e in self.events:
            for t in e.mitre_techniques:
                if t not in seen:
                    seen.append(t)
        return seen

    @property
    def risk_score(self) -> int:
        categories = {e.category for e in self.events}
        return incident_score([e.risk_score for e in self.events], len(categories))

    def dedupe_key(self) -> str:
        """Stable across overlapping sweeps: anchored to the first event."""
        first = min(self.events, key=lambda e: e.timestamp)
        anchor = first.event_id if first.event_id is not None else int(first.timestamp)
        raw = f"{self.rule_name}|{'|'.join(sorted(self.entities))}|{anchor}"
        return hashlib.sha256(raw.encode()).hexdigest()


def rule_brute_force(
    events: list[NormalizedEvent],
    threshold: int = BRUTE_FORCE_THRESHOLD,
    window_seconds: int = BRUTE_FORCE_WINDOW,
) -> list[IncidentCandidate]:
    """N or more auth failures for the same user inside the window."""
    failures: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for e in events:
        if e.event_name in ("AUTH_FAILURE", "RATE_LIMITED") and e.entity:
            failures[e.entity].append(e)

    candidates = []
    for user, evts in failures.items():
        evts.sort(key=lambda e: e.timestamp)
        # Largest cluster that fits in the window, anchored at the earliest event.
        for i, anchor in enumerate(evts):
            cluster = [x for x in evts[i:] if x.timestamp - anchor.timestamp <= window_seconds]
            if len(cluster) >= threshold:
                candidates.append(
                    IncidentCandidate(
                        rule_name="brute_force_burst",
                        title=f"Brute force suspected against user '{user}'",
                        summary=(
                            f"{len(cluster)} authentication failures for '{user}' within "
                            f"{window_seconds}s (threshold {threshold})."
                        ),
                        events=cluster,
                    )
                )
                break  # one incident per user per sweep, anchored at first burst
    return candidates


def rule_replay_attack(events: list[NormalizedEvent]) -> list[IncidentCandidate]:
    """Replay attacks are single-event incidents: token theft is in progress."""
    return [
        IncidentCandidate(
            rule_name="replay_attack",
            title=f"Token replay attack against user '{e.entity or 'unknown'}'",
            summary=e.message,
            events=[e],
        )
        for e in events
        if e.event_name == "REPLAY_ATTACK"
    ]


def rule_recon_then_auth(
    events: list[NormalizedEvent], window_seconds: int = CHAIN_WINDOW
) -> list[IncidentCandidate]:
    """Network reconnaissance followed by authentication failures (kill chain)."""
    recon = [e for e in events if e.event_name in ("syn_scan", "arp_spoofing")]
    auth_failures = [e for e in events if e.event_name == "AUTH_FAILURE"]
    candidates = []
    for r in recon:
        followers = [
            a for a in auth_failures if 0 <= a.timestamp - r.timestamp <= window_seconds
        ]
        if followers:
            chain = [r] + followers
            candidates.append(
                IncidentCandidate(
                    rule_name="recon_then_auth",
                    title="Recon followed by authentication attempts",
                    summary=(
                        f"{r.event_name} from {r.entity or 'unknown source'} followed by "
                        f"{len(followers)} auth failure(s) within {window_seconds}s."
                    ),
                    events=chain,
                )
            )
    return candidates


def rule_network_then_fim(
    events: list[NormalizedEvent], window_seconds: int = CHAIN_WINDOW
) -> list[IncidentCandidate]:
    """Network attack followed by file tampering: likely successful intrusion."""
    network_critical = [
        e for e in events if e.category == "network" and e.severity == "CRITICAL"
    ]
    fim_events = [e for e in events if e.category == "fim"]
    candidates = []
    for n in network_critical:
        tampering = [
            f for f in fim_events if 0 <= f.timestamp - n.timestamp <= window_seconds
        ]
        if tampering:
            candidates.append(
                IncidentCandidate(
                    rule_name="network_then_fim",
                    title="Network attack followed by file integrity violation",
                    summary=(
                        f"{n.event_name} from {n.entity or 'unknown source'} followed by "
                        f"{len(tampering)} file integrity event(s) within {window_seconds}s."
                    ),
                    events=[n] + tampering,
                )
            )
    return candidates


DEFAULT_RULES = (
    rule_brute_force,
    rule_replay_attack,
    rule_recon_then_auth,
    rule_network_then_fim,
)


class CorrelationEngine:
    """Loads recent events, applies rules, persists incidents idempotently."""

    def __init__(
        self,
        db_path: str | None = None,
        lookback_seconds: int = 3600,
        rules: tuple = DEFAULT_RULES,
    ):
        self.db_path = db_path or os.getenv("DB_PATH", "./logs/ids_database.sqlite3")
        self.lookback_seconds = lookback_seconds
        self.rules = rules
        self._bootstrap()

    def _connect(self) -> contextlib.closing:
        # sqlite3's context manager only manages transactions, not the file
        # handle; close explicitly so Windows can release the lock.
        return contextlib.closing(sqlite3.connect(self.db_path))

    def _bootstrap(self) -> None:
        schema = Path(__file__).parent / "schema.sql"
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            with open(schema, encoding="utf-8") as f:
                conn.executescript(f.read())
            conn.commit()

    def load_events(self, since_ts: float | None = None) -> list[NormalizedEvent]:
        """Reads and normalizes audit_events newer than the lookback horizon."""
        horizon = since_ts if since_ts is not None else time.time() - self.lookback_seconds
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT id, timestamp, level, module_source, message, context_data
                FROM audit_events
                WHERE timestamp >= ?
                ORDER BY timestamp ASC
                """,
                (horizon,),
            ).fetchall()
        return [from_audit_row(dict(r)) for r in rows]

    def sweep(self, since_ts: float | None = None) -> int:
        """Runs all rules over the lookback window. Returns # of NEW incidents."""
        events = self.load_events(since_ts)
        candidates: list[IncidentCandidate] = []
        for rule in self.rules:
            try:
                candidates.extend(rule(events))
            except Exception:
                logger.exception(f"Correlation rule {getattr(rule, '__name__', rule)} failed")

        new_count = 0
        with self._connect() as conn:
            for c in candidates:
                cursor = conn.execute(
                    """
                    INSERT OR IGNORE INTO incidents
                        (created_at, rule_name, title, severity, risk_score,
                         mitre_techniques, entities, event_count,
                         first_event_ts, last_event_ts, summary, status, dedupe_key)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
                    """,
                    (
                        time.time(),
                        c.rule_name,
                        c.title,
                        c.severity,
                        c.risk_score,
                        json.dumps(c.mitre_techniques),
                        json.dumps(c.entities),
                        len(c.events),
                        min(e.timestamp for e in c.events),
                        max(e.timestamp for e in c.events),
                        c.summary,
                        c.dedupe_key(),
                    ),
                )
                new_count += cursor.rowcount
            conn.commit()

        if new_count:
            logger.warning(
                f"Correlation sweep created {new_count} new incident(s).",
                extra={"context": {"new_incidents": new_count, "rules": len(self.rules)}},
            )
        return new_count

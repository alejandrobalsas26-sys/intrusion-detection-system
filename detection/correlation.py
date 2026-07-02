"""Sliding-window correlation engine.

Reads recent `audit_events` rows, normalizes them, applies correlation rules,
and persists resulting incidents to the additive `incidents` table. Re-running
a sweep over the same data is idempotent: each incident carries a stable
`dedupe_key` and is inserted with INSERT OR IGNORE.

Rules implemented:
  * brute_force_burst              — >= threshold AUTH_FAILUREs for one user in a window
  * password_spray                 — failures against >= threshold DISTINCT users in a window
  * auth_success_after_failures    — a success following a burst of failures for one user
  * replay_attack                  — any REPLAY_ATTACK event escalates immediately
  * recon_then_auth                — network recon followed by authentication failures
  * network_then_fim               — network attack followed by file-integrity violation
  * ioc_match                      — entity matches a local threat-intel watchlist (opt-in)
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

from detection.intel import ThreatIntel
from detection.normalize import NormalizedEvent, from_audit_row
from detection.scoring import incident_score
from logs.logger import get_logger

logger = get_logger("detection_engine")

_SEVERITY_ORDER = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}

BRUTE_FORCE_THRESHOLD = int(os.getenv("CORRELATION_BRUTE_FORCE_THRESHOLD", "5"))
BRUTE_FORCE_WINDOW = int(os.getenv("CORRELATION_BRUTE_FORCE_WINDOW_SECONDS", "300"))
CHAIN_WINDOW = int(os.getenv("CORRELATION_CHAIN_WINDOW_SECONDS", "1800"))

# Password spray: distinct accounts attacked from a low-and-slow campaign that
# stays under the per-user brute-force threshold. Conservative default (5
# distinct users in 5 min) keeps false positives low on busy multi-user hosts.
PASSWORD_SPRAY_USER_THRESHOLD = int(
    os.getenv("CORRELATION_PASSWORD_SPRAY_USER_THRESHOLD", "5")
)
PASSWORD_SPRAY_WINDOW = int(
    os.getenv("CORRELATION_PASSWORD_SPRAY_WINDOW_SECONDS", "300")
)
# Successful authentication immediately following a run of failures for the same
# user — the signature of a brute force that finally landed, or a credential
# that was just compromised. Conservative default mirrors the brute-force count.
SUCCESS_AFTER_FAILURES_THRESHOLD = int(
    os.getenv("CORRELATION_SUCCESS_AFTER_FAILURES_THRESHOLD", "5")
)
SUCCESS_AFTER_FAILURES_WINDOW = int(
    os.getenv("CORRELATION_SUCCESS_AFTER_FAILURES_WINDOW_SECONDS", "600")
)


@dataclass
class IncidentCandidate:
    rule_name: str
    title: str
    summary: str
    events: list[NormalizedEvent] = field(default_factory=list)
    # Techniques evidenced by the rule itself rather than any single event
    # (e.g. password spraying is a property of the *pattern*, not one failure).
    # Defaults empty, so existing rules are unaffected.
    extra_techniques: list[str] = field(default_factory=list)

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
        for t in self.extra_techniques:
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
    recon = [e for e in events if e.event_name in ("syn_scan", "arp_spoofing", "icmp_sweep")]
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


def rule_password_spray(
    events: list[NormalizedEvent],
    user_threshold: int = PASSWORD_SPRAY_USER_THRESHOLD,
    window_seconds: int = PASSWORD_SPRAY_WINDOW,
) -> list[IncidentCandidate]:
    """Authentication failures against many DISTINCT users in one window.

    Complements ``rule_brute_force`` (which keys on a single user): a spray
    campaign deliberately stays under any single account's lockout/backoff by
    trying one or few passwords across a breadth of accounts. The signal is the
    number of distinct targeted users, not the per-user failure count.
    """
    failures = [
        e
        for e in events
        if e.event_name in ("AUTH_FAILURE", "RATE_LIMITED") and e.entity
    ]
    if len({f.entity for f in failures}) < user_threshold:
        return []  # cheap early exit before the O(n^2) anchor scan

    failures.sort(key=lambda e: e.timestamp)
    for i, anchor in enumerate(failures):
        window = [f for f in failures[i:] if f.timestamp - anchor.timestamp <= window_seconds]
        distinct_users = {f.entity for f in window}
        if len(distinct_users) >= user_threshold:
            return [
                IncidentCandidate(
                    rule_name="password_spray",
                    title=f"Password spray suspected across {len(distinct_users)} accounts",
                    summary=(
                        f"Authentication failures against {len(distinct_users)} distinct "
                        f"users within {window_seconds}s (threshold {user_threshold}) — "
                        "characteristic of password spraying (low-and-slow brute force "
                        "spread across many accounts)."
                    ),
                    events=window,
                    extra_techniques=["T1110.003"],
                )
            ]
    return []  # distinct-user count never concentrated inside one window


def rule_auth_success_after_failures(
    events: list[NormalizedEvent],
    threshold: int = SUCCESS_AFTER_FAILURES_THRESHOLD,
    window_seconds: int = SUCCESS_AFTER_FAILURES_WINDOW,
) -> list[IncidentCandidate]:
    """A successful login preceded by a burst of failures for the same user.

    This is the high-value tail of a brute-force attempt: the point where
    guessing succeeded, or a freshly compromised credential was first used.
    Legitimate users occasionally fat-finger a code, so the threshold matches
    the brute-force count to keep this low-noise and high-confidence.
    """
    failures: dict[str, list[NormalizedEvent]] = defaultdict(list)
    successes: list[NormalizedEvent] = []
    for e in events:
        if not e.entity:
            continue
        if e.event_name in ("AUTH_FAILURE", "RATE_LIMITED"):
            failures[e.entity].append(e)
        elif e.event_name == "AUTH_SUCCESS":
            successes.append(e)

    candidates = []
    for s in successes:
        prior = [
            f
            for f in failures.get(s.entity, [])
            if 0 <= s.timestamp - f.timestamp <= window_seconds
        ]
        if len(prior) >= threshold:
            chain = sorted(prior, key=lambda e: e.timestamp) + [s]
            candidates.append(
                IncidentCandidate(
                    rule_name="auth_success_after_failures",
                    title=(
                        f"Successful login after {len(prior)} failures for user '{s.entity}'"
                    ),
                    summary=(
                        f"User '{s.entity}' authenticated successfully after {len(prior)} "
                        f"failed attempt(s) within {window_seconds}s — possible successful "
                        "brute force or a compromised credential in use. Verify the login "
                        "is legitimate."
                    ),
                    events=chain,
                    extra_techniques=["T1078"],
                )
            )
    return candidates


def rule_ioc_match(
    events: list[NormalizedEvent], intel: ThreatIntel | None = None
) -> list[IncidentCandidate]:
    """Flags any event whose entity matches a local threat-intel indicator.

    A pure no-op unless the operator has configured IOC watchlists
    (``IOC_IP_LIST_PATH`` / ``IOC_DOMAIN_LIST_PATH``). One incident is raised per
    distinct matched entity, gathering every event that referenced it.
    """
    ti = intel if intel is not None else ThreatIntel.from_env()
    if not ti.has_indicators():
        return []

    matched: dict[str, list] = {}  # entity -> [indicator, [events]]
    for e in events:
        if not e.entity:
            continue
        indicator = ti.match(e.entity)
        if indicator:
            slot = matched.setdefault(e.entity, [indicator, []])
            slot[1].append(e)

    return [
        IncidentCandidate(
            rule_name="ioc_match",
            title=f"Threat-intel match: {entity}",
            summary=(
                f"Entity '{entity}' matched the known-bad indicator '{indicator}' across "
                f"{len(evts)} event(s). Treat the associated activity as hostile and "
                "investigate the source immediately."
            ),
            events=evts,
        )
        for entity, (indicator, evts) in matched.items()
    ]


DEFAULT_RULES = (
    rule_brute_force,
    rule_password_spray,
    rule_auth_success_after_failures,
    rule_replay_attack,
    rule_recon_then_auth,
    rule_network_then_fim,
    rule_ioc_match,
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

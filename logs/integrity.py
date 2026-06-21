"""Tamper-evident audit log sealing (hash chaining).

The audit store is append-only by design, but nothing stops an intruder with
database access from editing or deleting rows after the fact. This module adds a
lightweight, PKI-free integrity layer: an operator periodically *seals* the log,
folding every new ``audit_events`` row into a hash chained to the previous seal.
Verification later recomputes those chains and reports any modification,
deletion, or insertion within a sealed range.

Design choices that keep it safe and cheap:
  * It never touches the hot logging path — sealing is an out-of-band batch job
    (run it from the retention task or a scheduled command).
  * Each checkpoint is *independently* verifiable from its stored seed
    (``prev_chain_hash``), and checkpoints are chained to each other, so a
    forger must rewrite every subsequent checkpoint consistently — not just one
    row — to evade detection. For a stronger guarantee, export the latest
    ``chain_hash`` to off-box/WORM storage as an anchor.
  * It coexists with retention: segments whose rows have legitimately aged out
    below the current minimum id are reported as "aged out", not as tampering.

Returns plain dataclasses; no exceptions for the expected "tamper found" path so
callers can branch on the result.
"""

import contextlib
import hashlib
import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

GENESIS = "GENESIS"
_FIELD_SEP = "\x1e"  # record separator, won't appear in audit text
_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def _db_path(db_path: str | None = None) -> str:
    return db_path or os.getenv("DB_PATH", "./logs/ids_database.sqlite3")


def _connect(db_path: str) -> contextlib.closing:
    return contextlib.closing(sqlite3.connect(db_path))


def _ensure_schema(conn: sqlite3.Connection) -> None:
    with open(_SCHEMA_PATH, encoding="utf-8") as f:
        conn.executescript(f.read())


def _row_fingerprint(row: sqlite3.Row) -> str:
    """Stable per-row hash over every persisted column."""
    raw = _FIELD_SEP.join(
        (
            str(row["id"]),
            repr(row["timestamp"]),
            row["level"] or "",
            row["module_source"] or "",
            row["message"] or "",
            row["context_data"] or "",
        )
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _fold(running: str, row_fp: str) -> str:
    return hashlib.sha256(f"{running}|{row_fp}".encode()).hexdigest()


@dataclass
class SealResult:
    sealed: bool
    from_id: int = 0
    through_id: int = 0
    row_count: int = 0
    chain_hash: str = ""
    message: str = ""


@dataclass
class VerifyResult:
    ok: bool
    checkpoints_total: int = 0
    verified: int = 0
    aged_out: int = 0
    partial: int = 0
    unsealed_events: int = 0
    failures: list[str] = field(default_factory=list)
    last_chain_hash: str = ""
    message: str = ""


def _last_checkpoint(conn: sqlite3.Connection):
    conn.row_factory = sqlite3.Row
    return conn.execute(
        "SELECT * FROM audit_checkpoints ORDER BY id DESC LIMIT 1"
    ).fetchone()


def seal_audit_log(db_path: str | None = None) -> SealResult:
    """Seals all audit_events newer than the last checkpoint. Idempotent no-op
    when there is nothing new to seal."""
    path = _db_path(db_path)
    with _connect(path) as conn:
        _ensure_schema(conn)
        conn.row_factory = sqlite3.Row

        last = _last_checkpoint(conn)
        prev_through = last["through_id"] if last else 0
        prev_chain = last["chain_hash"] if last else GENESIS

        rows = conn.execute(
            "SELECT id, timestamp, level, module_source, message, context_data "
            "FROM audit_events WHERE id > ? ORDER BY id ASC",
            (prev_through,),
        ).fetchall()

        if not rows:
            return SealResult(False, message="No new audit events to seal.")

        running = prev_chain
        for row in rows:
            running = _fold(running, _row_fingerprint(row))

        from_id = rows[0]["id"]
        through_id = rows[-1]["id"]
        conn.execute(
            "INSERT INTO audit_checkpoints "
            "(created_at, from_id, through_id, row_count, chain_hash, prev_chain_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (time.time(), from_id, through_id, len(rows), running, prev_chain),
        )
        conn.commit()

    return SealResult(
        True,
        from_id=from_id,
        through_id=through_id,
        row_count=len(rows),
        chain_hash=running,
        message=f"Sealed {len(rows)} event(s) (ids {from_id}-{through_id}).",
    )


def verify_audit_log(db_path: str | None = None) -> VerifyResult:
    """Recomputes every sealed segment and reports tampering.

    A segment fails verification if its recomputed chain hash no longer matches
    the stored value (an event was modified, deleted, or inserted) or if the
    checkpoint chain itself is broken. Segments whose rows have aged out under
    retention are counted separately and never reported as tampering.
    """
    path = _db_path(db_path)
    with _connect(path) as conn:
        _ensure_schema(conn)
        conn.row_factory = sqlite3.Row

        checkpoints = conn.execute(
            "SELECT * FROM audit_checkpoints ORDER BY id ASC"
        ).fetchall()
        result = VerifyResult(ok=True, checkpoints_total=len(checkpoints))
        if not checkpoints:
            result.message = "No checkpoints; nothing sealed yet."
            return result

        bounds = conn.execute(
            "SELECT MIN(id) AS lo, MAX(id) AS hi FROM audit_events"
        ).fetchone()
        min_present = bounds["lo"]
        max_present = bounds["hi"]

        prev_chain = GENESIS
        for cp in checkpoints:
            # Checkpoint-chain continuity (independent of row presence).
            if cp["prev_chain_hash"] != prev_chain:
                result.ok = False
                result.failures.append(
                    f"Checkpoint #{cp['id']} chain seed broken "
                    "(prior seal altered or checkpoints reordered)."
                )
            prev_chain = cp["chain_hash"]

            if min_present is None or cp["through_id"] < min_present:
                result.aged_out += 1
                continue
            if cp["from_id"] < min_present:
                # Straddles the retention boundary; the missing prefix makes a
                # full recompute impossible without false-flagging the purge.
                result.partial += 1
                continue

            rows = conn.execute(
                "SELECT id, timestamp, level, module_source, message, context_data "
                "FROM audit_events WHERE id >= ? AND id <= ? ORDER BY id ASC",
                (cp["from_id"], cp["through_id"]),
            ).fetchall()
            running = cp["prev_chain_hash"]
            for row in rows:
                running = _fold(running, _row_fingerprint(row))

            if len(rows) != cp["row_count"]:
                result.ok = False
                result.failures.append(
                    f"Checkpoint #{cp['id']}: expected {cp['row_count']} event(s) in "
                    f"ids {cp['from_id']}-{cp['through_id']}, found {len(rows)} "
                    "(rows deleted or inserted)."
                )
            elif running != cp["chain_hash"]:
                result.ok = False
                result.failures.append(
                    f"Checkpoint #{cp['id']}: hash mismatch over ids "
                    f"{cp['from_id']}-{cp['through_id']} (an event was modified)."
                )
            else:
                result.verified += 1

        last = checkpoints[-1]
        result.last_chain_hash = last["chain_hash"]
        if max_present is not None and max_present > last["through_id"]:
            result.unsealed_events = conn.execute(
                "SELECT COUNT(*) FROM audit_events WHERE id > ?",
                (last["through_id"],),
            ).fetchone()[0]

    return result

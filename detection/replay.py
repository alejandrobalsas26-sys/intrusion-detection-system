"""Deterministic offline replay of JSONL event records into the audit store.

Feeds the exact pipeline the platform uses at runtime — rows land in
``audit_events`` and are then visible to the correlation engine, dashboard,
and metrics — without needing live traffic, privileges, or a network.

Record format (one JSON object per line; blank lines and ``#`` comments allowed):

    {"level": "WARNING", "module_source": "auth_core",
     "message": "Authentication failed for user 'admin'.",
     "context": {"reason_code": "INVALID_TOTP"},
     "offset_seconds": 30}

Timestamps: a record carries either an absolute epoch ``timestamp`` or a
relative ``offset_seconds``. Relative offsets are anchored so the *latest*
event lands at the base time (default: now), which keeps a replayed scenario
inside the correlator's default one-hour lookback no matter when you run it.
Replays are deterministic given ``--base-time``; note they are inserts, so
replaying the same file twice stores the rows twice (see docs).

CLI:
    python -m detection.replay demo/sample_events.jsonl [--sweep] [--base-time T]
"""

import argparse
import contextlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

_REQUIRED_KEYS = ("level", "module_source", "message")
_LOGS_SCHEMA = Path(__file__).parent.parent / "logs" / "schema.sql"


@dataclass
class ReplayResult:
    db_path: str
    inserted: int
    first_timestamp: float | None
    last_timestamp: float | None


class ReplayFormatError(ValueError):
    """A record is malformed: not JSON, or missing required fields."""


def read_jsonl(path: str) -> list[dict]:
    """Parses and validates a JSONL event file. Raises ReplayFormatError."""
    records: list[dict] = []
    text = Path(path).read_text(encoding="utf-8")
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ReplayFormatError(f"{path}:{lineno}: invalid JSON ({exc})") from exc
        if not isinstance(record, dict):
            raise ReplayFormatError(f"{path}:{lineno}: record must be a JSON object")
        missing = [k for k in _REQUIRED_KEYS if k not in record]
        if missing:
            raise ReplayFormatError(f"{path}:{lineno}: missing field(s) {missing}")
        if "timestamp" not in record and "offset_seconds" not in record:
            raise ReplayFormatError(
                f"{path}:{lineno}: need either 'timestamp' or 'offset_seconds'"
            )
        records.append(record)
    return records


def resolve_timestamps(records: list[dict], base_time: float | None = None) -> list[float]:
    """Maps each record to an absolute epoch timestamp.

    Records with ``timestamp`` keep it. Records with ``offset_seconds`` are
    shifted so the largest offset coincides with ``base_time`` (default now);
    smaller offsets land proportionally earlier.
    """
    base = base_time if base_time is not None else time.time()
    offsets = [
        float(r["offset_seconds"]) for r in records if "timestamp" not in r
    ]
    max_offset = max(offsets, default=0.0)
    anchor = base - max_offset

    resolved: list[float] = []
    for record in records:
        if "timestamp" in record:
            resolved.append(float(record["timestamp"]))
        else:
            resolved.append(anchor + float(record["offset_seconds"]))
    return resolved


def _bootstrap_audit_schema(db_path: str) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    # contextlib.closing: sqlite3's context manager only scopes the
    # transaction; the handle must close explicitly so Windows releases the lock.
    with contextlib.closing(sqlite3.connect(db_path)) as conn:
        conn.executescript(_LOGS_SCHEMA.read_text(encoding="utf-8"))
        conn.commit()


def insert_audit_records(
    records: list[dict], db_path: str | None = None, base_time: float | None = None
) -> ReplayResult:
    """Inserts event records into ``audit_events`` with parameterized SQL."""
    resolved_db = db_path or os.getenv("DB_PATH", "./logs/ids_database.sqlite3")
    _bootstrap_audit_schema(resolved_db)

    timestamps = resolve_timestamps(records, base_time)
    rows = [
        (
            ts,
            str(record["level"]).upper(),
            str(record["module_source"]),
            str(record["message"]),
            json.dumps(record["context"]) if record.get("context") else None,
        )
        for record, ts in zip(records, timestamps, strict=True)
    ]

    with contextlib.closing(sqlite3.connect(resolved_db)) as conn:
        conn.executemany(
            "INSERT INTO audit_events (timestamp, level, module_source, message, context_data)"
            " VALUES (?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()

    return ReplayResult(
        db_path=resolved_db,
        inserted=len(rows),
        first_timestamp=min(timestamps) if timestamps else None,
        last_timestamp=max(timestamps) if timestamps else None,
    )


def replay_file(
    path: str, db_path: str | None = None, base_time: float | None = None
) -> ReplayResult:
    """Reads a JSONL file and inserts its events into the audit store."""
    return insert_audit_records(read_jsonl(path), db_path=db_path, base_time=base_time)


def main(argv: list[str] | None = None) -> int:
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    parser = argparse.ArgumentParser(
        prog="detection.replay",
        description="Replay JSONL event records into the audit store (offline).",
    )
    parser.add_argument("file", help="Path to a .jsonl event file")
    parser.add_argument("--db", default=None, help="Override DB path (default: $DB_PATH)")
    parser.add_argument(
        "--base-time",
        type=float,
        default=None,
        help="Epoch anchor for offset_seconds records (default: now)",
    )
    parser.add_argument(
        "--sweep",
        action="store_true",
        help="Run one correlation sweep after inserting the events",
    )
    args = parser.parse_args(argv)

    try:
        result = replay_file(args.file, db_path=args.db, base_time=args.base_time)
    except (OSError, ReplayFormatError) as exc:
        print(f"[x] Replay failed: {exc}")
        return 1

    print(f"[+] Replayed {result.inserted} event(s) into {result.db_path}")
    if args.sweep:
        from detection.correlation import CorrelationEngine

        created = CorrelationEngine(db_path=result.db_path).sweep()
        print(f"[+] Correlation sweep: {created} new incident(s).")
    else:
        print("    Run 'python -m detection' to correlate them into incidents.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

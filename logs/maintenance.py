"""Database maintenance: retention purges, integrity verification, VACUUM.

The audit store grows without bound by default. These routines implement the
retention policy and operational integrity procedures (docs/OPERATIONS.md).
All operations are additive/destructive-by-policy only: purges respect the
configured retention horizon and never touch identity tables (users,
recovery_codes baselines are preserved).
"""

import contextlib
import os
import sqlite3
import time
from dataclasses import dataclass

DEFAULT_RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "90"))


def _db_path(db_path: str | None = None) -> str:
    return db_path or os.getenv("DB_PATH", "./logs/ids_database.sqlite3")


def _connect(db_path: str) -> contextlib.closing:
    return contextlib.closing(sqlite3.connect(db_path))


@dataclass
class PurgeResult:
    audit_events: int = 0
    fim_events: int = 0
    auth_attempts: int = 0
    closed_incidents: int = 0

    @property
    def total(self) -> int:
        return self.audit_events + self.fim_events + self.auth_attempts + self.closed_incidents


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    ).fetchone()
    return row is not None


def purge_old_events(
    retention_days: int = DEFAULT_RETENTION_DAYS, db_path: str | None = None
) -> PurgeResult:
    """Deletes event/telemetry rows older than the retention horizon.

    * audit_events.timestamp is epoch seconds (REAL).
    * fim_events.timestamp / auth_attempts.timestamp are SQLite DATETIME text.
    * incidents are only purged once closed.
    Identity data (users, recovery codes, file baselines) is never touched.
    """
    if retention_days < 1:
        raise ValueError("retention_days must be >= 1")

    path = _db_path(db_path)
    horizon_epoch = time.time() - retention_days * 86400
    result = PurgeResult()

    with _connect(path) as conn:
        cur = conn.execute("DELETE FROM audit_events WHERE timestamp < ?", (horizon_epoch,))
        result.audit_events = cur.rowcount

        if _table_exists(conn, "fim_events"):
            cur = conn.execute(
                "DELETE FROM fim_events "
                "WHERE timestamp < datetime('now', '-' || ? || ' days')",
                (retention_days,),
            )
            result.fim_events = cur.rowcount

        if _table_exists(conn, "auth_attempts"):
            cur = conn.execute(
                "DELETE FROM auth_attempts "
                "WHERE timestamp < datetime('now', '-' || ? || ' days')",
                (retention_days,),
            )
            result.auth_attempts = cur.rowcount

        if _table_exists(conn, "incidents"):
            cur = conn.execute(
                "DELETE FROM incidents WHERE status = 'closed' AND created_at < ?",
                (horizon_epoch,),
            )
            result.closed_incidents = cur.rowcount

        conn.commit()
    return result


def integrity_check(db_path: str | None = None) -> tuple[bool, list[str]]:
    """Runs PRAGMA integrity_check. Returns (ok, findings)."""
    path = _db_path(db_path)
    with _connect(path) as conn:
        rows = conn.execute("PRAGMA integrity_check").fetchall()
    findings = [r[0] for r in rows]
    return findings == ["ok"], findings


def quick_check(db_path: str | None = None) -> tuple[bool, list[str]]:
    """Runs PRAGMA quick_check — a faster, lighter structural check than
    integrity_check (skips the per-row index cross-check). Suited to routine
    health probes; use integrity_check when corruption is suspected."""
    path = _db_path(db_path)
    with _connect(path) as conn:
        rows = conn.execute("PRAGMA quick_check").fetchall()
    findings = [r[0] for r in rows]
    return findings == ["ok"], findings


def wal_checkpoint(db_path: str | None = None) -> dict:
    """Flushes the WAL into the main database and truncates it.

    Good hygiene after a large purge: in WAL mode the freed pages otherwise
    linger in a growing -wal file until the next automatic checkpoint. Returns
    the PRAGMA's (busy, wal_frames, checkpointed) counters for visibility.
    """
    path = _db_path(db_path)
    with _connect(path) as conn:
        row = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    if not row:
        return {}
    return {"busy": row[0], "wal_frames": row[1], "checkpointed_frames": row[2]}


def vacuum(db_path: str | None = None) -> None:
    """Reclaims space after purges; also defragments the WAL store."""
    path = _db_path(db_path)
    with _connect(path) as conn:
        conn.execute("VACUUM")


def database_stats(db_path: str | None = None) -> dict:
    """Row counts and file size for operational visibility."""
    path = _db_path(db_path)
    stats: dict = {"db_path": path}
    try:
        stats["size_bytes"] = os.path.getsize(path)
    except OSError:
        stats["size_bytes"] = 0
    with _connect(path) as conn:
        for table in ("audit_events", "fim_events", "auth_attempts", "incidents", "users"):
            if _table_exists(conn, table):
                stats[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608
    return stats

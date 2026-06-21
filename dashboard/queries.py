import os
import sqlite3

from logs.logger import get_logger

logger = get_logger("dashboard_queries")

DB_PATH = os.getenv("DB_PATH", "logs/ids_database.sqlite3")


def _get_connection() -> sqlite3.Connection:
    """Open read-only connection to the unified audit DB."""
    # mode=ro enforces read-only at DB level
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def get_recent_audit_events(limit: int = 50) -> list[dict]:
    """Fetch most recent audit events across all modules."""
    try:
        with _get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT timestamp, level, module_source, message, context_data
                FROM audit_events
                ORDER BY timestamp DESC
                LIMIT ?
            """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error("Query failure: get_recent_audit_events - %s", e)
        return []


def get_fim_events_count() -> int:
    """Count of FIM events (modification/deletion alerts)."""
    try:
        with _get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM fim_events")
            return cursor.fetchone()[0]
    except sqlite3.Error as e:
        logger.error("Query failure: get_fim_events_count - %s", e)
        return 0


def get_active_users_count() -> int:
    """Count of users with is_active = 1."""
    try:
        with _get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
            return cursor.fetchone()[0]
    except sqlite3.Error as e:
        logger.error("Query failure: get_active_users_count - %s", e)
        return 0


def get_network_events(limit: int = 50) -> list[dict]:
    """Fetch most recent network detection events (ARP spoofing, SYN scans)."""
    try:
        with _get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT timestamp, level, module_source, message, context_data
                FROM audit_events
                WHERE module_source = 'network_sensor'
                ORDER BY timestamp DESC
                LIMIT ?
            """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error("Query failure: get_network_events - %s", e)
        return []


def get_network_events_count() -> int:
    """Count of network detection events (ARP/SYN) in the audit log."""
    try:
        with _get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) FROM audit_events
                WHERE module_source = 'network_sensor'
            """)
            return cursor.fetchone()[0]
    except sqlite3.Error as e:
        logger.error("Query failure: get_network_events_count - %s", e)
        return 0


def get_incidents(limit: int = 50, status: str | None = None) -> list[dict]:
    """Fetch correlated incidents (newest first), optionally filtered by status."""
    try:
        with _get_connection() as conn:
            cursor = conn.cursor()
            if status:
                cursor.execute(
                    """
                    SELECT id, created_at, rule_name, title, severity, risk_score,
                           mitre_techniques, entities, event_count,
                           first_event_ts, last_event_ts, summary, status
                    FROM incidents
                    WHERE status = ?
                    ORDER BY created_at DESC
                    LIMIT ?
                """,
                    (status, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT id, created_at, rule_name, title, severity, risk_score,
                           mitre_techniques, entities, event_count,
                           first_event_ts, last_event_ts, summary, status
                    FROM incidents
                    ORDER BY created_at DESC
                    LIMIT ?
                """,
                    (limit,),
                )
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        # Table may not exist until the first correlation sweep runs.
        logger.error("Query failure: get_incidents - %s", e)
        return []


def get_open_incidents_count() -> int:
    """Count of incidents still in 'open' status."""
    try:
        with _get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM incidents WHERE status = 'open'")
            return cursor.fetchone()[0]
    except sqlite3.Error as e:
        logger.error("Query failure: get_open_incidents_count - %s", e)
        return 0


def get_event_counts_by_level() -> dict[str, int]:
    """Audit event totals grouped by level, for the metrics endpoint."""
    try:
        with _get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT level, COUNT(*) FROM audit_events GROUP BY level")
            return {row[0]: row[1] for row in cursor.fetchall()}
    except sqlite3.Error as e:
        logger.error("Query failure: get_event_counts_by_level - %s", e)
        return {}


def database_is_readable() -> bool:
    """Readiness probe: the audit DB exists and accepts a read."""
    try:
        with _get_connection() as conn:
            conn.execute("SELECT 1 FROM audit_events LIMIT 1")
        return True
    except sqlite3.Error:
        return False


def get_database_size_bytes() -> int:
    """On-disk size of the audit database (main file + WAL), for capacity alerts."""
    total = 0
    for suffix in ("", "-wal"):
        try:
            total += os.path.getsize(DB_PATH + suffix)
        except OSError:
            pass
    return total


def get_latest_event_timestamp() -> float:
    """Epoch timestamp of the most recent audit event (0.0 if none/unreadable).

    A stalling value is the clearest 'a sensor stopped feeding the IDS' signal,
    so it is exported as an absolute gauge for the operator to alert on.
    """
    try:
        with _get_connection() as conn:
            row = conn.execute("SELECT MAX(timestamp) FROM audit_events").fetchone()
        return float(row[0]) if row and row[0] is not None else 0.0
    except sqlite3.Error as e:
        logger.error("Query failure: get_latest_event_timestamp - %s", e)
        return 0.0


def get_audit_events_since(last_id: int, limit: int = 20) -> list[dict]:
    """Fetch audit events with id > last_id for SSE incremental polling."""
    try:
        with _get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, timestamp, level, module_source, message
                FROM audit_events
                WHERE id > ?
                ORDER BY id ASC
                LIMIT ?
            """,
                (last_id, limit),
            )
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error as e:
        logger.error("Query failure: get_audit_events_since - %s", e)
        return []

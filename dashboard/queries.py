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

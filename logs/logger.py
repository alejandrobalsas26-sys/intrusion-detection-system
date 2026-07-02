import json
import logging
import os
import sqlite3
import sys
from datetime import datetime
from pathlib import Path


class SQLiteAuditHandler(logging.Handler):
    """
    High-availability forensic handler persisting into SQLite.
    Provides automatic redundancy (failsafe text log) and SQLi protection.
    """

    # Concurrent writers (network sensor, auth core, detection engine) all
    # converge on this single audit DB. Without a busy timeout, SQLite returns
    # "database is locked" immediately on contention and the event is demoted
    # to the failsafe text log. Waiting briefly for the lock keeps audit events
    # in the structured store, where queries and correlation can see them.
    _BUSY_TIMEOUT_MS = 5000

    def __init__(self, db_path: str, failsafe_path: str):
        super().__init__()
        self.db_path = db_path
        self.failsafe_path = failsafe_path
        self.schema_path = Path(__file__).parent / "schema.sql"
        self._bootstrap_db()

    def _connect(self) -> sqlite3.Connection:
        """Opens a connection with a bounded busy timeout for lock resilience."""
        conn = sqlite3.connect(self.db_path, timeout=self._BUSY_TIMEOUT_MS / 1000)
        conn.execute(f"PRAGMA busy_timeout = {self._BUSY_TIMEOUT_MS}")
        return conn

    def _bootstrap_db(self):
        """Ensures the data infrastructure exists before the first ingest."""
        try:
            # mkdir guarantees the path exists on clean deployments
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            conn = self._connect()
            try:
                with conn:
                    # Explicit encoding avoids charmap errors on Windows consoles
                    with open(self.schema_path, encoding="utf-8") as f:
                        conn.executescript(f.read())
            finally:
                conn.close()
        except Exception as e:
            sys.stderr.write(f"CRITICAL BOOTSTRAP ERROR: {e}\n")

    def emit(self, record: logging.LogRecord):
        """Inserts the event into the DB; falls back to the text log if the DB is locked."""
        try:
            context_data = getattr(record, "context", {})
            context_json = json.dumps(context_data) if context_data else None

            # `with conn` commits the INSERT; the explicit close releases the
            # file handle immediately so a high log rate cannot accumulate open
            # connections (and the locks they hold on Windows).
            conn = self._connect()
            try:
                with conn:
                    query = "INSERT INTO audit_events (timestamp, level, module_source, message, context_data) VALUES (?, ?, ?, ?, ?)"  # noqa: E501
                    # SQLi protection: native parameter binding
                    conn.execute(
                        query,
                        (
                            record.created,
                            record.levelname,
                            record.name,
                            record.getMessage(),
                            context_json,
                        ),
                    )
            finally:
                conn.close()
        except Exception as e:
            self._write_failsafe(record, e)

    def _write_failsafe(self, record: logging.LogRecord, error: Exception):
        """
        Redundancy layer C1: plain-text fallback when the C0 layer (SQLite) is unavailable.
        """
        failsafe_msg = f"[{datetime.now().isoformat()}] SQLITE_FAIL ({error}) | {record.levelname} - {record.name} - {record.getMessage()}\n"  # noqa: E501
        try:
            Path(self.failsafe_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.failsafe_path, "a", encoding="utf-8") as f:
                f.write(failsafe_msg)
        except Exception:
            # Last line of defense: the process's standard error stream
            sys.stderr.write("FATAL FALLBACK ERROR: " + failsafe_msg)
            self.handleError(record)


def get_logger(module_name: str) -> logging.Logger:
    """Logger factory with a per-logger handler singleton to avoid duplicate records."""
    logger = logging.getLogger(module_name)
    logger.propagate = False
    logger.setLevel(logging.INFO)

    if not any(isinstance(h, SQLiteAuditHandler) for h in logger.handlers):
        # Path.resolve() normalizes relative and absolute paths alike
        db_path_env = os.getenv("DB_PATH", "./logs/ids_database.sqlite3")
        failsafe_env = os.getenv("FAILSAFE_LOG_PATH", "./logs/failsafe.log")

        abs_db_path = Path(db_path_env).resolve()
        abs_failsafe_path = Path(failsafe_env).resolve()

        handler = SQLiteAuditHandler(str(abs_db_path), str(abs_failsafe_path))
        logger.addHandler(handler)

    return logger

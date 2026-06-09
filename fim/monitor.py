import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

from alerts.email_alert import send_security_alert
from logs.logger import get_logger

logger = get_logger("fim_monitor")

# Unify DB_PATH with the logger module
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.getenv("DB_PATH", os.path.join(BASE_DIR, "logs", "ids_database.sqlite3"))


@dataclass
class FimEvent:
    """Dataclass for file integrity telemetry."""

    level: str
    event_type: str  # 'MODIFIED', 'DELETED', 'CREATED'
    filepath: str
    message: str
    module_source: str = "fim"
    timestamp: float = field(default_factory=time.time)


def _bootstrap_fim_db() -> None:
    """Ensures the FIM schema exists regardless of invocation order."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        schema_path = Path(__file__).parent / "schema.sql"
        if schema_path.exists():
            with open(schema_path, encoding="utf-8") as s:
                conn.executescript(s.read())
        else:
            logger.error(f"Schema file not found at {schema_path}")


def calculate_sha256(filepath: str) -> str | None:
    """Calculates SHA-256 hash of a file in 4KB chunks to save memory."""
    sha256_hash = hashlib.sha256()
    try:
        if not os.path.exists(filepath):
            return None
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, OSError) as e:
        logger.warning(f"Access error on {filepath}: {e}")
        return None


def initialize_baselines(config_path: str = "fim/config.json") -> None:
    """Reads configuration and stores initial hashes in the database."""
    if not os.path.exists(config_path):
        logger.warning(f"Configuration file {config_path} not found.")
        return

    with open(config_path, encoding="utf-8") as f:
        config = json.load(f)

    _bootstrap_fim_db()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        for item in config.get("critical_files", []):
            filepath = item["path"]
            current_hash = calculate_sha256(filepath)

            if current_hash:
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO file_baselines (filepath, hash_sha256, is_active)
                    VALUES (?, ?, 1)
                """,
                    (filepath, current_hash),
                )
                logger.info(f"Baseline established for: {filepath}")
            else:
                logger.warning(f"Could not hash {filepath} (Does the file exist?)")

        conn.commit()


def check_integrity() -> None:
    """
    Compares current file hashes against the stored DB baselines.
    Debt: TOCTOU accepted as out-of-scope for MVP.
    """
    logger.info("Initiating integrity check...")
    _bootstrap_fim_db()

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT filepath, hash_sha256 FROM file_baselines WHERE is_active = 1")
        baselines = cursor.fetchall()

        for row in baselines:
            filepath = row["filepath"]
            stored_hash = row["hash_sha256"]
            current_hash = calculate_sha256(filepath)

            if current_hash is None:
                _dispatch_fim_event(
                    FimEvent(
                        level="CRITICAL",
                        event_type="DELETED",
                        filepath=filepath,
                        message=f"CRITICAL: Protected file {filepath} has been deleted.",
                    )
                )
            elif current_hash != stored_hash:
                _dispatch_fim_event(
                    FimEvent(
                        level="CRITICAL",
                        event_type="MODIFIED",
                        filepath=filepath,
                        message=f"CRITICAL: Integrity breach detected in {filepath}.",
                    )
                )
            else:
                logger.debug(f"{filepath}: No changes detected.")


def _dispatch_fim_event(event: FimEvent) -> None:
    """Dispatches the FIM event to DB, Logger, and Alerts."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                INSERT INTO fim_events (filepath, event_type, severity)
                VALUES (?, ?, ?)
            """,
                (event.filepath, event.event_type, event.level),
            )
            conn.commit()

        # L0: Local Logging
        log_method = getattr(logger, event.level.lower(), logger.info)
        log_method(
            event.message,
            extra={
                "filepath": event.filepath,
                "event_type": event.event_type,
                "timestamp": event.timestamp,
            },
        )

        # L1: Email Alerting
        if event.level == "CRITICAL":
            send_security_alert(
                event_level=event.level,
                module_source=event.module_source,
                alert_message=event.message,
            )

    except Exception as e:
        logger.error(f"Failed to dispatch FIM event: {e}")

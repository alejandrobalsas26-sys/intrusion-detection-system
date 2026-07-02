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


def _iter_directory_files(dirpath: str, recursive: bool) -> list[str]:
    """Lists regular files under a monitored directory, normalized for
    stable set-membership comparison between baseline and check time."""
    root = Path(dirpath)
    if not root.is_dir():
        return []
    pattern = "**/*" if recursive else "*"
    return sorted(str(p) for p in root.glob(pattern) if p.is_file())


def _baseline_file(cursor: sqlite3.Cursor, filepath: str) -> bool:
    """Hashes and upserts one file baseline. Returns True on success."""
    current_hash = calculate_sha256(filepath)
    if not current_hash:
        logger.warning(f"Could not hash {filepath} (Does the file exist?)")
        return False
    cursor.execute(
        """
        INSERT OR REPLACE INTO file_baselines (filepath, hash_sha256, is_active)
        VALUES (?, ?, 1)
    """,
        (filepath, current_hash),
    )
    logger.info(f"Baseline established for: {filepath}")
    return True


def initialize_baselines(config_path: str = "fim/config.json") -> None:
    """Reads configuration and stores initial hashes in the database.

    Supports two config sections:
      * ``critical_files`` — individual files (legacy behavior, unchanged)
      * ``critical_dirs``  — directories: every contained file is baselined
        and the directory is registered so future checks can flag files
        CREATED inside it. Optional keys: ``recursive`` (default true),
        ``created_severity`` (default WARNING).
    """
    if not os.path.exists(config_path):
        logger.warning(f"Configuration file {config_path} not found.")
        return

    with open(config_path, encoding="utf-8") as f:
        config = json.load(f)

    _bootstrap_fim_db()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        for item in config.get("critical_files", []):
            _baseline_file(cursor, item["path"])

        for item in config.get("critical_dirs", []):
            dirpath = item["path"]
            recursive = bool(item.get("recursive", True))
            severity = str(item.get("created_severity", "WARNING")).upper()
            if severity not in ("INFO", "WARNING", "ERROR", "CRITICAL"):
                severity = "WARNING"
            if not os.path.isdir(dirpath):
                logger.warning(f"Monitored directory {dirpath} does not exist; skipping.")
                continue
            cursor.execute(
                """
                INSERT OR REPLACE INTO fim_directories
                    (dirpath, recursive, created_severity, is_active)
                VALUES (?, ?, ?, 1)
            """,
                (dirpath, int(recursive), severity),
            )
            for filepath in _iter_directory_files(dirpath, recursive):
                _baseline_file(cursor, filepath)
            logger.info(f"Directory baseline established for: {dirpath}")

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

        _check_directories_for_created(conn)


def _check_directories_for_created(conn: sqlite3.Connection) -> None:
    """Flags files that appeared inside monitored directories since baseline.

    Each new file raises exactly one CREATED event and is then folded into the
    baseline set, so subsequent tampering with it surfaces as MODIFIED/DELETED
    rather than repeated CREATED noise. If the file cannot be hashed it stays
    un-baselined and will be re-reported on the next check (deliberate: an
    unreadable new file in a protected directory should not go quiet).
    """
    cursor = conn.cursor()
    cursor.execute(
        "SELECT dirpath, recursive, created_severity FROM fim_directories WHERE is_active = 1"
    )
    directories = cursor.fetchall()
    if not directories:
        return

    cursor.execute("SELECT filepath FROM file_baselines WHERE is_active = 1")
    known = {row[0] for row in cursor.fetchall()}

    for dirpath, recursive, severity in directories:
        for filepath in _iter_directory_files(dirpath, bool(recursive)):
            if filepath in known:
                continue
            _dispatch_fim_event(
                FimEvent(
                    level=severity or "WARNING",
                    event_type="CREATED",
                    filepath=filepath,
                    message=(
                        f"New file created in monitored directory: {filepath} "
                        f"(watch root: {dirpath})."
                    ),
                )
            )
            if _baseline_file(cursor, filepath):
                known.add(filepath)
    conn.commit()


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

        # L0: Local Logging. The audit handler serializes record.context into
        # the context_data column; loose extra attributes would be dropped, so
        # the structured fields ride inside one "context" dict.
        log_method = getattr(logger, event.level.lower(), logger.info)
        log_method(
            event.message,
            extra={
                "context": {
                    "filepath": event.filepath,
                    "event_type": event.event_type,
                    "timestamp": event.timestamp,
                }
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

import hashlib
import json
import os
import socket
import sqlite3
import time
from contextlib import closing
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
    with closing(sqlite3.connect(DB_PATH)) as conn:
        schema_path = Path(__file__).parent / "schema.sql"
        if schema_path.exists():
            with open(schema_path, encoding="utf-8") as s:
                conn.executescript(s.read())
            conn.executescript((Path(BASE_DIR) / "logs/schema.sql").read_text(encoding="utf-8"))
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


def _store_baseline(conn, filepath, digest):
    conn.execute(
        "INSERT OR REPLACE INTO file_baselines (filepath, hash_sha256, is_active) VALUES (?, ?, 1)",
        (filepath, digest),
    )


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

    files = {item["path"] for item in config.get("critical_files", [])}
    directories = []
    for item in config.get("critical_dirs", []):
        dirpath = item["path"]
        recursive = bool(item.get("recursive", True))
        severity = str(item.get("created_severity", "WARNING")).upper()
        if severity not in ("INFO", "WARNING", "ERROR", "CRITICAL"):
            severity = "WARNING"
        if not os.path.isdir(dirpath):
            logger.warning(f"Monitored directory {dirpath} does not exist; skipping.")
            continue
        directories.append((dirpath, int(recursive), severity))
        files.update(_iter_directory_files(dirpath, recursive))
    # Complete file I/O and logging before acquiring the database writer.
    hashes = [(path, calculate_sha256(path)) for path in sorted(files)]
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        conn.executemany(
            "INSERT OR REPLACE INTO fim_directories "
            "(dirpath, recursive, created_severity, is_active) VALUES (?, ?, ?, 1)",
            directories,
        )
        for path, digest in hashes:
            if digest is not None:
                _store_baseline(conn, path, digest)
    for path, digest in hashes:
        if digest is not None:
            logger.info(f"Baseline established for: {path}")


def check_integrity() -> None:
    """
    Compares current file hashes against the stored DB baselines.
    Debt: TOCTOU accepted as out-of-scope for MVP.
    """
    logger.info("Initiating integrity check...")
    _bootstrap_fim_db()

    with closing(sqlite3.connect(DB_PATH)) as conn:
        baselines = conn.execute(
            "SELECT filepath, hash_sha256 FROM file_baselines WHERE is_active = 1"
        ).fetchall()
    for filepath, stored_hash in baselines:
        current_hash = calculate_sha256(filepath)
        if current_hash is None:
            kind, message = "DELETED", f"CRITICAL: Protected file {filepath} has been deleted."
        elif current_hash != stored_hash:
            kind, message = "MODIFIED", f"CRITICAL: Integrity breach detected in {filepath}."
        else:
            continue
        _dispatch_fim_event(FimEvent("CRITICAL", kind, filepath, message))
    _check_directories_for_created()


def _persist_fim_event(conn, event):
    """The FIM row and audit row share a single transaction."""
    conn.execute(
        "INSERT INTO fim_events (filepath, event_type, severity) VALUES (?, ?, ?)",
        (event.filepath, event.event_type, event.level),
    )
    context = {
        "filepath": event.filepath,
        "event_type": event.event_type,
        "timestamp": event.timestamp,
        "host_id": socket.gethostname(),
    }
    conn.execute(
        "INSERT INTO audit_events (timestamp, level, module_source, message, context_data) "
        "VALUES (?, ?, 'fim_monitor', ?, ?)",
        (event.timestamp, event.level, event.message, json.dumps(context)),
    )


def _notify(event):
    if event.level == "CRITICAL":
        send_security_alert(
            event_level=event.level, module_source=event.module_source, alert_message=event.message
        )


def _check_directories_for_created():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        directories = conn.execute(
            "SELECT dirpath, recursive, created_severity FROM fim_directories WHERE is_active = 1"
        ).fetchall()
        known = {
            row[0]
            for row in conn.execute("SELECT filepath FROM file_baselines WHERE is_active = 1")
        }
    for dirpath, recursive, severity in directories:
        for filepath in _iter_directory_files(dirpath, bool(recursive)):
            if filepath in known:
                continue
            digest = calculate_sha256(filepath)
            event = FimEvent(
                severity or "WARNING",
                "CREATED",
                filepath,
                f"New file created in monitored directory: {filepath} (watch root: {dirpath}).",
            )
            try:
                with closing(sqlite3.connect(DB_PATH)) as conn, conn:
                    conn.execute("BEGIN IMMEDIATE")
                    if conn.execute(
                        "SELECT 1 FROM file_baselines WHERE filepath = ? AND is_active = 1",
                        (filepath,),
                    ).fetchone():
                        continue
                    _persist_fim_event(conn, event)
                    if digest is not None:
                        _store_baseline(conn, filepath, digest)
                if digest is not None:
                    known.add(filepath)
                _notify(event)
            except Exception as exc:
                # The baseline rolls back with the failed event, allowing a retry.
                logger.error(f"Failed to persist CREATED event for {filepath}: {exc}")


def _dispatch_fim_event(event: FimEvent) -> None:
    try:
        with closing(sqlite3.connect(DB_PATH)) as conn, conn:
            _persist_fim_event(conn, event)
        _notify(event)
    except Exception as exc:
        logger.error(f"Failed to dispatch FIM event: {exc}")

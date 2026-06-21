import os
import sqlite3
from pathlib import Path

from logs.logger import get_logger

logger = get_logger("auth_storage")

# Path Resolution Pattern
DB_PATH = os.getenv("DB_PATH", "./logs/ids_database.sqlite3")
SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def _bootstrap_auth_db():
    """Ensures auth tables exist in the shared IDS database."""
    if not os.path.exists(SCHEMA_PATH):
        raise FileNotFoundError(f"Auth schema not found at {SCHEMA_PATH}")

    with sqlite3.connect(DB_PATH) as conn:
        with open(SCHEMA_PATH) as f:
            conn.executescript(f.read())
        conn.commit()


# Auto-bootstrap on module load so that any first importer (web app or CLI)
# finds the auth tables present. auth.core also bootstraps defensively before
# every operation, so this is a convenience, not a correctness dependency: a
# failure here must never crash the importing process, but it must be recorded
# through the audit logger rather than a bare print to stdout.
try:
    _bootstrap_auth_db()
except Exception:
    logger.exception("Auth storage bootstrap failed during import of %s", __name__)

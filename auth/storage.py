import os
import sqlite3
from pathlib import Path

# Path Resolution Pattern
DB_PATH = os.getenv("DB_PATH", "./logs/ids_database.sqlite3")
SCHEMA_PATH = Path(__file__).parent / "schema.sql"

def _bootstrap_auth_db():
    """Ensures auth tables exist in the shared IDS database."""
    if not os.path.exists(SCHEMA_PATH):
        raise FileNotFoundError(f"Auth schema not found at {SCHEMA_PATH}")

    with sqlite3.connect(DB_PATH) as conn:
        with open(SCHEMA_PATH, "r") as f:
            conn.executescript(f.read())
        conn.commit()

# Option A: Auto-bootstrap on module load
try:
    _bootstrap_auth_db()
except Exception as e:
    # We don't want to crash the whole app if DB fails, 
    # but we must log it (even if logger isn't fully ready)
    print(f"[!] Auth Storage Error: {e}")
    
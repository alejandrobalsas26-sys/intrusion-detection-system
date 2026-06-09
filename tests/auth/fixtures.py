import sqlite3
from pathlib import Path


def setup_test_db(conn: sqlite3.Connection):
    """Dynamically loads the production schema and cleans state."""
    schema_path = Path(__file__).parent.parent.parent / "auth" / "schema.sql"
    with open(schema_path, encoding="utf-8") as f:
        conn.executescript(f.read())

    # Clean state for isolated tests
    conn.execute("DELETE FROM recovery_codes")
    conn.execute("DELETE FROM auth_attempts")
    conn.execute("DELETE FROM users")
    conn.commit()

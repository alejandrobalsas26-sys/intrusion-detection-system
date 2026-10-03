"""Real database identities for HTTP tests that do not exercise TOTP login."""

import sqlite3
import time
from contextlib import closing

from auth.core import DB_PATH, _bootstrap_auth_db


def seed_user(username="alice", role="analyst"):
    _bootstrap_auth_db()
    with closing(sqlite3.connect(DB_PATH)) as conn, conn:
        conn.execute(
            "INSERT INTO users (username, encrypted_secret, role, is_active) VALUES (?, 'test', ?, 1) "
            "ON CONFLICT(username) DO UPDATE SET role=excluded.role, is_active=1",
            (username, role),
        )


def seed_session(client, username="alice", role="analyst"):
    seed_user(username, role)
    with client.session_transaction() as session:
        session.clear()
        session.permanent = True
        session.update(user_id=username, authenticated_at=time.time(), role=role)

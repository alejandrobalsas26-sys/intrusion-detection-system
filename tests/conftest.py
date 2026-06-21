"""Global test fixtures and, most importantly, database isolation.

This module is imported by pytest BEFORE any test module (and therefore before
any application module binds ``DB_PATH``). Setting ``DB_PATH`` here redirects
EVERY database consumer — auth core/storage, the audit logger, FIM, the
detection engine, dashboard queries — to a disposable per-session SQLite file.

Why this matters: the auth test suite issues ``DELETE FROM users`` /
``DELETE FROM auth_attempts`` in setUp. Without this redirection those run
against the operator's real ``logs/ids_database.sqlite3`` and would wipe
genuinely enrolled identities every time the tests ran. Pointing the whole
suite at a throwaway database makes the tests hermetic and side-effect free.
"""

import atexit
import os
import shutil
import tempfile
from pathlib import Path

# Create the isolated store and publish its location through the environment
# *before* the first application import resolves DB_PATH.
_TEST_DB_DIR = tempfile.mkdtemp(prefix="ids_test_db_")
# Forward slashes keep the path valid both as a filesystem path and inside the
# ``file:...?mode=ro`` URI that dashboard.queries builds on Windows.
_TEST_DB_PATH = Path(_TEST_DB_DIR, "test_ids_database.sqlite3").as_posix()

os.environ["DB_PATH"] = _TEST_DB_PATH
os.environ["FAILSAFE_LOG_PATH"] = Path(_TEST_DB_DIR, "failsafe.log").as_posix()
# Deterministic, non-secret values so app factories never raise during tests.
os.environ.setdefault("FLASK_SECRET_KEY", "test-secret-key-not-for-production")


@atexit.register
def _cleanup_test_db() -> None:
    # Best-effort: the OS reclaims the temp dir regardless; ignore Windows
    # file-lock races on interpreter shutdown.
    shutil.rmtree(_TEST_DB_DIR, ignore_errors=True)

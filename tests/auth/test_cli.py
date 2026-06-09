import sqlite3
import unittest
from io import StringIO
from unittest.mock import patch

from auth.cli import main
from auth.core import _bootstrap_auth_db, enroll_user, revoke_user
from auth.storage import DB_PATH


class TestAuthCLI(unittest.TestCase):
    def setUp(self):
        """Clean the database before each test to guarantee isolation."""
        _bootstrap_auth_db()
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM auth_attempts")
            conn.execute("DELETE FROM recovery_codes")
            conn.execute("DELETE FROM users")
            conn.commit()

    @patch("sys.argv", ["auth-cli", "enroll", "user1"])
    @patch("sys.stdout", new_callable=StringIO)
    def test_enroll_success(self, mock_stdout):
        main()
        output = mock_stdout.getvalue()
        self.assertIn("enrolled successfully", output)
        self.assertIn("Scan this QR code", output)
        self.assertIn("Recovery codes", output)

    @patch("sys.argv", ["auth-cli", "enroll", "user2"])
    @patch("sys.stderr", new_callable=StringIO)
    def test_enroll_duplicate(self, mock_stderr):
        enroll_user("user2")
        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("already enrolled", mock_stderr.getvalue())

    @patch("sys.argv", ["auth-cli", "revoke", "user3"])
    @patch("sys.stdout", new_callable=StringIO)
    def test_revoke_success(self, mock_stdout):
        enroll_user("user3")
        main()
        self.assertIn("revoked successfully", mock_stdout.getvalue())

        # Verify DB is updated
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT is_active FROM users WHERE username = 'user3'")
            self.assertEqual(cursor.fetchone()[0], 0)

    @patch("sys.argv", ["auth-cli", "revoke", "fakeuser"])
    @patch("sys.stderr", new_callable=StringIO)
    def test_revoke_not_found(self, mock_stderr):
        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("not found", mock_stderr.getvalue())

    @patch("sys.argv", ["auth-cli", "revoke", "user4"])
    @patch("sys.stderr", new_callable=StringIO)
    def test_revoke_already_revoked(self, mock_stderr):
        enroll_user("user4")
        revoke_user("user4")
        with self.assertRaises(SystemExit) as cm:
            main()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("already revoked", mock_stderr.getvalue())

    @patch("sys.argv", ["auth-cli", "list"])
    @patch("sys.stdout", new_callable=StringIO)
    def test_list_empty(self, mock_stdout):
        main()
        self.assertIn("No users enrolled", mock_stdout.getvalue())

    @patch("sys.argv", ["auth-cli", "list"])
    @patch("sys.stdout", new_callable=StringIO)
    def test_list_with_users(self, mock_stdout):
        enroll_user("user5")
        main()
        output = mock_stdout.getvalue()
        self.assertIn("Username", output)
        self.assertIn("Status", output)
        self.assertIn("user5", output)
        self.assertIn("Active", output)

import os
import unittest
from unittest.mock import MagicMock, patch

os.environ.setdefault("FLASK_SECRET_KEY", "test-secret-key-not-for-production")

from dashboard import create_app, queries


def _build_mock_connection(fetchall_rows=None, fetchone_row=None):
    """Build a MagicMock standing in for a sqlite3 read-only connection.

    The real ``_get_connection`` uses ``with sqlite3.connect(...) as conn``,
    and sqlite3's ``__enter__`` returns the connection itself, so the mock
    must mirror that contract.
    """
    mock_conn = MagicMock()
    mock_conn.__enter__.return_value = mock_conn
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.fetchall.return_value = fetchall_rows or []
    mock_cursor.fetchone.return_value = fetchone_row
    return mock_conn


class DashboardRoutesTestCase(unittest.TestCase):
    """Exercises the dashboard HTTP routes and their security behaviour."""

    def setUp(self):
        # CSRF is an infrastructure concern covered by its own dedicated test
        # below; the route-logic cases disable it so each assertion stays
        # deterministic. Flask-Limiter was removed per the architectural
        # rate-limiting decision (commit 6c61030), so there is no limiter to
        # toggle here anymore.
        self.app = create_app()
        self.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.app.test_client()

    def test_unauthenticated_home_redirects_to_login(self):
        """GET / without a session must 302 to the login form."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_login_form_get_renders(self):
        """GET /login renders the login form with status 200."""
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'name="username"', response.data)
        self.assertIn(b'name="totp_code"', response.data)

    def test_login_missing_fields_redirects(self):
        """POST /login with absent credentials redirects back to the form."""
        response = self.client.post("/login", data={"username": "", "totp_code": ""})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    @patch("dashboard.routes.verify_token")
    def test_login_invalid_credentials_redirects(self, mock_verify):
        """A non-success AuthEvent redirects to login without setting identity."""
        mock_verify.return_value = MagicMock(event_name="AUTH_FAILURE")
        response = self.client.post("/login", data={"username": "alice", "totp_code": "000000"})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])
        mock_verify.assert_called_once_with("alice", "000000")
        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)

    @patch("dashboard.routes.verify_token")
    def test_login_success_sets_session_and_redirects_home(self, mock_verify):
        """A successful AuthEvent establishes the session and redirects to /."""
        mock_verify.return_value = MagicMock(event_name="AUTH_SUCCESS")
        response = self.client.post("/login", data={"username": "alice", "totp_code": "123456"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")
        with self.client.session_transaction() as sess:
            self.assertEqual(sess["user_id"], "alice")
            self.assertIn("authenticated_at", sess)

    def test_logout_post_clears_session(self):
        """POST /logout wipes the session and redirects to login."""
        with self.client.session_transaction() as sess:
            sess["user_id"] = "alice"
        response = self.client.post("/logout")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])
        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)

    def test_logout_get_returns_405(self):
        """GET /logout is rejected (405); state change is POST-only by design."""
        response = self.client.get("/logout")
        self.assertEqual(response.status_code, 405)

    def test_csrf_protection_rejects_post_without_token(self):
        """With CSRF active, a POST lacking a valid token is rejected (400)."""
        app = create_app()
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
        client = app.test_client()
        response = client.post("/login", data={"username": "alice", "totp_code": "123456"})
        self.assertEqual(response.status_code, 400)

    def test_login_rate_limit_blocks_after_threshold(self):
        """The 6th /login POST inside the window is rejected with 429."""
        app = create_app()
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        client = app.test_client()
        # A unique source address keeps this test's per-IP budget independent
        # of every other test, so no shared-storage reset is required.
        source = {"REMOTE_ADDR": "203.0.113.7"}
        for _ in range(5):
            allowed = client.post(
                "/login",
                data={"username": "x", "totp_code": ""},
                environ_base=source,
            )
            self.assertNotEqual(allowed.status_code, 429)
        blocked = client.post(
            "/login",
            data={"username": "x", "totp_code": ""},
            environ_base=source,
        )
        self.assertEqual(blocked.status_code, 429)


class DashboardQueriesTestCase(unittest.TestCase):
    """Exercises the read-only data layer with sqlite3.connect fully mocked."""

    @patch("dashboard.queries.sqlite3.connect")
    def test_recent_audit_events_returns_rows(self, mock_connect):
        """Rows fetched from the cursor are returned as dictionaries."""
        rows = [
            {
                "timestamp": "2026-06-07T10:00:00",
                "level": "WARNING",
                "module_source": "auth",
                "message": "Authentication failed.",
                "context_data": "{}",
            }
        ]
        mock_connect.return_value = _build_mock_connection(fetchall_rows=rows)
        result = queries.get_recent_audit_events(50)
        self.assertEqual(result, rows)
        self.assertIn("?mode=ro", mock_connect.call_args.args[0])
        self.assertTrue(mock_connect.call_args.kwargs["uri"])

    @patch("dashboard.queries.sqlite3.connect")
    def test_fim_events_count_returns_int(self, mock_connect):
        """The FIM event count is read from the first cursor column."""
        mock_connect.return_value = _build_mock_connection(fetchone_row=(7,))
        self.assertEqual(queries.get_fim_events_count(), 7)

    @patch("dashboard.queries.sqlite3.connect")
    def test_active_users_count_returns_int(self, mock_connect):
        """The active-user count is read from the first cursor column."""
        mock_connect.return_value = _build_mock_connection(fetchone_row=(3,))
        self.assertEqual(queries.get_active_users_count(), 3)


if __name__ == "__main__":
    unittest.main()

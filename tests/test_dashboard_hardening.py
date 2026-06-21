"""Tests for the dashboard hardening layer: rate limiter unit behavior,
RBAC decorator, operational endpoints, and the incidents API."""

import os
import unittest
from unittest.mock import patch

os.environ.setdefault("FLASK_SECRET_KEY", "test-secret-key-not-for-production")

from dashboard import create_app
from dashboard.security import LoginRateLimiter


class LoginRateLimiterUnitTestCase(unittest.TestCase):
    def test_allows_up_to_max_attempts(self):
        limiter = LoginRateLimiter(max_attempts=3, window_seconds=60)
        for _ in range(3):
            allowed, _ = limiter.check("1.2.3.4", now=100.0)
            self.assertTrue(allowed)

    def test_blocks_after_threshold_with_retry_after(self):
        limiter = LoginRateLimiter(max_attempts=3, window_seconds=60)
        for _ in range(3):
            limiter.check("1.2.3.4", now=100.0)
        allowed, retry_after = limiter.check("1.2.3.4", now=130.0)
        self.assertFalse(allowed)
        self.assertGreater(retry_after, 0)
        self.assertLessEqual(retry_after, 61)

    def test_window_resets(self):
        limiter = LoginRateLimiter(max_attempts=3, window_seconds=60)
        for _ in range(4):
            limiter.check("1.2.3.4", now=100.0)
        allowed, _ = limiter.check("1.2.3.4", now=161.0)
        self.assertTrue(allowed)

    def test_ips_are_independent(self):
        limiter = LoginRateLimiter(max_attempts=1, window_seconds=60)
        limiter.check("1.2.3.4", now=100.0)
        limiter.check("1.2.3.4", now=100.0)
        allowed, _ = limiter.check("5.6.7.8", now=100.0)
        self.assertTrue(allowed)


class OperationalEndpointsTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.app.test_client()

    def test_healthz_is_public_and_ok(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")

    @patch("dashboard.routes.database_is_readable", return_value=True)
    def test_readyz_ready_when_db_readable(self, _mock):
        response = self.client.get("/readyz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ready")

    @patch("dashboard.routes.database_is_readable", return_value=False)
    def test_readyz_503_when_db_unreadable(self, _mock):
        response = self.client.get("/readyz")
        self.assertEqual(response.status_code, 503)

    @patch("dashboard.routes.get_open_incidents_count", return_value=2)
    @patch("dashboard.routes.get_active_users_count", return_value=3)
    @patch("dashboard.routes.get_network_events_count", return_value=4)
    @patch("dashboard.routes.get_fim_events_count", return_value=5)
    @patch(
        "dashboard.routes.get_event_counts_by_level",
        return_value={"WARNING": 7, "CRITICAL": 1},
    )
    @patch("dashboard.routes.database_is_readable", return_value=True)
    def test_metrics_prometheus_exposition(self, *mocks):
        response = self.client.get("/metrics")
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("ids_up 1", body)
        self.assertIn('ids_audit_events_total{level="WARNING"} 7', body)
        self.assertIn("ids_fim_events_total 5", body)
        self.assertIn("ids_open_incidents 2", body)
        self.assertTrue(response.mimetype.startswith("text/plain"))


class IncidentsApiTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.app.test_client()

    def test_unauthenticated_api_gets_401_json(self):
        response = self.client.get("/api/incidents")
        self.assertEqual(response.status_code, 401)
        self.assertIn("error", response.get_json())

    @patch("dashboard.routes.get_incidents")
    def test_authenticated_incidents_decoded(self, mock_get):
        mock_get.return_value = [
            {
                "id": 1,
                "rule_name": "brute_force_burst",
                "title": "Brute force suspected against user 'alice'",
                "severity": "WARNING",
                "risk_score": 55,
                "mitre_techniques": '["T1110"]',
                "entities": '["alice"]',
                "event_count": 5,
                "status": "open",
            }
        ]
        with self.client.session_transaction() as sess:
            sess["user_id"] = "alice"
        response = self.client.get("/api/incidents")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["incidents"][0]["mitre_techniques"], ["T1110"])
        self.assertEqual(payload["incidents"][0]["entities"], ["alice"])

    def test_invalid_status_filter_rejected(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = "alice"
        response = self.client.get("/api/incidents?status=bogus")
        self.assertEqual(response.status_code, 400)


class RbacDecoratorTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)

        # Test-only route exercising the decorator; never part of the app.
        from dashboard.security import require_role

        @self.app.route("/api/_test_admin_only")
        @require_role("admin")
        def _admin_only():
            return {"ok": True}

        self.client = self.app.test_client()

    def test_unauthenticated_gets_401(self):
        response = self.client.get("/api/_test_admin_only")
        self.assertEqual(response.status_code, 401)

    def test_wrong_role_gets_403(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = "alice"
            sess["role"] = "analyst"
        response = self.client.get("/api/_test_admin_only")
        self.assertEqual(response.status_code, 403)

    def test_admin_role_allowed(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = "alice"
            sess["role"] = "admin"
        response = self.client.get("/api/_test_admin_only")
        self.assertEqual(response.status_code, 200)


class LoginRoleBindingTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.app.test_client()

    @patch("dashboard.routes.get_user_role", return_value="admin")
    @patch("dashboard.routes.verify_token")
    def test_successful_login_binds_role_to_session(self, mock_verify, _mock_role):
        from unittest.mock import MagicMock

        mock_verify.return_value = MagicMock(event_name="AUTH_SUCCESS")
        self.client.post("/login", data={"username": "alice", "totp_code": "123456"})
        with self.client.session_transaction() as sess:
            self.assertEqual(sess["role"], "admin")


class ApiUsersRbacTestCase(unittest.TestCase):
    """The /api/users roster is admin-gated (RBAC enforced on a real route)."""

    def setUp(self):
        self.app = create_app()
        self.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.app.test_client()

    def test_unauthenticated_gets_401(self):
        response = self.client.get("/api/users")
        self.assertEqual(response.status_code, 401)

    def test_analyst_gets_403(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = "alice"
            sess["role"] = "analyst"
        response = self.client.get("/api/users")
        self.assertEqual(response.status_code, 403)

    @patch("dashboard.routes.list_users")
    def test_admin_gets_roster_without_secrets(self, mock_list):
        mock_list.return_value = [
            {"username": "alice", "created_at": "2026-01-01", "role": "admin", "is_active": 1}
        ]
        with self.client.session_transaction() as sess:
            sess["user_id"] = "alice"
            sess["role"] = "admin"
        response = self.client.get("/api/users")
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("alice", body)
        # No secret material must ever appear in the roster.
        self.assertNotIn("encrypted_secret", body)
        self.assertNotIn("hashed_code", body)


class MetricsTokenGatingTestCase(unittest.TestCase):
    """When METRICS_TOKEN is set, /metrics requires a matching bearer token."""

    def setUp(self):
        self.app = create_app()
        self.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.app.test_client()

    @patch.dict(os.environ, {"METRICS_TOKEN": "s3cret-scrape-token"})
    def test_missing_token_rejected(self):
        response = self.client.get("/metrics")
        self.assertEqual(response.status_code, 401)

    @patch.dict(os.environ, {"METRICS_TOKEN": "s3cret-scrape-token"})
    def test_wrong_token_rejected(self):
        response = self.client.get(
            "/metrics", headers={"Authorization": "Bearer wrong"}
        )
        self.assertEqual(response.status_code, 401)

    @patch.dict(os.environ, {"METRICS_TOKEN": "s3cret-scrape-token"})
    @patch("dashboard.routes.database_is_readable", return_value=True)
    def test_correct_token_allowed(self, _mock):
        response = self.client.get(
            "/metrics", headers={"Authorization": "Bearer s3cret-scrape-token"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("ids_up 1", response.get_data(as_text=True))

    @patch("dashboard.routes.database_is_readable", return_value=True)
    def test_public_when_token_unset(self, _mock):
        # No METRICS_TOKEN in env -> endpoint stays public (default behavior).
        os.environ.pop("METRICS_TOKEN", None)
        response = self.client.get("/metrics")
        self.assertEqual(response.status_code, 200)


class LoginInputValidationTestCase(unittest.TestCase):
    """The login boundary must reject malformed credentials before they reach
    the auth core (anti log-injection / anti-abuse)."""

    def setUp(self):
        self.app = create_app()
        self.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.app.test_client()

    @patch("dashboard.routes.verify_token")
    def test_username_with_control_chars_rejected(self, mock_verify):
        response = self.client.post(
            "/login",
            data={"username": "alice\r\nINJECTED", "totp_code": "123456"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])
        mock_verify.assert_not_called()

    @patch("dashboard.routes.verify_token")
    def test_oversized_username_rejected(self, mock_verify):
        response = self.client.post(
            "/login",
            data={"username": "a" * 200, "totp_code": "123456"},
        )
        self.assertEqual(response.status_code, 302)
        mock_verify.assert_not_called()

    @patch("dashboard.routes.verify_token")
    def test_non_numeric_token_rejected(self, mock_verify):
        response = self.client.post(
            "/login",
            data={"username": "alice", "totp_code": "abcdef"},
        )
        self.assertEqual(response.status_code, 302)
        mock_verify.assert_not_called()

    @patch("dashboard.routes.verify_token")
    def test_wellformed_credentials_reach_core(self, mock_verify):
        from unittest.mock import MagicMock

        mock_verify.return_value = MagicMock(event_name="AUTH_FAILURE")
        self.client.post("/login", data={"username": "alice", "totp_code": "123456"})
        mock_verify.assert_called_once_with("alice", "123456")


class RequestSizeLimitTestCase(unittest.TestCase):
    """Oversized request bodies are refused at the WSGI layer (413)."""

    def setUp(self):
        self.app = create_app()
        self.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.app.test_client()

    def test_max_content_length_is_configured(self):
        self.assertEqual(self.app.config["MAX_CONTENT_LENGTH"], 64 * 1024)

    def test_oversized_body_rejected_with_413(self):
        response = self.client.post(
            "/login",
            data={"username": "alice", "totp_code": "1" * (128 * 1024)},
        )
        self.assertEqual(response.status_code, 413)


if __name__ == "__main__":
    unittest.main()

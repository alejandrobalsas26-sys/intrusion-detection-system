"""Tests for startup configuration diagnostics and the dashboard entrypoint."""

import os
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet

from dashboard import diagnostics
from dashboard.diagnostics import FAIL, OK, WARN, format_report, run_diagnostics

# A real, valid Fernet key so the MFA check passes in the positive cases.
_VALID_FERNET = Fernet.generate_key().decode()


def _good_env(**overrides) -> dict:
    env = {
        "FLASK_SECRET_KEY": "a" * 64,
        "MFA_ENCRYPTION_KEY": _VALID_FERNET,
        "DB_PATH": os.getenv("DB_PATH", "./logs/ids_database.sqlite3"),
        "FLASK_ENV": "development",
        "AI_BACKEND": "none",
    }
    env.update(overrides)
    return env


class DiagnosticsTestCase(unittest.TestCase):
    def _statuses(self, report) -> dict:
        return {c.name: c.status for c in report.checks}

    def test_valid_config_is_ready(self):
        with patch.dict(os.environ, _good_env(), clear=True):
            report = run_diagnostics()
        self.assertTrue(report.ok)
        self.assertEqual(self._statuses(report)["FLASK_SECRET_KEY"], OK)
        self.assertEqual(self._statuses(report)["MFA_ENCRYPTION_KEY"], OK)

    def test_missing_secret_key_is_fatal(self):
        env = _good_env()
        env.pop("FLASK_SECRET_KEY")
        with patch.dict(os.environ, env, clear=True):
            report = run_diagnostics()
        self.assertFalse(report.ok)
        self.assertEqual(self._statuses(report)["FLASK_SECRET_KEY"], FAIL)

    def test_placeholder_secret_is_fatal(self):
        with patch.dict(
            os.environ, _good_env(FLASK_SECRET_KEY="your_64_character_hex_secret_here"), clear=True
        ):
            report = run_diagnostics()
        self.assertFalse(report.ok)

    def test_short_secret_warns_but_starts(self):
        with patch.dict(os.environ, _good_env(FLASK_SECRET_KEY="short"), clear=True):
            report = run_diagnostics()
        self.assertTrue(report.ok)
        self.assertEqual(self._statuses(report)["FLASK_SECRET_KEY"], WARN)

    def test_invalid_fernet_key_is_fatal(self):
        with patch.dict(os.environ, _good_env(MFA_ENCRYPTION_KEY="not-a-valid-key"), clear=True):
            report = run_diagnostics()
        self.assertFalse(report.ok)
        self.assertEqual(self._statuses(report)["MFA_ENCRYPTION_KEY"], FAIL)

    def test_missing_mfa_key_is_fatal(self):
        env = _good_env()
        env.pop("MFA_ENCRYPTION_KEY")
        with patch.dict(os.environ, env, clear=True):
            report = run_diagnostics()
        self.assertFalse(report.ok)

    def test_production_without_metrics_token_warns(self):
        with patch.dict(os.environ, _good_env(FLASK_ENV="production"), clear=True):
            report = run_diagnostics(production=True)
        names = {c.name for c in report.warnings}
        self.assertIn("METRICS_TOKEN", names)
        # A warning must never block startup.
        self.assertTrue(report.ok)

    def test_production_inferred_from_flask_env(self):
        with patch.dict(os.environ, _good_env(FLASK_ENV="production"), clear=True):
            report = run_diagnostics()
        self.assertTrue(report.production)

    def test_sleep_backoff_in_web_tier_warns(self):
        with patch.dict(os.environ, _good_env(MFA_BACKOFF_MODE="sleep"), clear=True):
            report = run_diagnostics()
        names = {c.name for c in report.warnings}
        self.assertIn("MFA_BACKOFF_MODE", names)

    def test_configured_missing_ioc_file_warns(self):
        with patch.dict(
            os.environ, _good_env(IOC_IP_LIST_PATH="/nonexistent/iocs.txt"), clear=True
        ):
            report = run_diagnostics()
        names = {c.name for c in report.warnings}
        self.assertIn("IOC_IP_LIST_PATH", names)

    def test_format_report_renders_result_line(self):
        with patch.dict(os.environ, _good_env(), clear=True):
            report = run_diagnostics()
        text = format_report(report)
        self.assertIn("configuration diagnostics", text)
        self.assertIn("READY", text)


class EntrypointCheckTestCase(unittest.TestCase):
    """The `--check` flag exits 0/1 by readiness without starting a server."""

    def test_check_flag_returns_zero_on_valid_config(self):
        from dashboard.__main__ import main

        with patch.dict(os.environ, _good_env(), clear=True):
            self.assertEqual(main(["--check"]), 0)

    def test_check_flag_returns_one_on_invalid_config(self):
        from dashboard.__main__ import main

        env = _good_env()
        env.pop("FLASK_SECRET_KEY")
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(main(["--check"]), 1)

    def test_invalid_config_refuses_to_start(self):
        # A failing report must abort before create_app / serve are reached.
        import dashboard.__main__ as entry

        failing = diagnostics.Diagnostics(
            checks=[diagnostics.Check("FLASK_SECRET_KEY", FAIL, "Missing.")]
        )
        # main() binds run_diagnostics by name at import; patch it there.
        with patch.object(entry, "run_diagnostics", return_value=failing):
            with patch.dict(os.environ, _good_env(), clear=True):
                self.assertEqual(entry.main([]), 1)


class ServerResolutionTestCase(unittest.TestCase):
    """The auto server choice picks Waitress in production, Flask otherwise."""

    def test_auto_selects_waitress_in_production(self):
        from dashboard.__main__ import _parse_args, _resolve_server

        args = _parse_args([])
        self.assertEqual(_resolve_server(args, production=True), "waitress")

    def test_auto_selects_flask_in_development(self):
        from dashboard.__main__ import _parse_args, _resolve_server

        args = _parse_args([])
        self.assertEqual(_resolve_server(args, production=False), "flask")

    def test_explicit_server_overrides_auto(self):
        from dashboard.__main__ import _parse_args, _resolve_server

        args = _parse_args(["--server", "flask"])
        self.assertEqual(_resolve_server(args, production=True), "flask")


if __name__ == "__main__":
    unittest.main()

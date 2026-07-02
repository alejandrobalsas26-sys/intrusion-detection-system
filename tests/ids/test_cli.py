"""CLI wiring tests for the ``python -m ids`` orchestrator."""

import io
import os
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import MagicMock, patch

from ids import services
from ids.__main__ import main


class CheckCommandTestCase(unittest.TestCase):
    def _run_check(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer), redirect_stderr(buffer):
            code = main(["check"])
        return code, buffer.getvalue()

    def test_check_passes_in_configured_environment(self):
        from cryptography.fernet import Fernet

        env = {
            "MFA_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "FLASK_ENV": "development",
        }
        with patch.dict(os.environ, env):
            code, output = self._run_check()
        self.assertEqual(code, 0, output)
        self.assertIn("READY", output)
        self.assertNotIn("[x]", output)

    def test_check_fails_on_blocking_misconfiguration(self):
        # An empty MFA key is a FAIL in diagnostics; check must propagate it.
        with patch.dict(os.environ, {"MFA_ENCRYPTION_KEY": "", "FLASK_ENV": "development"}):
            code, output = self._run_check()
        self.assertEqual(code, 1)
        self.assertIn("NOT READY", output)


class DemoCommandTestCase(unittest.TestCase):
    def test_demo_invokes_generator_and_prints_summary(self):
        sentinel = object()
        with patch("demo.attack_chain.run_demo", return_value=sentinel) as mock_run, patch(
            "demo.attack_chain.print_summary"
        ) as mock_print:
            code = main(["demo", "--no-sweep"])
        self.assertEqual(code, 0)
        mock_run.assert_called_once_with(db_path=None, sweep=False)
        mock_print.assert_called_once_with(sentinel)


class RunCommandTestCase(unittest.TestCase):
    def test_run_requires_a_component_flag(self):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                main(["run"])
        self.assertEqual(ctx.exception.code, 2)

    def test_run_fails_cleanly_when_nothing_starts(self):
        with patch("network.sensor.start_sensor", return_value=None):
            with redirect_stderr(io.StringIO()) as buffer:
                code = main(["run", "--sensor"])
        self.assertEqual(code, 1)
        self.assertIn("No components could be started", buffer.getvalue())

    def test_run_supervises_until_components_stop(self):
        worker = threading.Thread(target=lambda: None)
        worker.start()
        worker.join()
        with patch("network.sensor.start_sensor", return_value=worker):
            with redirect_stderr(io.StringIO()):
                code = main(["run", "--sensor"])
        self.assertEqual(code, 0)


class CorrelatorServiceTestCase(unittest.TestCase):
    def test_correlator_sweeps_and_stops_on_event(self):
        engine = MagicMock()
        engine.sweep.return_value = 0
        with patch("detection.correlation.CorrelationEngine", return_value=engine):
            thread = services.start_correlator_service(interval_seconds=1)
            for _ in range(200):
                if engine.sweep.called:
                    break
                time.sleep(0.02)
            thread.stop_event.set()
            thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertTrue(engine.sweep.called)


class DashboardServiceTestCase(unittest.TestCase):
    def test_dashboard_skipped_when_diagnostics_fail(self):
        report = MagicMock()
        report.ok = False
        with patch("dashboard.diagnostics.run_diagnostics", return_value=report), patch(
            "dashboard.diagnostics.format_report", return_value="diagnostics output"
        ):
            with redirect_stderr(io.StringIO()) as buffer:
                thread = services.start_dashboard_service()
        self.assertIsNone(thread)
        self.assertIn("Dashboard not started", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()

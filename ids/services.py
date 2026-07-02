"""Component starters for ``python -m ids run``.

Each starter returns a running ``threading.Thread`` on success or ``None``
when the component cannot start safely; the reason is printed as a warning.
Threads are daemons, so they exit with the main process on Ctrl+C; the
correlator additionally exposes a ``stop_event`` for cooperative shutdown.
"""

import os
import sys
import threading


def _warn(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr)


def start_sensor_service() -> threading.Thread | None:
    """Live scapy sniffer (requires consent env var and admin privileges)."""
    from network.sensor import start_sensor

    thread = start_sensor()
    if thread is None:
        _warn(
            "Network sensor not started: set NETWORK_MONITOR_CONSENT=true and "
            "run from an elevated prompt (raw sockets need admin on Windows)."
        )
    return thread


def start_correlator_service(
    interval_seconds: int = 60, lookback_seconds: int = 3600
) -> threading.Thread:
    """Periodic correlation sweeps over the audit store."""
    from detection.correlation import CorrelationEngine

    engine = CorrelationEngine(lookback_seconds=lookback_seconds)
    stop_event = threading.Event()

    def _loop() -> None:
        while not stop_event.is_set():
            try:
                created = engine.sweep()
                if created:
                    print(f"[!] correlator: {created} new incident(s).", file=sys.stderr)
            except Exception as exc:  # a bad sweep must not kill the daemon
                _warn(f"Correlator sweep failed: {exc}")
            stop_event.wait(interval_seconds)

    thread = threading.Thread(target=_loop, daemon=True, name="ids-correlator")
    thread.stop_event = stop_event  # cooperative shutdown hook for the supervisor
    thread.start()
    return thread


def start_dashboard_service(
    production: bool = False, host: str | None = None, port: int | None = None
) -> threading.Thread | None:
    """Read-only dashboard; Waitress in production, Flask dev server otherwise."""
    from dashboard.diagnostics import format_report, run_diagnostics

    if production:
        os.environ["FLASK_ENV"] = "production"
    is_production = os.getenv("FLASK_ENV", "").strip().lower() == "production"

    report = run_diagnostics(production=is_production)
    if not report.ok:
        print(format_report(report), file=sys.stderr)
        _warn("Dashboard not started: resolve the blocking issue(s) above.")
        return None

    from dashboard import create_app

    app = create_app()
    bind_host = host or os.getenv("DASHBOARD_HOST", "127.0.0.1")
    bind_port = int(port or os.getenv("DASHBOARD_PORT", "5000"))

    def _serve() -> None:
        try:
            if is_production:
                from waitress import serve

                serve(app, host=bind_host, port=bind_port, ident="antigravity-ids")
            else:
                app.run(host=bind_host, port=bind_port, use_reloader=False)
        except Exception as exc:  # bind errors etc. must not kill the supervisor
            _warn(f"Dashboard server stopped: {exc}")

    thread = threading.Thread(target=_serve, daemon=True, name="ids-dashboard")
    thread.start()
    server_name = "waitress" if is_production else "flask dev"
    print(f"[*] Dashboard ({server_name}) on http://{bind_host}:{bind_port}", file=sys.stderr)
    return thread

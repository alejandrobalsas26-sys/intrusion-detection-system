"""Starts the requested components and supervises them until shutdown."""

import sys
import time
from dataclasses import dataclass, field

from ids import services


@dataclass
class RunReport:
    """Which components launched (name, thread) and which were skipped."""

    started: list[tuple[str, object]] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def launch(
    *,
    sensor: bool = False,
    correlator: bool = False,
    dashboard: bool = False,
    production: bool = False,
    host: str | None = None,
    port: int | None = None,
    interval_seconds: int = 60,
    lookback_seconds: int = 3600,
) -> RunReport:
    report = RunReport()

    def _record(name: str, thread) -> None:
        if thread is None:
            report.skipped.append(name)
        else:
            report.started.append((name, thread))

    if sensor:
        _record("sensor", services.start_sensor_service())
    if correlator:
        _record(
            "correlator",
            services.start_correlator_service(interval_seconds, lookback_seconds),
        )
    if dashboard:
        _record(
            "dashboard",
            services.start_dashboard_service(production=production, host=host, port=port),
        )
    return report


def supervise(report: RunReport, poll_seconds: float = 1.0) -> int:
    """Blocks until Ctrl+C or every component thread has stopped."""
    try:
        while any(thread.is_alive() for _, thread in report.started):
            time.sleep(poll_seconds)
        print("[*] All components stopped.", file=sys.stderr)
    except KeyboardInterrupt:
        print("\n[*] Shutting down.", file=sys.stderr)
        for _, thread in report.started:
            stop_event = getattr(thread, "stop_event", None)
            if stop_event is not None:
                stop_event.set()
    return 0

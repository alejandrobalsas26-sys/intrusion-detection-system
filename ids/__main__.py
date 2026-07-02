"""Antigravity-IDS command line.

    python -m ids check                  import + configuration self-test
    python -m ids demo                   offline demo attack chain (no privileges)
    python -m ids run --dashboard --correlator --sensor

``run`` starts only the components requested by flags; a component that cannot
start safely (missing consent, privileges, or configuration) is reported and
skipped instead of aborting the others.
"""

import argparse
import importlib
import platform

from ids.config import load_env

CORE_MODULES = (
    "alerts.email_alert",
    "auth.storage",
    "dashboard.diagnostics",
    "demo.attack_chain",
    "detection.correlation",
    "detection.replay",
    "fim.monitor",
    "logs.logger",
    "network.replay",
    "network.sensor",
)

# Optional by design: a missing dependency is reported and skipped, never a
# failure. auth.crypto is intentionally absent from both lists — it raises at
# import time without a valid MFA key, which the diagnostics below already
# report with a friendlier message.
OPTIONAL_MODULES = {
    "vision.engine": "experimental, requires opencv-python",
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ids", description="Antigravity-IDS local orchestrator"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="Validate imports and configuration, then exit.")

    demo = sub.add_parser(
        "demo", help="Generate the reproducible demo attack chain (no privileges needed)."
    )
    demo.add_argument("--db", default=None, help="Target SQLite database (default: DB_PATH env).")
    demo.add_argument(
        "--no-sweep", action="store_true", help="Skip the correlation sweep after inserting."
    )

    run = sub.add_parser("run", help="Start selected components until Ctrl+C.")
    run.add_argument("--dashboard", action="store_true", help="Serve the read-only dashboard.")
    run.add_argument("--correlator", action="store_true", help="Periodic correlation sweeps.")
    run.add_argument("--sensor", action="store_true", help="Live network sensor (needs admin).")
    run.add_argument(
        "--production",
        action="store_true",
        help="Dashboard: serve via Waitress with FLASK_ENV=production.",
    )
    run.add_argument("--host", default=None, help="Dashboard bind host (default: env/127.0.0.1).")
    run.add_argument(
        "--port", type=int, default=None, help="Dashboard bind port (default: env/5000)."
    )
    run.add_argument(
        "--interval", type=int, default=60, help="Correlator sweep interval in seconds."
    )
    run.add_argument(
        "--lookback", type=int, default=3600, help="Correlator lookback window in seconds."
    )
    return parser


def cmd_check(_args: argparse.Namespace) -> int:
    failures = 0
    print(f"Python {platform.python_version()} - module import checks")
    print("=" * 30)
    for module in CORE_MODULES:
        try:
            importlib.import_module(module)
            print(f" [+] {module}")
        except Exception as exc:  # noqa: BLE001 - any import-time error is a finding
            failures += 1
            print(f" [x] {module}: {type(exc).__name__}: {exc}")
    for module, note in OPTIONAL_MODULES.items():
        try:
            importlib.import_module(module)
            print(f" [+] {module} ({note})")
        except Exception as exc:  # noqa: BLE001
            print(f" [!] {module} skipped ({note}; {type(exc).__name__})")
    print()

    from dashboard.diagnostics import format_report, run_diagnostics

    report = run_diagnostics()
    print(format_report(report))
    return 0 if failures == 0 and report.ok else 1


def cmd_demo(args: argparse.Namespace) -> int:
    from demo import attack_chain

    summary = attack_chain.run_demo(db_path=args.db, sweep=not args.no_sweep)
    attack_chain.print_summary(summary)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    import sys

    from ids import orchestrator

    report = orchestrator.launch(
        sensor=args.sensor,
        correlator=args.correlator,
        dashboard=args.dashboard,
        production=args.production,
        host=args.host,
        port=args.port,
        interval_seconds=args.interval,
        lookback_seconds=args.lookback,
    )
    for name, _ in report.started:
        print(f"[+] {name} started.", file=sys.stderr)
    for name in report.skipped:
        print(f"[-] {name} skipped.", file=sys.stderr)
    if not report.started:
        print("[x] No components could be started.", file=sys.stderr)
        return 1
    return orchestrator.supervise(report)


def main(argv: list[str] | None = None) -> int:
    load_env()
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "run" and not (args.dashboard or args.correlator or args.sensor):
        parser.error("select at least one component: --dashboard, --correlator, --sensor")
    handlers = {"check": cmd_check, "demo": cmd_demo, "run": cmd_run}
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())

"""Dashboard entrypoint.

Defaults preserve the historical behavior exactly: `python -m dashboard` serves
the Flask development server on 127.0.0.1:5000. For production on Windows (where
gunicorn is unavailable) pass `--production` or set `FLASK_ENV=production` to
serve through Waitress, a mature pure-Python WSGI server.

Startup is gated by configuration diagnostics (see dashboard.diagnostics): a
fatal misconfiguration is reported clearly and aborts before the socket opens,
rather than surfacing as a stack trace on the first request.
"""

import argparse
import os
import sys

from dotenv import load_dotenv

load_dotenv()

from dashboard.diagnostics import format_report, run_diagnostics  # noqa: E402


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="dashboard", description="Antigravity-IDS dashboard server"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run configuration diagnostics and exit (no server started).",
    )
    parser.add_argument(
        "--production",
        action="store_true",
        help="Serve via Waitress with production settings (implies FLASK_ENV=production).",
    )
    parser.add_argument(
        "--server",
        choices=("auto", "waitress", "flask"),
        default="auto",
        help="WSGI server: auto (waitress in production, else flask dev), or force one.",
    )
    parser.add_argument("--host", default=os.getenv("DASHBOARD_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("DASHBOARD_PORT", "5000")))
    parser.add_argument(
        "--threads",
        type=int,
        default=int(os.getenv("WAITRESS_THREADS", "8")),
        help="Waitress worker threads (production server only).",
    )
    return parser.parse_args(argv)


def _resolve_server(args: argparse.Namespace, production: bool) -> str:
    if args.server != "auto":
        return args.server
    return "waitress" if production else "flask"


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    # --production is a convenience switch for FLASK_ENV=production so the app
    # factory's secure-cookie / HSTS / HTTPS-redirect behavior activates.
    if args.production:
        os.environ["FLASK_ENV"] = "production"
    production = os.getenv("FLASK_ENV", "").strip().lower() == "production"

    report = run_diagnostics(production=production)
    print(format_report(report), file=sys.stderr)

    if args.check:
        return 0 if report.ok else 1

    if not report.ok:
        print(
            "\n[x] Refusing to start: resolve the blocking issue(s) above.",
            file=sys.stderr,
        )
        return 1

    # Import the factory only after diagnostics pass; create_app re-validates the
    # secret key and would raise on a misconfiguration we already explained.
    from dashboard import create_app

    app = create_app()
    server = _resolve_server(args, production)

    if server == "waitress":
        try:
            from waitress import serve
        except ImportError:
            print(
                "[x] Waitress is not installed. Install it (pip install waitress) "
                "or run with --server flask for development.",
                file=sys.stderr,
            )
            return 1
        if args.host not in ("127.0.0.1", "localhost", "::1"):
            print(
                f"[!] Binding Waitress to {args.host}: put a TLS-terminating reverse "
                "proxy in front and keep FLASK_ENV=production.",
                file=sys.stderr,
            )
        print(
            f"[*] Antigravity-IDS dashboard (Waitress) on http://{args.host}:{args.port}",
            file=sys.stderr,
        )
        serve(app, host=args.host, port=args.port, threads=args.threads, ident="antigravity-ids")
        return 0

    # Development server. Bound to localhost only to prevent accidental exposure.
    print(
        f"[*] Antigravity-IDS dashboard (Flask dev server) on "
        f"http://{args.host}:{args.port}",
        file=sys.stderr,
    )
    app.run(host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""CLI for the reproducible demo attack chain.

Run from the repository root:
    python demo/generate_attack_chain.py [--no-sweep] [--db PATH] [--live-email]
"""

import argparse
import sys
from pathlib import Path

# Support both `python demo/generate_attack_chain.py` (script: package parent
# is not on sys.path) and `python -m demo.generate_attack_chain`.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from demo.attack_chain import print_summary, run_demo  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="demo/generate_attack_chain.py",
        description="Generate a synthetic multi-stage attack chain into the audit store.",
    )
    parser.add_argument("--db", default=None, help="Override DB path (default: $DB_PATH)")
    parser.add_argument(
        "--base-time",
        type=float,
        default=None,
        help="Epoch anchor for the timeline (default: now)",
    )
    parser.add_argument(
        "--no-sweep",
        action="store_true",
        help="Only insert events; correlate later with 'python -m detection'",
    )
    parser.add_argument(
        "--live-email",
        action="store_true",
        help="Do NOT suppress e-mail alerts during the demo (default: suppressed)",
    )
    args = parser.parse_args(argv)

    summary = run_demo(
        db_path=args.db,
        base_time=args.base_time,
        sweep=not args.no_sweep,
        suppress_email=not args.live_email,
    )
    print_summary(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

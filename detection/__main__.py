import argparse
import time

from dotenv import load_dotenv

load_dotenv()

from detection.correlation import CorrelationEngine  # noqa: E402


def main():
    parser = argparse.ArgumentParser(
        prog="detection", description="Antigravity-IDS: Correlation engine sweeps"
    )
    parser.add_argument(
        "--lookback",
        type=int,
        default=3600,
        help="Seconds of audit history to correlate (default: 3600)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=0,
        help="Run continuously, sweeping every N seconds (0 = single sweep)",
    )
    args = parser.parse_args()

    engine = CorrelationEngine(lookback_seconds=args.lookback)

    if args.interval <= 0:
        created = engine.sweep()
        print(f"[+] Sweep complete: {created} new incident(s).")
        return

    print(f"[*] Correlation daemon: sweeping every {args.interval}s. Ctrl+C to stop.")
    try:
        while True:
            created = engine.sweep()
            if created:
                print(f"[!] {created} new incident(s) created.")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Correlation daemon stopped by user.")


if __name__ == "__main__":
    main()

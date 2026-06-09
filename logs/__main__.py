import argparse

from dotenv import load_dotenv

load_dotenv()

from logs.maintenance import (  # noqa: E402
    DEFAULT_RETENTION_DAYS,
    database_stats,
    integrity_check,
    purge_old_events,
    vacuum,
)


def main():
    parser = argparse.ArgumentParser(
        prog="logs", description="Antigravity-IDS: Audit database maintenance"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    purge = sub.add_parser("purge", help="Delete events older than the retention horizon")
    purge.add_argument(
        "--days",
        type=int,
        default=DEFAULT_RETENTION_DAYS,
        help=f"Retention in days (default: {DEFAULT_RETENTION_DAYS})",
    )
    purge.add_argument(
        "--vacuum", action="store_true", help="Reclaim disk space after purging"
    )

    sub.add_parser("check", help="Run PRAGMA integrity_check")
    sub.add_parser("vacuum", help="Reclaim disk space")
    sub.add_parser("stats", help="Show row counts and database size")

    args = parser.parse_args()

    if args.command == "purge":
        result = purge_old_events(retention_days=args.days)
        print(
            f"[+] Purged {result.total} rows "
            f"(audit={result.audit_events}, fim={result.fim_events}, "
            f"auth_attempts={result.auth_attempts}, closed_incidents={result.closed_incidents})"
        )
        if args.vacuum:
            vacuum()
            print("[+] VACUUM complete.")
    elif args.command == "check":
        ok, findings = integrity_check()
        if ok:
            print("[+] Integrity check: ok")
        else:
            print("[!] Integrity check FAILED:")
            for finding in findings:
                print(f"    - {finding}")
            raise SystemExit(1)
    elif args.command == "vacuum":
        vacuum()
        print("[+] VACUUM complete.")
    elif args.command == "stats":
        for key, value in database_stats().items():
            print(f"  {key}: {value}")


if __name__ == "__main__":
    main()

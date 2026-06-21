import argparse

from dotenv import load_dotenv

load_dotenv()

from logs.integrity import seal_audit_log, verify_audit_log  # noqa: E402
from logs.maintenance import (  # noqa: E402
    DEFAULT_RETENTION_DAYS,
    database_stats,
    integrity_check,
    purge_old_events,
    quick_check,
    vacuum,
    wal_checkpoint,
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

    check = sub.add_parser("check", help="Run PRAGMA integrity_check")
    check.add_argument(
        "--quick", action="store_true", help="Run the faster PRAGMA quick_check instead"
    )
    sub.add_parser("vacuum", help="Reclaim disk space")
    sub.add_parser("checkpoint", help="Flush and truncate the WAL into the main DB file")
    sub.add_parser("stats", help="Show row counts and database size")
    sub.add_parser("seal", help="Seal new audit events into the tamper-evident hash chain")
    sub.add_parser("verify-chain", help="Verify the audit log hash chain for tampering")

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
        ok, findings = quick_check() if args.quick else integrity_check()
        label = "Quick check" if args.quick else "Integrity check"
        if ok:
            print(f"[+] {label}: ok")
        else:
            print(f"[!] {label} FAILED:")
            for finding in findings:
                print(f"    - {finding}")
            raise SystemExit(1)
    elif args.command == "vacuum":
        vacuum()
        print("[+] VACUUM complete.")
    elif args.command == "checkpoint":
        stats = wal_checkpoint()
        print(f"[+] WAL checkpoint complete. {stats}")
    elif args.command == "stats":
        for key, value in database_stats().items():
            print(f"  {key}: {value}")
    elif args.command == "seal":
        result = seal_audit_log()
        print(f"[+] {result.message}")
        if result.sealed:
            print(f"    chain_hash: {result.chain_hash}")
    elif args.command == "verify-chain":
        result = verify_audit_log()
        print(
            f"[*] Checkpoints: {result.checkpoints_total} "
            f"(verified={result.verified}, aged_out={result.aged_out}, "
            f"partial={result.partial})"
        )
        if result.unsealed_events:
            print(f"    {result.unsealed_events} event(s) not yet sealed.")
        if result.ok:
            print("[+] Audit chain verification: OK")
            if result.last_chain_hash:
                print(f"    anchor (export off-box): {result.last_chain_hash}")
        else:
            print("[!] Audit chain verification FAILED:")
            for finding in result.failures:
                print(f"    - {finding}")
            raise SystemExit(1)


if __name__ == "__main__":
    main()

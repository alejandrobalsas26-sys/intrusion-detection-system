import argparse

from dotenv import load_dotenv

load_dotenv()

from fim.monitor import check_integrity, initialize_baselines  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="Antigravity-IDS: File Integrity Monitor")
    parser.add_argument(
        "--baseline", action="store_true", help="Initialize or re-baseline all monitored files"
    )
    parser.add_argument(
        "--check", action="store_true", help="Run an integrity check against stored baselines"
    )
    parser.add_argument(
        "--config", default="fim/config.json", help="Path to FIM config (default: fim/config.json)"
    )
    args = parser.parse_args()

    if not args.baseline and not args.check:
        parser.print_help()
        return

    if args.baseline:
        print("[*] Initializing baselines...")
        initialize_baselines(args.config)
        print("[+] Baselines written to database.")

    if args.check:
        print("[*] Running integrity check...")
        check_integrity()
        print("[+] Integrity check complete.")


if __name__ == "__main__":
    main()

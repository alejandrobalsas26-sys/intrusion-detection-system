import argparse
import sys

import qrcode

from auth.core import (
    UserAlreadyExistsError,
    enroll_user,
    list_users,
    revoke_user,
    set_user_role,
)


def handle_enroll(args):
    try:
        uri, recovery_codes = enroll_user(args.username)

        print(f"\n[+] User '{args.username}' enrolled successfully.\n")
        print("Scan this QR code with your authenticator app:")

        # Render the QR code in the terminal
        qr = qrcode.QRCode(version=1, box_size=1, border=2)
        qr.add_data(uri)
        qr.make(fit=True)
        qr.print_ascii(invert=True)

        print("\nOr manually enter the URI:")
        print(f"{uri}\n")

        print("Recovery codes (save these securely):")
        for i, code in enumerate(recovery_codes, start=1):
            print(f"  {i}. {code}")
        print("\n")

    except UserAlreadyExistsError:
        print(f"[!] Error: User '{args.username}' is already enrolled.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[!] Critical Error during enrollment: {e}", file=sys.stderr)
        sys.exit(1)


def handle_revoke(args):
    success, reason = revoke_user(args.username)
    if success:
        print(f"\n[+] User '{args.username}' revoked successfully.\n")
    else:
        if reason == "not_found":
            print(f"[!] User '{args.username}' not found.", file=sys.stderr)
        elif reason == "already_revoked":
            print(f"[!] User '{args.username}' is already revoked.", file=sys.stderr)
        sys.exit(1)


def handle_list(args):
    users = list_users()

    if not users:
        print("\n[i] No users enrolled.\n")
        return

    print("\n")
    header = f"{'Username':<20} {'Created At':<22} {'Role':<12} {'Status':<10}"
    separator = "-" * len(header)
    print(header)
    print(separator)

    for u in users:
        status_str = "Active" if u["is_active"] == 1 else "Revoked"
        print(f"{u['username']:<20} {u['created_at']:<22} {u['role']:<12} {status_str:<10}")
    print("\n")


def handle_set_role(args):
    try:
        if set_user_role(args.username, args.role):
            print(f"\n[+] Role for '{args.username}' set to '{args.role}'.\n")
        else:
            print(f"[!] User '{args.username}' not found.", file=sys.stderr)
            sys.exit(1)
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="auth-cli", description="Antigravity-IDS Authentication Management CLI"
    )

    subparsers = parser.add_subparsers(dest="command", required=True, help="Available subcommands")

    # Enroll subcommand
    enroll_parser = subparsers.add_parser("enroll", help="Enroll a new user with MFA")
    enroll_parser.add_argument("username", help="Username to enroll")

    # Revoke subcommand
    revoke_parser = subparsers.add_parser("revoke", help="Revoke an existing user (soft-delete)")
    revoke_parser.add_argument("username", help="Username to revoke")

    # List subcommand
    subparsers.add_parser("list", help="List enrolled users")

    # Set-role subcommand (RBAC)
    role_parser = subparsers.add_parser("set-role", help="Assign a role to a user")
    role_parser.add_argument("username", help="Target username")
    role_parser.add_argument("role", help="Role to assign: analyst, admin, or viewer")

    args = parser.parse_args()

    if args.command == "enroll":
        handle_enroll(args)
    elif args.command == "revoke":
        handle_revoke(args)
    elif args.command == "list":
        handle_list(args)
    elif args.command == "set-role":
        handle_set_role(args)


if __name__ == "__main__":
    main()

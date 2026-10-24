#!/usr/bin/env python3
"""
Stellar Studio - Emergency Administrator CLI Tool
Allows server administrators with direct SSH / terminal access to safely manage
admin accounts, reset passwords, disable 2FA, and recover access directly from the server.

Usage:
    python manage_admin.py list-users
    python manage_admin.py reset-password <username> [--password <new_password>]
    python manage_admin.py reset-mfa <username>
    python manage_admin.py generate-recovery-key <username>
    python manage_admin.py create-admin <username> <email> [--password <password>]
"""

import sys
import argparse
import getpass
import secrets
import re

from core.db import get_db_connection, init_db, log_audit_event
from core.auth import hash_password
from core.totp import generate_emergency_recovery_key

def list_users():
    """Lists all registered administrator and editor accounts."""
    init_db()
    conn = get_db_connection()
    users = conn.execute("SELECT id, username, display_name, email, role, mfa_enabled, created_at, last_login FROM users").fetchall()
    conn.close()

    if not users:
        print("[!] No users found in database. Run the web setup wizard at /admin/setup or create an admin using: python manage_admin.py create-admin")
        return

    print("=" * 80)
    print(f"{'ID':<4} {'Username':<16} {'Role':<10} {'2FA Status':<12} {'Email':<25} {'Last Login'}")
    print("-" * 80)
    for u in users:
        mfa = "ACTIVE" if u['mfa_enabled'] else "Disabled"
        last = u['last_login'] or "Never"
        print(f"{u['id']:<4} {u['username']:<16} {u['role']:<10} {mfa:<12} {u['email']:<25} {last}")
    print("=" * 80)

def reset_password(username: str, explicit_pwd: str = None):
    """Resets password for the given username, revokes all sessions, and clears failed login lockouts."""
    init_db()
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, username.lower())).fetchone()

    if not user:
        conn.close()
        print(f"[-] Error: User '{username}' not found in database.")
        sys.exit(1)

    if explicit_pwd:
        new_pwd = explicit_pwd
    else:
        new_pwd = getpass.getpass(f"Enter new password for '{user['username']}': ")
        confirm_pwd = getpass.getpass("Confirm new password: ")
        if new_pwd != confirm_pwd:
            conn.close()
            print("[-] Error: Passwords do not match.")
            sys.exit(1)

    if len(new_pwd) < 8:
        conn.close()
        print("[-] Error: Password must be at least 8 characters long.")
        sys.exit(1)

    new_hash = hash_password(new_pwd)
    new_stamp = secrets.token_hex(16)

    conn.execute("""
        UPDATE users 
        SET password_hash = ?, security_stamp = ?
        WHERE id = ?
    """, (new_hash, new_stamp, user['id']))
    conn.commit()
    conn.close()

    log_audit_event('CLI_PASSWORD_RESET', f"Password reset via CLI for user '{user['username']}'", user_id=user['id'], username=user['username'], ip_address='127.0.0.1')
    print(f"[+] Success: Password for '{user['username']}' has been updated.")
    print("[+] All active web sessions have been invalidated with a new security stamp.")

def reset_mfa(username: str):
    """Deactivates Two-Factor Authentication (2FA) if the user lost their authenticator app."""
    init_db()
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, username.lower())).fetchone()

    if not user:
        conn.close()
        print(f"[-] Error: User '{username}' not found in database.")
        sys.exit(1)

    conn.execute("""
        UPDATE users 
        SET mfa_enabled = 0, mfa_secret = NULL, mfa_backup_codes = NULL 
        WHERE id = ?
    """, (user['id'],))
    conn.commit()
    conn.close()

    log_audit_event('CLI_MFA_RESET', f"2FA disabled via CLI for user '{user['username']}'", user_id=user['id'], username=user['username'], ip_address='127.0.0.1')
    print(f"[+] Success: Two-Factor Authentication (2FA) has been deactivated for '{user['username']}'.")
    print("[+] User can now log in using their username and password directly.")

def generate_recovery_key_cli(username: str):
    """Generates a fresh Emergency Master Recovery Key for the user."""
    init_db()
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, username.lower())).fetchone()

    if not user:
        conn.close()
        print(f"[-] Error: User '{username}' not found in database.")
        sys.exit(1)

    rec_plain, rec_hash = generate_emergency_recovery_key()
    conn.execute("UPDATE users SET recovery_key_hash = ? WHERE id = ?", (rec_hash, user['id']))
    conn.commit()
    conn.close()

    log_audit_event('CLI_RECOVERY_KEY_GEN', f"Fresh recovery key generated via CLI for user '{user['username']}'", user_id=user['id'], username=user['username'], ip_address='127.0.0.1')
    print("=" * 60)
    print(f"[+] NEW EMERGENCY RECOVERY KEY FOR '{user['username']}':")
    print(f"    {rec_plain}")
    print("=" * 60)
    print("[!] Keep this key safe. It can be used at /admin/forgot-password to reset the account.")

def create_admin_user(username: str, email: str, explicit_pwd: str = None):
    """Creates a new administrator account directly from the command line."""
    init_db()
    conn = get_db_connection()
    existing = conn.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email.lower())).fetchone()
    if existing:
        conn.close()
        print(f"[-] Error: A user with username '{username}' or email '{email}' already exists.")
        sys.exit(1)

    if explicit_pwd:
        pwd = explicit_pwd
    else:
        pwd = getpass.getpass(f"Enter password for new admin '{username}': ")
        confirm = getpass.getpass("Confirm password: ")
        if pwd != confirm:
            conn.close()
            print("[-] Error: Passwords do not match.")
            sys.exit(1)

    hashed = hash_password(pwd)
    stamp = secrets.token_hex(16)
    rec_plain, rec_hash = generate_emergency_recovery_key()

    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (username, display_name, email, password_hash, role, security_stamp, recovery_key_hash)
        VALUES (?, ?, ?, ?, 'admin', ?, ?)
    """, (username, username, email.lower(), hashed, stamp, rec_hash))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()

    log_audit_event('CLI_ADMIN_CREATED', f"Admin '{username}' created via CLI", user_id=new_id, username=username, ip_address='127.0.0.1')
    print(f"[+] Administrator account '{username}' successfully created!")
    print(f"[+] Emergency Recovery Key: {rec_plain}")

def main():
    parser = argparse.ArgumentParser(description="Stellar Studio Emergency Admin CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available management commands")

    # list-users
    subparsers.add_parser("list-users", help="List all users and their MFA status")

    # reset-password
    p_reset = subparsers.add_parser("reset-password", help="Reset password for an admin account")
    p_reset.add_argument("username", help="Username or email")
    p_reset.add_argument("--password", help="Optional plain password string (or prompt interactively)")

    # reset-mfa
    p_mfa = subparsers.add_parser("reset-mfa", help="Disable Two-Factor Authentication (2FA) for an account")
    p_mfa.add_argument("username", help="Username or email")

    # generate-recovery-key
    p_rec = subparsers.add_parser("generate-recovery-key", help="Generate a new Emergency Master Recovery Key")
    p_rec.add_argument("username", help="Username or email")

    # create-admin
    p_create = subparsers.add_parser("create-admin", help="Create a brand new administrator account")
    p_create.add_argument("username", help="Admin username")
    p_create.add_argument("email", help="Admin email address")
    p_create.add_argument("--password", help="Optional password string (or prompt interactively)")

    args = parser.parse_args()

    if args.command == "list-users":
        list_users()
    elif args.command == "reset-password":
        reset_password(args.username, args.password)
    elif args.command == "reset-mfa":
        reset_mfa(args.username)
    elif args.command == "generate-recovery-key":
        generate_recovery_key_cli(args.username)
    elif args.command == "create-admin":
        create_admin_user(args.username, args.email, args.password)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setup_users.py — Creates and manages user accounts with bcrypt-hashed passwords.
Existing user accounts and their API keys are preserved on rerun so active sessions
remain valid. New users are appended, and modified users have their passwords updated.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import sys
from getpass import getpass
from pathlib import Path

# Dynamic path resolution
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
DATA_DIR = Path(os.environ.get("DATA_DIR", PROJECT_ROOT / "data"))
USERS_FILE = Path(os.environ.get("USERS_FILE", Path.home() / ".raymida_users.json"))

# Username validation: 1-32 chars, lowercase letters, numbers, hyphens, and underscores
USERNAME_RE = re.compile(r"^[a-z0-9_-]{1,32}$")


def hash_password(password: str) -> str:
    """
    Hashes a password using bcrypt. Strict requirement: exits with error if bcrypt is missing.
    """
    try:
        import bcrypt
    except ImportError:
        print("❌ Error: bcrypt is not installed (install with: pip install bcrypt).")
        print("   Refusing to proceed: passwords must not be stored with weak or unhashed schemes.")
        raise SystemExit(1)
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def load_existing_users() -> dict:
    """
    Loads existing users from USERS_FILE if present.
    Returns a dict mapping username -> user dict.
    """
    if not USERS_FILE.exists():
        return {}
    try:
        with USERS_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"⚠️ Failed to read existing users file ({e}).")
        answer = input("Continue and overwrite it? (yes/n): ").strip().lower()
        if answer == "yes":
            return {}
        sys.exit(1)


def main():
    print("🔐 Raymida User Setup")
    print("=" * 40)

    users = load_existing_users()
    if users:
        print(f"Existing users found: {', '.join(users)}")
        print("Passwords will be updated, existing API keys preserved.")

    while True:
        username = input("\nUsername (e.g., ray or tony): ").strip().lower()
        if not USERNAME_RE.match(username):
            print("❌ Username must be 1-32 characters, containing only a-z, 0-9, '-', and '_'")
            continue

        password = getpass(f"Password for {username}: ")
        if len(password) < 6:
            print("❌ Password must be at least 6 characters")
            continue

        existing = users.get(username, {})
        api_key = existing.get("api_key") or secrets.token_urlsafe(32)

        users[username] = {
            "password_hash": hash_password(password),
            "api_key": api_key,
        }

        if existing:
            print(f"✅ User '{username}' updated (API key preserved)")
        else:
            print(f"✅ User '{username}' created (API key generated)")

        another = input("\nAdd/modify another user? (y/n): ").strip().lower()
        if another != "y":
            break

    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with USERS_FILE.open("w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)

    os.chmod(USERS_FILE, 0o600)

    print(f"\n💾 Users saved to {USERS_FILE}")
    print("🔒 File permissions set to 600 (read/write for owner only)")
    print("\nNow restart the service: systemctl --user restart pochta-web.service")


if __name__ == "__main__":
    main()


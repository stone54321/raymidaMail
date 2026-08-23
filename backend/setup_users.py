"""
setup_users.py — Creates a user file with bcrypt-hashed passwords.
"""
import json
import secrets
import hashlib
import os
from pathlib import Path

USERS_FILE = Path.home() / ".raymida_users.json"

def hash_password(password: str) -> str:
    try:
        import bcrypt
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    except ImportError:
        print("⚠️ Warning: bcrypt not installed, using SHA-256 (less secure)")
        return hashlib.sha256(password.encode()).hexdigest()

def main():
    print("🔐 Raymida User Setup")
    print("=" * 40)

    users = {}

    while True:
        username = input("\nUsername (e.g., ray or tony): ").strip().lower()
        if not username:
            print("❌ Username cannot be empty")
            continue

        password = input(f"Password for {username}: ")
        if len(password) < 6:
            print("❌ Password must be at least 6 characters")
            continue

        api_key = secrets.token_urlsafe(32)

        users[username] = {
            "password_hash": hash_password(password),
            "api_key": api_key
        }

        print(f"✅ User '{username}' created")
        print(f"   (API Key generated and saved to file)")

        another = input("\nAdd another user? (y/n): ").strip().lower()
        if another != 'y':
            break

    with USERS_FILE.open('w') as f:
        json.dump(users, f, indent=2)

    os.chmod(USERS_FILE, 0o600)

    print(f"\n💾 Users saved to {USERS_FILE}")
    print("🔒 File permissions set to 600 (read/write for owner only)")
    print("\nNow restart the service: systemctl --user restart pochta-web.service")

if __name__ == "__main__":
    main()

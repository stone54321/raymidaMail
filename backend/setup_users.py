#!/usr/bin/env python3
"""
setup_users.py — Создает файл пользователей с bcrypt-хешами паролей.
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
        print("⚠️ Warning: bcrypt not installed, using SHA-256 (менее безопасно)")
        return hashlib.sha256(password.encode()).hexdigest()

def main():
    print("🔐 Raymida User Setup")
    print("=" * 40)

    users = {}

    while True:
        username = input("\nUsername (например, ray или tony): ").strip().lower()
        if not username:
            print("❌ Имя пользователя не может быть пустым")
            continue

        password = input(f"Password for {username}: ")
        if len(password) < 6:
            print("❌ Пароль должен быть минимум 6 символов")
            continue

        api_key = secrets.token_urlsafe(32)

        users[username] = {
            "password_hash": hash_password(password),
            "api_key": api_key
        }

        print(f"✅ Пользователь '{username}' создан")
        print(f"   (API Key сгенерирован и сохранен в файл)")

        another = input("\nДобавить еще пользователя? (y/n): ").strip().lower()
        if another != 'y':
            break

    with USERS_FILE.open('w') as f:
        json.dump(users, f, indent=2)

    os.chmod(USERS_FILE, 0o600)

    print(f"\n💾 Пользователи сохранены в {USERS_FILE}")
    print("🔒 Права файла установлены на 600 (только чтение для владельца)")
    print("\nТеперь перезапусти сервис: systemctl --user restart pochta-web.service")

if __name__ == "__main__":
    main()

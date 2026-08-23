#!/usr/bin/env python3
"""
r2_sync.py — Забирает пропущенные письма из Cloudflare R2 и кладёт их в локальный Maildir.
Ключи берутся из переменных окружения (через systemd EnvironmentFile).
"""
import os
import time
import hashlib
import email
import email.policy
from pathlib import Path
import boto3
from botocore.client import Config

# === Читаем настройки из переменных окружения ===
R2_ACCOUNT_ID = os.environ.get("R2_ACCOUNT_ID")
R2_ACCESS_KEY = os.environ.get("R2_ACCESS_KEY")
R2_SECRET_KEY = os.environ.get("R2_SECRET_KEY")
R2_BUCKET_NAME = os.environ.get("R2_BUCKET_NAME", "mail-fallback-queue")
R2_ENDPOINT = f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com"

LOCAL_MAIL_DIR = Path(os.environ.get("MAIL_DIR", Path.home() / "mail"))

def get_mailbox(address: str) -> str:
    address = (address or "").strip().lower()
    if "@" not in address:
        return "misc"
    name, domain = address.rsplit("@", 1)
    if domain != "raymida.com":
        return "misc"
    name = name.split("+", 1)[0].replace(".", "")
    clean_name = "".join(c for c in name if c.isalnum() or c in "-_")
    return clean_name or "misc"

def save_to_maildir(mailbox: str, raw_data: bytes) -> Path:
    mailbox_dir = LOCAL_MAIL_DIR / mailbox
    for subdir in ("tmp", "new", "cur"):
        (mailbox_dir / subdir).mkdir(parents=True, exist_ok=True)

    timestamp = int(time.time())
    file_hash = hashlib.sha1(raw_data[:4096]).hexdigest()[:12]
    filename = f"{timestamp}.{file_hash}.r2sync"

    tmp_path = mailbox_dir / "tmp" / filename
    new_path = mailbox_dir / "new" / filename

    tmp_path.write_bytes(raw_data)
    tmp_path.rename(new_path)
    return new_path

def sync_from_r2():
    if not all([R2_ACCOUNT_ID, R2_ACCESS_KEY, R2_SECRET_KEY]):
        print("❌ Ошибка: Не найдены переменные окружения R2. Проверь systemd сервис.")
        return

    print(f"[{time.strftime('%H:%M:%S')}] Подключение к R2...")

    s3 = boto3.client(
        's3',
        endpoint_url=R2_ENDPOINT,
        aws_access_key_id=R2_ACCESS_KEY,
        aws_secret_access_key=R2_SECRET_KEY,
        config=Config(signature_version='s3v4'),
        region_name='auto'
    )

    try:
        response = s3.list_objects_v2(Bucket=R2_BUCKET_NAME, Prefix='pending/')

        if 'Contents' not in response:
            print("✅ Очередь R2 пуста.")
            return

        processed_count = 0
        for obj in response['Contents']:
            key = obj['Key']
            if not key.endswith('.eml'):
                continue

            print(f"   Скачиваем: {key}")
            file_obj = s3.get_object(Bucket=R2_BUCKET_NAME, Key=key)
            raw_data = file_obj['Body'].read()

            msg = email.message_from_bytes(raw_data, policy=email.policy.default)
            to_header = msg.get("To", "")
            mailbox = get_mailbox(to_header)

            save_to_maildir(mailbox, raw_data)
            print(f"    ↳ Сохранено в ~/mail/{mailbox}/new/")

            s3.delete_object(Bucket=R2_BUCKET_NAME, Key=key)
            print(f"    ↳ Удалено из R2")
            processed_count += 1

        print(f"✅ Синхронизация завершена. Обработано: {processed_count}")

    except Exception as e:
        print(f"❌ Ошибка: {type(e).__name__}: {e}")

if __name__ == "__main__":
    sync_from_r2()

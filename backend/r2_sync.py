#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
r2_sync.py — Fetches missed emails from Cloudflare R2 and saves them to the local Maildir.
Credentials are read from environment variables (via systemd EnvironmentFile).
"""
from __future__ import annotations

import email
import email.policy
import hashlib
import os
import sys
import time
from pathlib import Path
import boto3
from botocore.client import Config

# Dynamic path resolution
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
DATA_DIR = Path(os.environ.get("DATA_DIR", PROJECT_ROOT / "data"))
MAIL_DIR = Path(os.environ.get("MAIL_DIR", Path.home() / "mail"))
LOCAL_MAIL_DIR = MAIL_DIR
MAIL_DOMAIN = os.environ.get("MAIL_DOMAIN", "raymida.com")

# === Read settings from environment variables ===
R2_ACCOUNT_ID = os.environ.get("R2_ACCOUNT_ID")
R2_ACCESS_KEY = os.environ.get("R2_ACCESS_KEY")
R2_SECRET_KEY = os.environ.get("R2_SECRET_KEY")
R2_BUCKET_NAME = os.environ.get("R2_BUCKET_NAME", "mail-fallback-queue")
R2_ENDPOINT = f"https://{R2_ACCOUNT_ID}.r2.cloudflarestorage.com"


def get_mailbox(address: str) -> str:
    address = (address or "").strip().lower()
    if "@" not in address:
        return "misc"
    name, domain = address.rsplit("@", 1)
    if domain != MAIL_DOMAIN:
        return "misc"
    name = name.split("+", 1)[0].replace(".", "")
    clean_name = "".join(c for c in name if c.isalnum() or c in "-_")
    return clean_name or "misc"


def save_to_maildir(mailbox: str, raw_data: bytes) -> Path:
    mailbox_dir = LOCAL_MAIL_DIR / mailbox
    for subdir in ("tmp", "new", "cur"):
        (mailbox_dir / subdir).mkdir(parents=True, exist_ok=True)

    # time.usec.pid.hash: high-resolution collision avoidance
    now = time.time()
    now_us = int(now * 1_000_000) % 1_000_000
    pid = os.getpid()
    digest = hashlib.sha1(raw_data[:4096]).hexdigest()[:8]
    hostname = "r2sync"
    filename = f"{int(now)}.{now_us:06d}.{pid}.{digest}.{hostname}"

    tmp_path = mailbox_dir / "tmp" / filename
    new_path = mailbox_dir / "new" / filename

    while new_path.exists():
        now_us += 1
        filename = f"{int(now)}.{now_us:06d}.{pid}.{digest}.{hostname}"
        tmp_path = mailbox_dir / "tmp" / filename
        new_path = mailbox_dir / "new" / filename

    tmp_path.write_bytes(raw_data)
    tmp_path.rename(new_path)
    return new_path


def sync_from_r2():
    if not all([R2_ACCOUNT_ID, R2_ACCESS_KEY, R2_SECRET_KEY]):
        print("❌ Error: R2 environment variables not found. Check systemd service.")
        return

    print(f"[{time.strftime('%H:%M:%S')}] Connecting to R2...")

    s3 = boto3.client(
        's3',
        endpoint_url=R2_ENDPOINT,
        aws_access_key_id=R2_ACCESS_KEY,
        aws_secret_access_key=R2_SECRET_KEY,
        config=Config(signature_version='s3v4'),
        region_name='auto'
    )

    try:
        paginator = s3.get_paginator('list_objects_v2')
        processed_count = 0

        for page in paginator.paginate(Bucket=R2_BUCKET_NAME, Prefix='pending/'):
            for obj in page.get('Contents', []):
                key = obj['Key']
                if not key.endswith('.eml'):
                    continue

                print(f"   Downloading: {key}")
                file_obj = s3.get_object(Bucket=R2_BUCKET_NAME, Key=key)
                raw_data = file_obj['Body'].read()

                msg = email.message_from_bytes(raw_data, policy=email.policy.default)
                to_header = msg.get("To", "")
                mailbox = get_mailbox(to_header)

                save_to_maildir(mailbox, raw_data)
                print(f"    ↳ Saved to {LOCAL_MAIL_DIR}/{mailbox}/new/")

                s3.delete_object(Bucket=R2_BUCKET_NAME, Key=key)
                print(f"    ↳ Deleted from R2")
                processed_count += 1

        if processed_count == 0:
            print("✅ R2 queue is empty.")
        else:
            print(f"✅ Synchronization completed. Processed: {processed_count}")

    except Exception as e:
        print(f"❌ Error: {type(e).__name__}: {e}")


if __name__ == "__main__":
    sync_from_r2()

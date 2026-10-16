#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
r2_sync.py — Fetches missed emails from Cloudflare R2 and saves them to the local Maildir.
Credentials are read from environment variables (via systemd EnvironmentFile).
"""
from __future__ import annotations

import email
import email.policy
from email.utils import getaddresses
import hashlib
import os
import sys
import time
from pathlib import Path
import boto3
from botocore.client import Config
from maildir_forms import save_form_once

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
    address = email.utils.parseaddr((address or "").strip())[1].lower()
    if "@" not in address:
        return "misc"
    name, domain = address.rsplit("@", 1)
    if domain != MAIL_DOMAIN:
        return "misc"
    name = name.split("+", 1)[0].replace(".", "")
    clean_name = "".join(c for c in name if c.isalnum() or c in "-_")
    return clean_name or "misc"


def save_to_maildir(mailbox: str, raw_data: bytes) -> Path:
    form_path = save_form_once(LOCAL_MAIL_DIR, mailbox, raw_data)
    if form_path is not None:
        return form_path
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

    descriptor = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(raw_data)
            output.flush()
            os.fsync(output.fileno())
        tmp_path.rename(new_path)
        descriptor = os.open(new_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        tmp_path.unlink(missing_ok=True)

    return new_path


def queued_mailbox(file_obj, raw_data):
    metadata = {key.lower(): value for key, value in file_obj.get('Metadata', {}).items()}
    if 'originalto' in metadata:
        addresses = getaddresses([metadata['originalto']])
    else:
        # Legacy objects have no envelope metadata. Never guess between recipients.
        msg = email.message_from_bytes(raw_data, policy=email.policy.default)
        addresses = getaddresses(msg.get_all('To', []))
    if len(addresses) != 1 or not addresses[0][1]:
        raise ValueError('Ambiguous recipient; object kept in R2')
    mailbox = get_mailbox(addresses[0][1])
    if mailbox == 'misc':
        raise ValueError('Recipient cannot be routed; object kept in R2')
    return mailbox


def sync_from_r2():
    if not all([R2_ACCOUNT_ID, R2_ACCESS_KEY, R2_SECRET_KEY]):
        print("❌ Error: R2 environment variables not found. Check systemd service.")
        return False

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
        failed_count = 0

        for page in paginator.paginate(Bucket=R2_BUCKET_NAME, Prefix='pending/'):
            for obj in page.get('Contents', []):
                key = obj['Key']
                if not key.endswith('.eml'):
                    continue

                print(f"   Downloading: {key}")
                try:
                    file_obj = s3.get_object(Bucket=R2_BUCKET_NAME, Key=key)
                    try:
                        raw_data = file_obj['Body'].read()
                    finally:
                        file_obj['Body'].close()
                    mailbox = queued_mailbox(file_obj, raw_data)
                    save_to_maildir(mailbox, raw_data)
                    s3.delete_object(Bucket=R2_BUCKET_NAME, Key=key)
                    print(f"    ↳ Saved to {mailbox}; removed from R2")
                    processed_count += 1
                except Exception as error:
                    failed_count += 1
                    print(f"    Failed ({type(error).__name__}); object retained for retry")

        if processed_count == 0 and failed_count == 0:
            print("✅ R2 queue is empty.")
        else:
            print(f"Synchronization completed. Processed: {processed_count}; failed: {failed_count}")
        return failed_count == 0

    except Exception as e:
        print(f"❌ Error: {type(e).__name__}: {e}")
        return False


if __name__ == "__main__":
    raise SystemExit(0 if sync_from_r2() else 1)

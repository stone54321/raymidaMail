"""Idempotent Maildir delivery for website requests; ordinary email is unchanged."""
from __future__ import annotations
import email
import email.policy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import uuid


def save_form_once(mail_dir: Path, mailbox: str, raw_data: bytes) -> Path | None:
    message = email.message_from_bytes(raw_data, policy=email.policy.default)
    request_id = str(message.get('X-Raymida-Request-ID', '')).lower()
    if message.get('X-Raymida-Source') != 'website' or not re.fullmatch(
        r'[a-f\d]{8}-[a-f\d]{4}-4[a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}', request_id
    ):
        return None
    if not re.fullmatch(r'[a-z0-9_-]+', mailbox):
        raise ValueError('Invalid form mailbox')
    if str(message.get('Message-ID', '')) != f'<raymida-form-{request_id}-{mailbox}@raymida.com>':
        return None
    mailbox_dir = Path(mail_dir) / mailbox
    for subdir in ('tmp', 'new', 'cur'):
        (mailbox_dir / subdir).mkdir(parents=True, exist_ok=True)
    receipts = Path(mail_dir) / '.form-receipts' / mailbox
    receipts.mkdir(parents=True, exist_ok=True, mode=0o700)
    filename = f'form-{request_id}.raymida'
    destination = mailbox_dir / 'new' / filename
    fingerprint = hashlib.sha256(raw_data).hexdigest()
    receipt_path = receipts / f'{request_id}.json'
    descriptor = os.open(receipts / f'{request_id}.lock', os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(descriptor, 'r+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if receipt_path.exists():
            if json.loads(receipt_path.read_text())['fingerprint'] != fingerprint:
                raise ValueError('Conflicting form delivery ID')
            return destination
        # Recover a write completed before the receipt was committed.
        if not destination.exists() and not (mailbox_dir / 'cur' / filename).exists():
            temporary = mailbox_dir / 'tmp' / f'{filename}.{uuid.uuid4().hex}'
            try:
                with temporary.open('xb') as output:
                    output.write(raw_data)
                    output.flush()
                    os.fsync(output.fileno())
                temporary.rename(destination)
                directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            finally:
                temporary.unlink(missing_ok=True)
        temporary_receipt = receipts / f'{request_id}.{uuid.uuid4().hex}.tmp'
        try:
            receipt_fd = os.open(temporary_receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(receipt_fd, 'w') as receipt:
                json.dump({'fingerprint': fingerprint}, receipt)
                receipt.flush()
                os.fsync(receipt.fileno())
            temporary_receipt.replace(receipt_path)
            directory_fd = os.open(receipts, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary_receipt.unlink(missing_ok=True)
    return destination

"""Idempotent Maildir delivery for website requests; ordinary email is unchanged."""
from __future__ import annotations
import email
import email.policy
from pathlib import Path
import re
from maildir_delivery import deliver_once


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
    receipts = Path(mail_dir) / '.form-receipts' / mailbox
    filename = f'form-{request_id}.raymida'
    receipt_path = receipts / f'{request_id}.json'
    return deliver_once(mail_dir, mailbox, raw_data, filename, receipt_path)

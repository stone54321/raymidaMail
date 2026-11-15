"""Durable, locked Maildir delivery with permanent replay receipts.

Requires a local POSIX filesystem with working flock, atomic rename and fsync.
Keep receipts with the mailbox: a committed receipt also prevents resurrection
after a user deletes a delivered message. Unknown/corrupt state fails closed.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from auth_state import locked


def _fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _mkdir_durable(path):
    path = Path(path)
    if not path.parent.exists():
        _mkdir_durable(path.parent)
    path.mkdir(exist_ok=True, mode=0o700)
    # Also flush existing entries: a previous attempt may have failed at fsync.
    _fsync_directory(path)
    _fsync_directory(path.parent)


def _write_file(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def _write_receipt(receipt_path, state):
    # All callers hold this receipt's permanent lock; stale temp files are safe
    # to replace. Never unlink the lock file (another process may hold its inode).
    temporary = receipt_path.with_suffix('.json.tmp')
    temporary.unlink(missing_ok=True)
    _write_file(temporary, (json.dumps(state, sort_keys=True) + '\n').encode())
    temporary.replace(receipt_path)
    _fsync_directory(receipt_path.parent)


def _verify_file(path, fingerprint):
    with path.open('rb') as source:
        digest = hashlib.sha256()
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
        if digest.hexdigest() != fingerprint:
            raise ValueError('Conflicting delivery contents; recovery required')
        # Keep the descriptor open if the reader moves new -> cur meanwhile.
        os.fsync(source.fileno())


def _find_message(mailbox_dir, filename, fingerprint):
    # Check new before cur so a concurrent one-way move cannot hide the file.
    candidate = mailbox_dir / 'new' / filename
    try:
        _verify_file(candidate, fingerprint)
        return candidate
    except FileNotFoundError:
        pass
    candidates = [mailbox_dir / 'cur' / filename]
    candidates.extend((mailbox_dir / 'cur').glob(filename + ':2,*'))
    for candidate in candidates:
        try:
            _verify_file(candidate, fingerprint)
            return candidate
        except FileNotFoundError:
            if candidate.name != filename:
                # A flags rename raced enumeration. Retry the object later.
                raise ValueError('Maildir changed during recovery; retry required')
    return None


def _stage(mailbox_dir, filename, raw_data):
    temporary = mailbox_dir / 'tmp' / filename
    temporary.unlink(missing_ok=True)
    _write_file(temporary, raw_data)
    _fsync_directory(temporary.parent)


def _publish(mailbox_dir, filename, raw_data):
    # The staged file and publishing receipt are durable before this rename.
    (mailbox_dir / 'tmp' / filename).rename(mailbox_dir / 'new' / filename)


def _flush_maildir(mailbox_dir):
    for subdir in ('tmp', 'new', 'cur'):
        _fsync_directory(mailbox_dir / subdir)


def deliver_once(mail_dir, mailbox, raw_data, filename, receipt_path, deliver=None):
    """Return after durable delivery, or raise without acknowledging the source.

    ``deliver`` may delegate to another idempotent delivery (website forms),
    returning its path, or return None to use the staged Maildir message here.
    Legacy form receipts containing only a fingerprint mean committed delivery.
    """
    if not mailbox or any(not (c.isalnum() or c in '-_') for c in mailbox):
        raise ValueError('Invalid delivery mailbox')
    if not filename or '/' in filename or '\\' in filename or filename in ('.', '..'):
        raise ValueError('Invalid delivery filename')
    mail_dir, receipt_path = Path(mail_dir), Path(receipt_path)
    _mkdir_durable(mail_dir)
    # A previous crash may have interrupted creation of an ancestor before its
    # parent was flushed. Re-establish the entire storage path on every retry.
    for directory in mail_dir.parents:
        _fsync_directory(directory)
    mailbox_dir = mail_dir / mailbox
    _mkdir_durable(mailbox_dir)
    for subdir in ('tmp', 'new', 'cur'):
        _mkdir_durable(mailbox_dir / subdir)
    # Flush each receipt-directory link, including the form mailbox namespace.
    for directory in reversed(receipt_path.parent.relative_to(mail_dir).parents):
        _mkdir_durable(mail_dir / directory)
    _mkdir_durable(receipt_path.parent)
    fingerprint = hashlib.sha256(raw_data).hexdigest()
    expected = {'version': 1, 'mailbox': mailbox, 'filename': filename, 'fingerprint': fingerprint}
    destination = mailbox_dir / 'new' / filename
    temporary = mailbox_dir / 'tmp' / filename

    with locked(receipt_path.with_suffix('.lock')):
        state, corrupt = None, False
        try:
            state = json.loads(receipt_path.read_text())
            corrupt = not isinstance(state, dict)
        except FileNotFoundError:
            pass
        except (ValueError, UnicodeError):
            corrupt = True
        if isinstance(state, dict):
            if state == {'fingerprint': fingerprint} and deliver is None and filename.startswith('form-'):
                # Preserve existing website receipts, including deleted messages.
                _find_message(mailbox_dir, filename, fingerprint)
                _flush_maildir(mailbox_dir)
                _write_receipt(receipt_path, dict(expected, status='committed'))
                return destination
            if any(key in state and state[key] != expected[key] for key in ('fingerprint', 'mailbox', 'filename')):
                raise ValueError('Conflicting delivery identity; source retained')
            if any(state.get(key) != value for key, value in expected.items()) or state.get('status') not in ('writing', 'publishing', 'committed'):
                corrupt = True
            elif state['status'] == 'committed':
                # Recommit if the preceding attempt failed after receipt rename.
                _write_receipt(receipt_path, state)
                return destination

        existing = _find_message(mailbox_dir, filename, fingerprint)
        if corrupt and existing is None:
            raise ValueError('Corrupt delivery receipt without verifiable message; source retained')
        if existing is None:
            if state is None:
                state = dict(expected, status='writing')
                _write_receipt(receipt_path, state)
            if deliver is not None:
                # The delegate has its own permanent receipt and lock. Thus an
                # interrupted outer receipt can retry without duplicating forms.
                existing = deliver()
            if existing is None:
                if state['status'] != 'writing':
                    # Publication may have succeeded and the user may already
                    # have deleted/moved the message. Do not resurrect it, even
                    # if a power failure brought the old staging entry back.
                    raise ValueError('Uncertain Maildir publication; source retained for recovery')
                _stage(mailbox_dir, filename, raw_data)
                _write_receipt(receipt_path, dict(expected, status='publishing'))
                _publish(mailbox_dir, filename, raw_data)
                existing = destination
        _flush_maildir(mailbox_dir)
        _write_receipt(receipt_path, dict(expected, status='committed'))
        temporary.unlink(missing_ok=True)
        return existing

"""Password-bound, expiring sessions and atomic user updates."""
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import time
import uuid

SESSION_TTL = 30 * 24 * 60 * 60
USERNAME = re.compile(r'^[a-z0-9_-]{1,32}$')


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def locked(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(fd, 'a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def _key(user):
    return hashlib.sha256((user['api_key'] + '\0' + user['password_hash']).encode()).digest()


def issue_session(username, user, now=None):
    if not USERNAME.fullmatch(username):
        raise ValueError('Invalid username')
    encoded = base64.urlsafe_b64encode(username.encode()).decode().rstrip('=')
    expiry = int(time.time() if now is None else now) + SESSION_TTL
    value = f'v2.{encoded}.{expiry}.{secrets.token_hex(16)}'
    return value + '.' + hmac.new(_key(user), value.encode(), hashlib.sha256).hexdigest()


def session_user(token, users, now=None):
    if not isinstance(token, str) or len(token) > 512:
        return None
    try:
        version, encoded, expiry, nonce, signature = token.split('.')
        username = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)).decode()
        current = time.time() if now is None else now
        if version != 'v2' or not USERNAME.fullmatch(username) or not re.fullmatch(r'[a-f0-9]{32}', nonce):
            return None
        if not current < int(expiry) <= current + SESSION_TTL + 60:
            return None
        user = users.get(username)
        if not user:
            return None
        value = token.rsplit('.', 1)[0]
        expected = hmac.new(_key(user), value.encode(), hashlib.sha256).hexdigest()
        return username if hmac.compare_digest(expected.encode(), signature.encode()) else None
    except (ValueError, KeyError, TypeError, UnicodeError):
        return None


def set_password(path, username, password_hash, expected_hash=None):
    if not USERNAME.fullmatch(username):
        raise ValueError('Invalid username')
    path = Path(path)
    with locked(path.with_name(path.name + '.lock')):
        users = json.loads(path.read_text()) if path.exists() else {}
        previous = users.get(username, {})
        if expected_hash is not None and previous.get('password_hash') != expected_hash:
            raise ValueError('Password changed concurrently; sign in again')
        users[username] = {**previous, 'password_hash': password_hash, 'api_key': secrets.token_urlsafe(32)}
        atomic_write(path, (json.dumps(users, indent=2) + '\n').encode())
        return users[username]

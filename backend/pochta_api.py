#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pochta_api.py v2.1 — Multi-user auth + Attachments + Search + XSS-safe ready
"""
from __future__ import annotations

import base64
from collections import defaultdict
import email
from email.header import Header
from email.mime.text import MIMEText
import email.policy
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler
import json
import mimetypes
import os
from pathlib import Path
import socket
import socketserver
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from auth_state import issue_session, session_user, set_password, SESSION_TTL
from outgoing import send_and_store, recover_accepted

# Configuration
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

MAIL_DIR = Path(os.environ.get("MAIL_DIR", Path.home() / "mail"))
_default_web = PROJECT_ROOT / "frontend" if (PROJECT_ROOT / "frontend").exists() else SCRIPT_DIR / "web"
WEB_DIR = Path(os.environ.get("WEB_DIR", _default_web))
MAIL_DOMAIN = os.environ.get("MAIL_DOMAIN", "raymida.com")
USERS_FILE = Path(os.environ.get("USERS_FILE", Path.home() / ".raymida_users.json"))
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() != "false"
RESEND_KEY = os.environ.get("RESEND_KEY", "").strip()
def _parse_port() -> int:
    if len(sys.argv) > 1:
        try:
            return int(sys.argv[1])
        except ValueError:
            pass
    return int(os.environ.get("PORT", "8926"))

PORT = _parse_port()

PREVIEW_READ_LIMIT = 262144  # 256 KB (Item 15)
MAX_BODY = 50 * 1024 * 1024  # 50 MB (Item 2)

# ==========================================
# FAIL2BAN CONFIGURATION
# ==========================================
MAX_ATTEMPTS = 5
BAN_DURATION = 300
WINDOW_SECONDS = 60
WHITELISTED_IPS = {"127.0.0.1", "::1"}

ban_lock = threading.Lock()
ip_attempts = defaultdict(lambda: {"count": 0, "last_attempt": 0.0, "banned_until": 0.0})
# ==========================================

def load_users() -> dict:
    if not USERS_FILE.exists():
        return {}
    try:
        with USERS_FILE.open("r") as f:
            return json.load(f)
    except Exception:
        return {}

def verify_password(password: str, stored_hash: str) -> bool:
    if not password or not stored_hash:
        return False
    try:
        import bcrypt
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
    except ImportError:
        print("[AUTH] Error: bcrypt module is not installed.", file=sys.stderr)
        return False
    except (ValueError, TypeError, Exception):
        return False

def get_user_by_api_key(api_key: str) -> str | None:
    if not isinstance(api_key, str) or not api_key:
        return None
    for username, data in load_users().items():
        stored = data.get('api_key')
        if isinstance(stored, str) and hmac.compare_digest(stored.encode(), api_key.encode()):
            return username
    return None

def _reply_recipient(email_data):
    import email.utils
    for field in ('replyTo', 'from'):
        value = str((email_data or {}).get(field, ''))
        if '\r' in value or '\n' in value:
            continue
        address = email.utils.parseaddr(value)[1]
        if address and '@' in address and not any(c.isspace() for c in address):
            return address
    return ''

def _extract_email_address(email_str: str) -> str:
    if "<" in email_str and ">" in email_str:
        return email_str.split("<", 1)[1].split(">", 1)[0].strip()
    return email_str.strip()

def get_emails(mailbox: str, folder: str = 'inbox') -> list[dict]:
    result = []
    if folder == 'sent':
        recover_accepted(MAIL_DIR, mailbox)
    for subdir in (('sent',) if folder == 'sent' else ('new', 'cur')):
        folder = MAIL_DIR / mailbox / subdir
        if not folder.exists():
            continue
        for file_path in folder.iterdir():
            if not file_path.is_file():
                continue
            try:
                with file_path.open("rb") as f:
                    raw_data = f.read(PREVIEW_READ_LIMIT)
                msg = email.message_from_bytes(raw_data, policy=email.policy.default)

                attachments = []
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.is_attachment() or part.get_filename():
                            attachments.append({
                                "filename": part.get_filename() or "unnamed",
                                "content_type": part.get_content_type()
                            })

                result.append({
                    "id": f"{subdir}/{file_path.name}",
                    "isNew": subdir == "new",
                    "from": str(msg.get("From", "?")),
                    "to": str(msg.get("To", "")),
                    "subject": str(msg.get("Subject", "(no subject)")),
                    "date": str(msg.get("Date", "")),
                    "mtime": file_path.stat().st_mtime,
                    "messageId": str(msg.get("Message-ID", "")),
                    "inReplyTo": str(msg.get("In-Reply-To", "")),
                    "attachments": attachments,
                })
            except Exception:
                continue
    result.sort(key=lambda item: -item["mtime"])
    return result

def search_emails(mailbox: str, query: str, folder: str = 'inbox') -> list[dict]:
    if not query.strip():
        return []
    query_lower = query.lower()
    results = []
    if folder == 'sent':
        recover_accepted(MAIL_DIR, mailbox)
    for subdir in (('sent',) if folder == 'sent' else ('new', 'cur')):
        folder = MAIL_DIR / mailbox / subdir
        if not folder.exists():
            continue
        for file_path in folder.iterdir():
            if not file_path.is_file():
                continue
            try:
                with file_path.open("rb") as f:
                    raw_data = f.read(PREVIEW_READ_LIMIT)
                msg = email.message_from_bytes(raw_data, policy=email.policy.default)
                from_str = str(msg.get("From", "")).lower()
                subject_str = str(msg.get("Subject", "")).lower()
                body_part = msg.get_body(preferencelist=("plain", "html"))
                body_str = str(body_part.get_content()).lower() if body_part else ""

                if query_lower in from_str or query_lower in str(msg.get('To', '')).lower() or query_lower in subject_str or query_lower in body_str:
                    results.append({
                        "id": f"{subdir}/{file_path.name}",
                        "isNew": subdir == "new",
                        "from": str(msg.get("From", "?")),
                        "to": str(msg.get("To", "")),
                        "subject": str(msg.get("Subject", "(no subject)")),
                        "date": str(msg.get("Date", "")),
                        "mtime": file_path.stat().st_mtime,
                    })
            except Exception:
                continue
    results.sort(key=lambda item: -item["mtime"])
    return results

def get_email(mailbox: str, email_id: str) -> dict | None:
    subdir, _, filename = email_id.partition("/")
    if subdir not in ("new", "cur", "sent") or not filename or "/" in filename or "\\" in filename or ".." in filename:
        return None

    file_path = MAIL_DIR / mailbox / subdir / filename

    if not file_path.is_file() and subdir == "new":
        cur_candidate = MAIL_DIR / mailbox / "cur" / filename
        if cur_candidate.is_file():
            file_path = cur_candidate

    if not file_path.is_file():
        return None

    try:
        mtime = file_path.stat().st_mtime
    except OSError:
        return None

    try:
        raw_bytes = file_path.read_bytes()
    except OSError:
        return None

    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    body_part = msg.get_body(preferencelist=("plain", "html"))
    text, is_html = "", False
    if body_part is not None:
        try:
            text = body_part.get_content()
            is_html = body_part.get_content_type() == "text/html"
        except Exception:
            text, is_html = "", False

    if subdir == "new" and file_path.parent.name == "new":
        target_path = MAIL_DIR / mailbox / "cur" / filename
        try:
            file_path.rename(target_path)
            file_path = target_path
        except OSError:
            pass

    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_attachment() or part.get_filename():
                attachments.append({
                    "filename": part.get_filename() or "unnamed",
                    "content_type": part.get_content_type()
                })

    return {
        "from": str(msg.get("From", "?")),
        "to": str(msg.get("To", "")),
        "replyTo": str(msg.get("Reply-To", "")),
        "folder": 'sent' if subdir == 'sent' else 'inbox',
        "subject": str(msg.get("Subject", "(no subject)")),
        "date": str(msg.get("Date", "")),
        "mtime": mtime,
        "text": text,
        "isHtml": is_html,
        "messageId": str(msg.get("Message-ID", "")),
        "references": str(msg.get("References", "")),
        "attachments": attachments,
    }

def get_attachment(mailbox: str, email_id: str, attachment_index: int) -> tuple[bytes, str, str] | None:
    subdir, _, filename = email_id.partition("/")
    if subdir not in ("new", "cur", "sent") or not filename or "/" in filename or "\\" in filename or ".." in filename:
        return None
    file_path = MAIL_DIR / mailbox / subdir / filename
    if not file_path.is_file() and subdir == "new":
        cur_candidate = MAIL_DIR / mailbox / "cur" / filename
        if cur_candidate.is_file():
            file_path = cur_candidate
    if not file_path.is_file():
        return None
    try:
        raw_bytes = file_path.read_bytes()
    except OSError:
        return None
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    if not msg.is_multipart():
        return None
    attachments = [part for part in msg.walk() if part.is_attachment() or part.get_filename()]
    if attachment_index < 0 or attachment_index >= len(attachments):
        return None
    part = attachments[attachment_index]
    payload = part.get_payload(decode=True) or b""
    return (payload, part.get_filename() or "attachment", part.get_content_type() or "application/octet-stream")

def send_email(from_addr: str, to_addr: str, subject: str, body: str,
               in_reply_to: str = "", references: str = "", attachments: list[dict] | None = None, send_id: str | None = None) -> str:
    if not RESEND_KEY:
        return "Resend API key is not configured"

    try:
        send_id = str(uuid.UUID(send_id)) if send_id else str(uuid.uuid4())
    except (ValueError, TypeError):
        return 'Invalid send identifier'
    if not all(isinstance(value, str) for value in (from_addr, to_addr, subject, body, in_reply_to, references)):
        return 'Invalid message'
    if any('\r' in value or '\n' in value for value in (from_addr, to_addr, subject, in_reply_to, references)):
        return 'Invalid message headers'
    sender_name = from_addr.split("@", 1)[0].capitalize()
    payload = {
        "from": f"{sender_name} <{from_addr}>",
        "to": [to_addr],
        "subject": subject,
        "text": body,
        "headers": {"Message-ID": f"<raymida-sent-{send_id}@{MAIL_DOMAIN}>"},
    }

    if in_reply_to:
        payload["headers"].update({
            "In-Reply-To": in_reply_to,
            "References": (references + " " + in_reply_to).strip()
        })

    if attachments:
        payload["attachments"] = attachments

    def submit(message_payload, idempotency_key):
        data = json.dumps(message_payload).encode('utf-8')
        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=data,
            headers={
                "Authorization": f"Bearer {RESEND_KEY}",
                "Content-Type": "application/json",
                "User-Agent": "RaymidaMail/1.0",
                "Idempotency-Key": idempotency_key,
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            if not 200 <= response.status < 300:
                raise ValueError(f'Resend returned status {response.status}')
            result = json.loads(response.read())
            if not isinstance(result.get('id'), str) or not result['id']:
                raise ValueError('Invalid Resend acceptance response')
            return result['id']
    try:
        send_and_store(MAIL_DIR, from_addr.split('@', 1)[0], send_id, payload, submit)
        return ''
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8', errors='replace')
        return f"Resend API Error {e.code}: {error_body}"

    except Exception as e:
        return f"{type(e).__name__}: {e}"


class MailAPIHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 60

    def log_message(self, *_):
        pass

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (TimeoutError, socket.timeout):
            self.close_connection = True
        except (ConnectionResetError, BrokenPipeError):
            self.close_connection = True

    def get_client_ip(self) -> str:
        cf_ip = self.headers.get("Cf-Connecting-Ip")
        if cf_ip:
            return cf_ip.strip()
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[-1].strip()
        return self.client_address[0]

    def check_ban(self, ip: str) -> bool:
        with ban_lock:
            if ip in ip_attempts:
                record = ip_attempts[ip]
                now = time.time()
                if now < record["banned_until"]:
                    return True
                if now - record["last_attempt"] > WINDOW_SECONDS:
                    del ip_attempts[ip]
                    return False
            return False

    def record_failure(self, ip: str):
        if ip in WHITELISTED_IPS:
            return
        with ban_lock:
            record = ip_attempts[ip]
            record["count"] += 1
            record["last_attempt"] = time.time()
            if record["count"] >= MAX_ATTEMPTS:
                record["banned_until"] = time.time() + BAN_DURATION
                print(f"[FAIL2BAN] IP {ip} banned for {BAN_DURATION} seconds.")

    def record_success(self, ip: str):
        with ban_lock:
            if ip in ip_attempts:
                del ip_attempts[ip]

    def _send_bytes(self, data: bytes, content_type: str, status: int = 200, cookie: str | None = None, close_connection: bool = False):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        if close_connection or self.close_connection:
            self.send_header("Connection", "close")
        if self.path.startswith('/api/'):
            self.send_header('Cache-Control', 'no-store')
        if cookie is not None:
            secure = '; Secure' if COOKIE_SECURE else ''
            self.send_header('Set-Cookie', f'auth_key={cookie}; Path=/; Max-Age={SESSION_TTL if cookie else 0}; HttpOnly{secure}; SameSite=Lax')
        self.end_headers()
        try:
            self.wfile.write(data)
        except (ConnectionResetError, BrokenPipeError, TimeoutError, socket.timeout):
            self.close_connection = True

    def _send_json(self, data: dict | list, status: int = 200, cookie: str | None = None, close_connection: bool = False):
        self._send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status, cookie, close_connection)

    def _is_authenticated(self) -> str | None:
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            value = auth_header[7:].strip()
            user = session_user(value, load_users()) or get_user_by_api_key(value)
            if user:
                return user
        for chunk in (self.headers.get("Cookie") or "").split(";"):
            name, _, value = chunk.strip().partition("=")
            if name in ("auth_key", "session"):
                user = session_user(value, load_users())
                if user:
                    return user
        return None

    def do_POST(self):
        ip = self.get_client_ip()
        if self.check_ban(ip):
            self.close_connection = True
            return self._send_json({"ok": False, "error": "IP temporarily banned"}, 403, close_connection=True)

        cl_header = self.headers.get("Content-Length")
        if cl_header is None:
            content_length = 0
        else:
            try:
                content_length = int(cl_header.strip())
            except (ValueError, TypeError):
                self.close_connection = True
                return self._send_json({"ok": False, "error": "invalid content length"}, 400, close_connection=True)

        if content_length < 0:
            self.close_connection = True
            return self._send_json({"ok": False, "error": "negative content length"}, 400, close_connection=True)

        if content_length > MAX_BODY:
            self.close_connection = True
            return self._send_json({"ok": False, "error": "payload too large"}, 413, close_connection=True)

        try:
            body = self.rfile.read(content_length) if content_length > 0 else b""
        except (TimeoutError, socket.timeout):
            self.close_connection = True
            return self._send_json({"ok": False, "error": "request timeout"}, 408, close_connection=True)
        except OSError:
            self.close_connection = True
            return

        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path

        if path == "/api/login":
            try:
                payload = json.loads(body or b"{}")
                username = payload.get("username", "").strip().lower()
                password = payload.get("password", "")
                if not isinstance(username, str) or not isinstance(password, str):
                    raise ValueError('Invalid credentials')
            except Exception:
                return self._send_json({"ok": False, "error": "invalid request"}, 400)

            users = load_users()
            if username in users and verify_password(password, users[username].get("password_hash", "")):
                self.record_success(ip)
                return self._send_json({"ok": True, "username": username}, cookie=issue_session(username, users[username]))
            else:
                self.record_failure(ip)
                self.close_connection = True
                return self._send_json({"ok": False, "error": "invalid credentials"}, 403, close_connection=True)

        if path == '/api/logout':
            return self._send_json({'ok': True}, cookie='')
        current_user = self._is_authenticated()
        if not current_user:
            self.close_connection = True
            return self._send_json({"ok": False, "error": "unauthorized"}, 403, close_connection=True)

        if path == '/api/password':
            try:
                payload = json.loads(body)
                old, new = payload['old_password'], payload['new_password']
                if not isinstance(old, str) or not isinstance(new, str) or len(new) < 12 or len(new.encode('utf8')) > 72:
                    raise ValueError('Пароль: минимум 12 символов, не больше 72 байт UTF-8.')
                user = load_users()[current_user]
                if not verify_password(old, user['password_hash']):
                    raise ValueError('Текущий пароль неверен.')
                import bcrypt
                updated = set_password(USERS_FILE, current_user, bcrypt.hashpw(new.encode(), bcrypt.gensalt()).decode(), expected_hash=user['password_hash'])
            except (ValueError, KeyError, TypeError):
                return self._send_json({'ok': False, 'error': 'Проверь текущий пароль. Новый пароль: от 12 символов, до 72 байт UTF-8.'}, 400)
            except OSError:
                return self._send_json({'ok': False, 'error': 'Не удалось сохранить пароль.'}, 503)
            return self._send_json({'ok': True}, cookie=issue_session(current_user, updated))

        if path == "/api/send":
            content_type = self.headers.get("Content-Type", "")

            if "multipart/form-data" in content_type:
                if "boundary=" not in content_type:
                    return self._send_json({"ok": False, "error": "missing boundary in multipart/form-data"}, 400)
                try:
                    boundary_part = content_type.split("boundary=", 1)[1]
                    boundary = boundary_part.split(";")[0].strip().strip('"\'')
                    if not boundary:
                        return self._send_json({"ok": False, "error": "empty boundary"}, 400)
                except Exception:
                    return self._send_json({"ok": False, "error": "invalid boundary in multipart/form-data"}, 400)

                raw_multipart = f"Content-Type: multipart/form-data; boundary={boundary}\r\n\r\n".encode() + body
                msg = email.message_from_bytes(raw_multipart)

                subject, text, email_id, attachments = "", "", "", []
                for part in msg.walk():
                    if part.get_content_maintype() == 'multipart':
                        continue
                    name = part.get_param('name', header='Content-Disposition')
                    if not name:
                        continue
                    if name == 'subject':
                        subject = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    elif name == 'text':
                        text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    elif name == 'id':
                        email_id = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    elif name == 'attachments':
                        filename = part.get_filename()
                        if filename:
                            file_data = part.get_payload(decode=True)
                            if file_data:
                                attachments.append({"filename": filename, "content": base64.b64encode(file_data).decode('utf-8')})
            else:
                try:
                    payload = json.loads(body or b"{}")
                except Exception:
                    return self._send_json({"ok": False, "error": "invalid request"}, 400)
                if not isinstance(payload, dict):
                    return self._send_json({"ok": False, "error": "invalid request"}, 400)
                subject = payload.get("subject", "")
                text = payload.get("text", "")
                email_id = payload.get("id", "")
                attachments = None

            if not all(isinstance(value, str) for value in (subject, text, email_id)):
                return self._send_json({"ok": False, "error": "invalid request"}, 400)

            email_data = get_email(current_user, email_id or "")
            to_addr = _reply_recipient(email_data) if (email_data or {}).get('folder') != 'sent' else ''
            if not to_addr:
                return self._send_json({"ok": False, "error": "no recipient"}, 400)

            error_msg = send_email(f"{current_user}@{MAIL_DOMAIN}", to_addr, subject, text,
                                   (email_data or {}).get("messageId", ""), (email_data or {}).get("references", ""), attachments, send_id=self.headers.get('X-Raymida-Send-ID'))
            if error_msg:
                return self._send_json({"ok": False, "error": error_msg}, 502)
            return self._send_json({"ok": True})

        self._send_json({"ok": False, "error": "not found"}, 404)

    def do_GET(self):
        ip = self.get_client_ip()
        parsed_path = urllib.parse.urlparse(self.path)

        if parsed_path.path.startswith("/api/") and self.check_ban(ip):
            self.close_connection = True
            return self._send_json({"ok": False, "error": "IP temporarily banned"}, 403, close_connection=True)

        query_params = urllib.parse.parse_qs(parsed_path.query)

        if parsed_path.path.startswith("/api/"):
            current_user = self._is_authenticated()
            if not current_user:
                self.close_connection = True
                return self._send_json({"ok": False, "error": "unauthorized"}, 403, close_connection=True)

            if parsed_path.path == "/api/me":
                return self._send_json({"ok": True, "username": current_user})
            if parsed_path.path == "/api/boxes":
                return self._send_json([current_user] if (MAIL_DIR / current_user).exists() else [])
            if parsed_path.path == "/api/list":
                folder = (query_params.get('folder') or ['inbox'])[0]
                if folder not in ('inbox', 'sent'):
                    return self._send_json({'ok': False, 'error': 'invalid folder'}, 400)
                return self._send_json(get_emails(current_user, folder))
            if parsed_path.path == "/api/search":
                q = (query_params.get("q") or [""])[0]
                folder = (query_params.get('folder') or ['inbox'])[0]
                if folder not in ('inbox', 'sent'):
                    return self._send_json({'ok': False, 'error': 'invalid folder'}, 400)
                return self._send_json(search_emails(current_user, q, folder))
            if parsed_path.path == "/api/mail":
                email_id = (query_params.get("id") or [""])[0]
                if not email_id:
                    return self._send_json({"ok": False, "error": "email not found"}, 404)
                email_data = get_email(current_user, email_id)
                if email_data:
                    return self._send_json(email_data)
                return self._send_json({"ok": False, "error": "email not found"}, 404)
            if parsed_path.path == "/api/attachment":
                email_id = (query_params.get("id") or [""])[0]
                try:
                    idx = int((query_params.get("idx") or ["0"])[0])
                except ValueError:
                    return self._send_json({"ok": False, "error": "invalid index"}, 400)

                attachment = get_attachment(current_user, email_id, idx)
                if not attachment:
                    return self._send_json({"ok": False, "error": "attachment not found"}, 404)

                data, filename, content_type = attachment
                filename = filename or "attachment"
                ascii_fallback = "".join(c if 32 <= ord(c) < 127 and c not in ('"', '\\', ';') else '_' for c in filename).strip() or "attachment"
                encoded_filename = urllib.parse.quote(filename, safe='')

                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Content-Disposition", f'attachment; filename="{ascii_fallback}"; filename*=UTF-8\'\'{encoded_filename}')
                self.end_headers()
                try:
                    self.wfile.write(data)
                except (ConnectionResetError, BrokenPipeError, TimeoutError, socket.timeout):
                    self.close_connection = True
                return

            return self._send_json({"ok": False, "error": "not found"}, 404)

        filename = parsed_path.path.lstrip("/") or "index.html"
        try:
            resolved_web = WEB_DIR.resolve()
            file_path = (WEB_DIR / filename).resolve()
            if not file_path.is_relative_to(resolved_web) or not file_path.is_file():
                return self._send_bytes(b"nothing here", "text/plain; charset=utf-8", 404)
        except Exception:
            return self._send_bytes(b"nothing here", "text/plain; charset=utf-8", 404)

        content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type.endswith("javascript"):
            content_type += "; charset=utf-8"
        try:
            self._send_bytes(file_path.read_bytes(), content_type)
        except OSError:
            self._send_bytes(b"nothing here", "text/plain; charset=utf-8", 404)


class ThreadedMailServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    if not RESEND_KEY:
        print("Warning: RESEND_KEY is not configured", file=sys.stderr)

    WEB_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Mail API v2.1 (multi-user + attachments + search) running on port {PORT}", flush=True)

    with ThreadedMailServer(("127.0.0.1", PORT), MailAPIHandler) as server:
        server.serve_forever()

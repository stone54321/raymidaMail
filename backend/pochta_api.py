#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pochta_api.py v2.1 — Multi-user auth + Attachments + Search + XSS-safe ready
"""
from __future__ import annotations

import email
import email.policy
import json
import mimetypes
import os
import socketserver
import sys
import time
import urllib.parse
import urllib.request
import threading
import hashlib
import base64
from collections import defaultdict
from email.header import Header
from email.mime.text import MIMEText
from http.server import BaseHTTPRequestHandler
from pathlib import Path

# Configuration
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

MAIL_DIR = Path(os.environ.get("MAIL_DIR", Path.home() / "mail"))
_default_web = PROJECT_ROOT / "frontend" if (PROJECT_ROOT / "frontend").exists() else SCRIPT_DIR / "web"
WEB_DIR = Path(os.environ.get("WEB_DIR", _default_web))
MAIL_DOMAIN = os.environ.get("MAIL_DOMAIN", "raymida.com")
USERS_FILE = Path.home() / ".raymida_users.json"
RESEND_KEY = os.environ.get("RESEND_KEY", "").strip()
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8926

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
    try:
        import bcrypt
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
    except ImportError:
        return hashlib.sha256(password.encode()).hexdigest() == stored_hash

def get_user_by_api_key(api_key: str) -> str | None:
    users = load_users()
    for username, data in users.items():
        if data.get("api_key") == api_key:
            return username
    return None

def get_mailboxes() -> list[str]:
    if not MAIL_DIR.exists():
        return []
    return sorted(p.name for p in MAIL_DIR.iterdir() if (p / "new").exists() or (p / "cur").exists())

def _extract_email_address(email_str: str) -> str:
    if "<" in email_str and ">" in email_str:
        return email_str.split("<", 1)[1].split(">", 1)[0].strip()
    return email_str.strip()

def get_emails(mailbox: str) -> list[dict]:
    result = []
    for subdir in ("new", "cur"):
        folder = MAIL_DIR / mailbox / subdir
        if not folder.exists():
            continue
        for file_path in folder.iterdir():
            if not file_path.is_file():
                continue
            try:
                with file_path.open("rb") as f:
                    raw_data = f.read(32768)
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

def search_emails(mailbox: str, query: str) -> list[dict]:
    if not query.strip():
        return []
    query_lower = query.lower()
    results = []
    for subdir in ("new", "cur"):
        folder = MAIL_DIR / mailbox / subdir
        if not folder.exists():
            continue
        for file_path in folder.iterdir():
            if not file_path.is_file():
                continue
            try:
                with file_path.open("rb") as f:
                    raw_data = f.read(16384)
                msg = email.message_from_bytes(raw_data, policy=email.policy.default)
                from_str = str(msg.get("From", "")).lower()
                subject_str = str(msg.get("Subject", "")).lower()
                body_part = msg.get_body(preferencelist=("plain", "html"))
                body_str = str(body_part.get_content()).lower() if body_part else ""

                if query_lower in from_str or query_lower in subject_str or query_lower in body_str:
                    results.append({
                        "id": f"{subdir}/{file_path.name}",
                        "isNew": subdir == "new",
                        "from": str(msg.get("From", "?")),
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
    if subdir not in ("new", "cur") or "/" in filename or ".." in filename:
        return None

    file_path = MAIL_DIR / mailbox / subdir / filename


    if not file_path.exists() and subdir == "new":
        file_path = MAIL_DIR / mailbox / "cur" / filename

    if not file_path.exists():
        return None

    msg = email.message_from_bytes(file_path.read_bytes(), policy=email.policy.default)
    body_part = msg.get_body(preferencelist=("plain", "html"))
    text, is_html = "", False
    if body_part is not None:
        text = body_part.get_content()
        is_html = body_part.get_content_type() == "text/html"


    if subdir == "new" and file_path.parent.name == "new":
        try:
            file_path.rename(MAIL_DIR / mailbox / "cur" / filename)
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
        "subject": str(msg.get("Subject", "(no subject)")),
        "date": str(msg.get("Date", "")),
        "mtime": file_path.stat().st_mtime,
        "text": text,
        "isHtml": is_html,
        "messageId": str(msg.get("Message-ID", "")),
        "references": str(msg.get("References", "")),
        "attachments": attachments,
    }

def get_attachment(mailbox: str, email_id: str, attachment_index: int) -> tuple[bytes, str, str] | None:
    subdir, _, filename = email_id.partition("/")
    if subdir not in ("new", "cur") or "/" in filename or ".." in filename:
        return None
    file_path = MAIL_DIR / mailbox / subdir / filename
    if not file_path.exists():
        return None
    msg = email.message_from_bytes(file_path.read_bytes(), policy=email.policy.default)
    if not msg.is_multipart():
        return None
    attachments = [part for part in msg.walk() if part.is_attachment() or part.get_filename()]
    if attachment_index < 0 or attachment_index >= len(attachments):
        return None
    part = attachments[attachment_index]
    return (part.get_payload(decode=True), part.get_filename() or "attachment", part.get_content_type() or "application/octet-stream")

def send_email(from_addr: str, to_addr: str, subject: str, body: str,
               in_reply_to: str = "", references: str = "", attachments: list[dict] | None = None) -> str:
    if not RESEND_KEY:
        return "Resend API key is not configured"

    sender_name = from_addr.split("@", 1)[0].capitalize()
    payload = {
        "from": f"{sender_name} <{from_addr}>",
        "to": [to_addr],
        "subject": subject,
        "text": body,
    }

    if in_reply_to:
        payload["headers"] = {
            "In-Reply-To": in_reply_to,
            "References": (references + " " + in_reply_to).strip()
        }

    if attachments:
        payload["attachments"] = attachments

    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=data,
            headers={
                "Authorization": f"Bearer {RESEND_KEY}",
                "Content-Type": "application/json",
                "User-Agent": "RaymidaMail/1.0"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            return "" if response.status == 200 else f"Resend returned status {response.status}"

    except urllib.error.HTTPError as e:
        # 🔥 READ THE ACTUAL ERROR FROM RESEND (e.g., "invalid api key" or "unverified domain")
        error_body = e.read().decode('utf-8')
        return f"Resend API Error {e.code}: {error_body}"

    except Exception as e:
        return f"{type(e).__name__}: {e}"


class MailAPIHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def get_client_ip(self) -> str:
        cf_ip = self.headers.get("Cf-Connecting-Ip")
        if cf_ip:
            return cf_ip.strip()
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
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

    def _send_bytes(self, data: bytes, content_type: str, status: int = 200, cookie: str = ""):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if cookie:
            self.send_header("Set-Cookie", f"auth_key={cookie}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax")
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, data: dict | list, status: int = 200, cookie: str = ""):
        self._send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status, cookie)

    def _is_authenticated(self) -> str | None:
        for chunk in (self.headers.get("Cookie") or "").split(";"):
            name, _, value = chunk.strip().partition("=")
            if name == "auth_key":
                return get_user_by_api_key(value)
        return None

    def do_POST(self):
        ip = self.get_client_ip()
        if self.check_ban(ip):
            return self._send_json({"ok": False, "error": "IP temporarily banned"}, 403)

        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))

        if path == "/api/login":
            try:
                payload = json.loads(body or b"{}")
                username = payload.get("username", "").strip().lower()
                password = payload.get("password", "")
            except Exception:
                return self._send_json({"ok": False, "error": "invalid request"}, 400)

            users = load_users()
            if username in users and verify_password(password, users[username]["password_hash"]):
                self.record_success(ip)
                return self._send_json({"ok": True, "username": username}, cookie=users[username]["api_key"])
            else:
                self.record_failure(ip)
                return self._send_json({"ok": False, "error": "invalid credentials"}, 403)

        current_user = self._is_authenticated()
        if not current_user:
            return self._send_json({"ok": False, "error": "unauthorized"}, 403)

        if path == "/api/send":
            content_type = self.headers.get("Content-Type", "")

            if "multipart/form-data" in content_type:
                # Parse multipart without the deprecated cgi module (compatible with Python 3.13+)
                boundary = content_type.split("boundary=")[1].strip('"\'')
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
                subject = payload.get("subject", "")
                text = payload.get("text", "")
                email_id = payload.get("id", "")
                attachments = None

            email_data = get_email(current_user, email_id or "")
            to_addr = _extract_email_address((email_data or {}).get("from", ""))
            if not to_addr:
                return self._send_json({"ok": False, "error": "no recipient"}, 400)

            error_msg = send_email(f"{current_user}@{MAIL_DOMAIN}", to_addr, subject, text,
                                   (email_data or {}).get("messageId", ""), (email_data or {}).get("references", ""), attachments)
            if error_msg:
                return self._send_json({"ok": False, "error": error_msg})
            return self._send_json({"ok": True})

        self._send_json({"ok": False, "error": "not found"}, 404)

    def do_GET(self):
        ip = self.get_client_ip()
        parsed_path = urllib.parse.urlparse(self.path)

        if parsed_path.path.startswith("/api/") and self.check_ban(ip):
            return self._send_json({"ok": False, "error": "IP temporarily banned"}, 403)

        query_params = urllib.parse.parse_qs(parsed_path.query)

        if parsed_path.path.startswith("/api/"):
            current_user = self._is_authenticated()
            if not current_user:
                return self._send_json({"ok": False, "error": "unauthorized"}, 403)

            if parsed_path.path == "/api/me":
                return self._send_json({"ok": True, "username": current_user})
            if parsed_path.path == "/api/boxes":
                return self._send_json([current_user] if (MAIL_DIR / current_user).exists() else [])
            if parsed_path.path == "/api/list":
                return self._send_json(get_emails(current_user))
            if parsed_path.path == "/api/search":
                q = (query_params.get("q") or [""])[0]
                return self._send_json(search_emails(current_user, q))
            if parsed_path.path == "/api/mail":
                email_id = (query_params.get("id") or [""])[0]
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
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.end_headers()
                self.wfile.write(data)
                return

            return self._send_json({"ok": False, "error": "not found"}, 404)

        filename = parsed_path.path.lstrip("/") or "index.html"
        file_path = (WEB_DIR / filename).resolve()
        if not str(file_path).startswith(str(WEB_DIR.resolve())) or not file_path.is_file():
            return self._send_bytes(b"nothing here", "text/plain; charset=utf-8", 404)

        content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type.endswith("javascript"):
            content_type += "; charset=utf-8"
        self._send_bytes(file_path.read_bytes(), content_type)


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

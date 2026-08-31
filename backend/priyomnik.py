#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
inbound_receiver.py — Mail receiver for raymida.com.

Port 25 is blocked by the ISP and cannot be forwarded via Cloudflare Tunnel
because external mail servers cannot use cloudflared; they connect directly.
Therefore, Cloudflare Email Routing catches the email, passes it to a Worker,
and the Worker delivers it here via HTTPS through the existing Tunnel.

Saves to Maildir format: understood by all mail clients. Each email is a separate file,
no databases, no locking.

    ~/mail/<mailbox>/new/  — new, unread emails
    ~/mail/<mailbox>/cur/  — read emails
    ~/mail/<mailbox>/tmp/  — in-progress writes (Maildir rule: write here first,
                             then rename to 'new' — readers never see partial files)

Usage:
    INBOUND_KEY=<secret> python3 inbound_receiver.py [port]

The key is mandatory: without it, anyone could spam this endpoint, as it is
exposed via the Tunnel. The Cloudflare Worker must send it in the 'X-Webhook-Key' header.
"""
from __future__ import annotations

import email
import email.policy
import hashlib
import hmac
import json
import os
import socketserver
import sys
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path

# Configuration
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
DATA_DIR = Path(os.environ.get("DATA_DIR", PROJECT_ROOT / "data"))
MAIL_DIR = Path(os.environ.get("MAIL_DIR", Path.home() / "mail"))
MAIL_DOMAIN = os.environ.get("MAIL_DOMAIN", "raymida.com")
# Supports both INBOUND_KEY (recommended) and legacy RAY_MAIL_KEY for backward compatibility
INBOUND_KEY = os.environ.get("INBOUND_KEY") or os.environ.get("RAY_MAIL_KEY") or ""
try:
    PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8925
except ValueError:
    PORT = 8925
MAX_SIZE = int(os.environ.get("MAX_SIZE", 50 * 1024 * 1024))  # Reject emails larger than 50 MB


def get_mailbox(address: str) -> str:
    """
    Extracts mailbox name from email address.
    'ray@raymida.com' -> 'ray'
    'ray+test@raymida.com' -> 'ray' (plus addressing)
    'r.a.y@raymida.com' -> 'ray' (dot ignoring)
    Unknown domains or invalid formats -> 'misc'
    """
    address = (address or "").strip().lower()
    if "@" not in address:
        return "misc"

    name, domain = address.rsplit("@", 1)
    if domain != MAIL_DOMAIN:
        return "misc"

    # Handle plus addressing and remove dots
    name = name.split("+", 1)[0].replace(".", "")

    # Keep only alphanumeric, hyphens, and underscores
    clean_name = "".join(c for c in name if c.isalnum() or c in "-_")
    return clean_name or "misc"


def save_to_maildir(recipient: str, raw_data: bytes) -> Path:
    """
    Saves email using the Maildir atomic write pattern:
    write to 'tmp', then rename to 'new'.
    """
    mailbox_dir = MAIL_DIR / get_mailbox(recipient)
    for subdir in ("tmp", "new", "cur"):
        (mailbox_dir / subdir).mkdir(parents=True, exist_ok=True)

    # Maildir filename format: timestamp.usec.pid.hash.hostname
    now = time.time()
    now_us = int(now * 1_000_000) % 1_000_000
    pid = os.getpid()
    digest = hashlib.sha1(raw_data[:4096]).hexdigest()[:8]
    hostname = "raymida"
    filename = f"{int(now)}.{now_us:06d}.{pid}.{digest}.{hostname}"

    tmp_path = mailbox_dir / "tmp" / filename
    new_path = mailbox_dir / "new" / filename

    while new_path.exists():
        now_us += 1
        filename = f"{int(now)}.{now_us:06d}.{pid}.{digest}.{hostname}"
        tmp_path = mailbox_dir / "tmp" / filename
        new_path = mailbox_dir / "new" / filename

    # Atomic write (FIXED: was previously raw_dataTMP)
    tmp_path.write_bytes(raw_data)
    tmp_path.rename(new_path)  # Atomic on POSIX systems

    return new_path


def parse_headers(raw_data: bytes) -> dict:
    """Parses headers only for logging purposes. The raw file is saved intact."""
    try:
        msg = email.message_from_bytes(raw_data, policy=email.policy.default)
        return {
            "from": str(msg.get("From", ""))[:120],
            "to": str(msg.get("To", ""))[:120],
            "subject": str(msg.get("Subject", ""))[:160]
        }
    except Exception as e:
        return {
            "from": "?",
            "to": "?",
            "subject": f"(parse error: {type(e).__name__})"
        }


class InboundHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 60
    close_connection = False

    def _send_json_response(self, status: int, message: str):
        body = json.dumps({"ok": status < 300, "message": message}, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass  # Custom logging below, suppress default noise

    def do_GET(self):
        # Liveness check for monitoring (e.g., Uptime Kuma)
        if self.path.rstrip("/") in ("/health", "/live"):
            self._send_json_response(200, "alive")
        else:
            self.close_connection = True
            self._send_json_response(404, "not found")

    def do_POST(self):
        if self.path.rstrip("/") not in ("/inbound", "/webhook"):
            self.close_connection = True
            return self._send_json_response(404, "not found")

        # Security check
        webhook_key = (self.headers.get("X-Webhook-Key") or "").encode("utf-8")
        if not INBOUND_KEY or not hmac.compare_digest(webhook_key, INBOUND_KEY.encode("utf-8")):
            print(f"· DENIED: Invalid key from {self.client_address[0]}", flush=True)
            self.close_connection = True
            return self._send_json_response(403, "forbidden")

        # Size check
        try:
            content_length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self.close_connection = True
            return self._send_json_response(400, "invalid content length")

        if content_length < 0 or content_length > MAX_SIZE:
            self.close_connection = True
            return self._send_json_response(413, "payload too large")

        # Read payload
        try:
            raw_data = self.rfile.read(content_length)
        except TimeoutError:
            self.close_connection = True
            return self._send_json_response(408, "request timeout")

        # Determine recipient (prefer header, fallback to parsing)
        recipient = self.headers.get("X-Original-To") or self.headers.get("X-Ray-To") or ""
        if not recipient:
            recipient = parse_headers(raw_data).get("to", "")

        # Save to disk
        try:
            saved_path = save_to_maildir(recipient, raw_data)
        except Exception as e:
            print(f"· SAVE FAILED: {type(e).__name__}: {e}", flush=True)
            self.close_connection = True
            return self._send_json_response(500, "internal server error")

        # Log success
        headers = parse_headers(raw_data)
        mailbox_name = get_mailbox(recipient)
        print(f"✉ {mailbox_name:10s} ← {headers['from'][:60]} | {headers['subject'][:70]}", flush=True)

        self._send_json_response(200, saved_path.name)


class ThreadedReceiverServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# FIXED: was previously if __name__ == "__";
if __name__ == "__main__":
    if not INBOUND_KEY:
        print("Error: Missing key. Start with INBOUND_KEY=<secret>", file=sys.stderr)
        raise SystemExit(2)

    MAIL_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Inbound mail receiver running on port {PORT}, saving to {MAIL_DIR}", flush=True)

    with ThreadedReceiverServer(("127.0.0.1", PORT), InboundHandler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down receiver...", flush=True)

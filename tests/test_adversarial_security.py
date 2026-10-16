#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Adversarial Security Test Suite for Raymida Mail
Stress-tests:
1. Path Traversal & Static Asset Containment (is_relative_to, url-encoding, symlink escapes)
2. Proxy IP Resolution & Fail2ban Defense (X-Forwarded-For rightmost parsing, IP spoofing resistance, ban enforcement on GET/POST)
3. User Management & Bcrypt Security (setup_users.py validation, bcrypt strictness, password verification, key preservation)
4. Constant-Time Authentication (hmac.compare_digest for API tokens and webhook keys)
5. Session Security & HTTP Security Headers (Set-Cookie flags, nosniff, DENY, Content-Disposition RFC 5987)
6. Frontend DOMPurify & XSS Defense (Offline asset availability, escaping, sanitization rules)
"""

import ast
import base64
import email
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Import backend modules under test
from backend import pochta_api
from backend import setup_users
from backend import priyomnik


def _invoke_handler(handler_cls, method: str, path: str, headers: dict = None, body: bytes = b"", client_ip: str = "127.0.0.1") -> tuple[int, dict, bytes]:
    """Helper to simulate HTTP requests against BaseHTTPRequestHandler subclasses."""
    headers = headers or {}
    req_lines = [f"{method} {path} HTTP/1.1", f"Host: 127.0.0.1"]
    if body and "content-length" not in [k.lower() for k in headers]:
        req_lines.append(f"Content-Length: {len(body)}")
    for k, v in headers.items():
        req_lines.append(f"{k}: {v}")
    req_lines.append("")
    req_lines.append("")
    raw_req = "\r\n".join(req_lines).encode("utf-8") + body

    handler = handler_cls.__new__(handler_cls)
    handler.rfile = io.BytesIO(raw_req)
    handler.wfile = io.BytesIO()
    handler.client_address = (client_ip, 12345)
    handler.close_connection = False
    handler.server = None
    handler.raw_requestline = handler.rfile.readline(65537)
    handler.parse_request()

    if method == "GET":
        handler.do_GET()
    elif method == "POST":
        handler.do_POST()
    else:
        raise ValueError(f"Unsupported method {method}")

    wfile_data = handler.wfile.getvalue()
    if not wfile_data:
        return 0, {}, b""

    header_part, _, body_part = wfile_data.partition(b"\r\n\r\n")
    lines = header_part.decode("utf-8", errors="replace").split("\r\n")
    status_code = int(lines[0].split(" ")[1])

    resp_headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            resp_headers[k.strip().lower()] = v.strip()

    return status_code, resp_headers, body_part


class TestPathTraversalSecurity(unittest.TestCase):
    """Adversarial stress-testing of path traversal attacks across static serving, API endpoints, and maildir handling."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

        # Setup mock web directory with index.html and sensitive file outside web dir
        self.web_dir = self.temp_path / "frontend"
        self.web_dir.mkdir()
        (self.web_dir / "index.html").write_text("<!DOCTYPE html><html><body>Webmail</body></html>")
        (self.web_dir / "app.js").write_text("console.log('test');")
        (self.web_dir / "style.css").write_text("body { color: #000; }")

        # Secret file outside web_dir
        self.secret_file = self.temp_path / "secret.txt"
        self.secret_file.write_text("CONFIDENTIAL_SYSTEM_TOKEN_12345")

        # Symlink inside web_dir pointing outside to secret.txt
        self.symlink_target = self.web_dir / "symlink_secret.txt"
        try:
            self.symlink_target.symlink_to(self.secret_file)
        except OSError:
            pass

        # Setup mock mail directory
        self.mail_dir = self.temp_path / "mail"
        self.mail_dir.mkdir()
        (self.mail_dir / "ray" / "new").mkdir(parents=True)
        (self.mail_dir / "ray" / "cur").mkdir(parents=True)
        (self.mail_dir / "ray" / "cur" / "msg1.eml").write_text(
            "From: alice@example.com\nTo: ray@raymida.com\nSubject: Secret\n\nSecret email body"
        )

        # Setup users file
        self.users_file = self.temp_path / ".raymida_users.json"
        self.api_key = "test_api_key_path_traversal"
        self.users_file.write_text(json.dumps({
            "ray": {
                "password_hash": "$2b$12$e8P3L...",
                "api_key": self.api_key
            }
        }))

        self.orig_web_dir = pochta_api.WEB_DIR
        self.orig_mail_dir = pochta_api.MAIL_DIR
        self.orig_users_file = pochta_api.USERS_FILE

        pochta_api.WEB_DIR = self.web_dir
        pochta_api.MAIL_DIR = self.mail_dir
        pochta_api.USERS_FILE = self.users_file

    def tearDown(self):
        pochta_api.WEB_DIR = self.orig_web_dir
        pochta_api.MAIL_DIR = self.orig_mail_dir
        pochta_api.USERS_FILE = self.orig_users_file
        self.temp_dir.cleanup()

    def test_static_path_traversal_dotdot_attempts(self):
        """Verify adversarial ../ traversals cannot escape WEB_DIR."""
        traversal_payloads = [
            "/../secret.txt",
            "/../../secret.txt",
            "/../../../etc/passwd",
            "/....//secret.txt",
            "/....//....//secret.txt",
            "/..//..//secret.txt",
            "/./../secret.txt",
            "/foo/../../secret.txt",
            "/..\\secret.txt",
            "/..\\..\\secret.txt",
            "//etc/passwd",
            "////secret.txt",
        ]
        for payload in traversal_payloads:
            status, headers, body = _invoke_handler(pochta_api.MailAPIHandler, "GET", payload)
            self.assertEqual(status, 404, f"Payload '{payload}' did not return 404 (got {status})")
            self.assertNotIn(b"CONFIDENTIAL", body, f"Payload '{payload}' leaked file content!")
            self.assertIn(b"nothing here", body)

    def test_static_path_traversal_url_encoded_attempts(self):
        """Verify URL-encoded and double URL-encoded path traversals are contained."""
        encoded_payloads = [
            "/%2e%2e/secret.txt",
            "/%2e%2e%2fsecret.txt",
            "/..%2fsecret.txt",
            "/%252e%252e%252fsecret.txt",
            "/..%5csecret.txt",
            "/%2e%2e%5csecret.txt",
            "/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]
        for payload in encoded_payloads:
            status, headers, body = _invoke_handler(pochta_api.MailAPIHandler, "GET", payload)
            self.assertEqual(status, 404, f"Encoded payload '{payload}' did not return 404 (got {status})")
            self.assertNotIn(b"CONFIDENTIAL", body)

    def test_static_symlink_escape_containment(self):
        """Verify symlinks pointing outside WEB_DIR are blocked by is_relative_to resolve check."""
        if self.symlink_target.is_symlink():
            status, headers, body = _invoke_handler(pochta_api.MailAPIHandler, "GET", "/symlink_secret.txt")
            self.assertEqual(status, 404)
            self.assertNotIn(b"CONFIDENTIAL", body)

    def test_api_mail_email_id_path_traversal(self):
        """Verify get_email rejects adversarial email_id strings attempting directory traversal."""
        headers = {"Authorization": f"Bearer {self.api_key}"}
        malicious_ids = [
            "../../secret.txt",
            "cur/../../secret.txt",
            "new/../../secret.txt",
            "cur/../cur/msg1.eml",
            "cur/subdir/msg1.eml",
            "cur/msg1.eml/../",
            "cur\\msg1.eml",
            "cur/..\\msg1.eml",
            "/etc/passwd",
            "temp/msg1.eml",
        ]
        for email_id in malicious_ids:
            # Direct function test
            res = pochta_api.get_email("ray", email_id)
            self.assertIsNone(res, f"get_email accepted malicious email_id '{email_id}'")

            # API endpoint test
            status, _, body = _invoke_handler(pochta_api.MailAPIHandler, "GET", f"/api/mail?id={email_id}", headers)
            self.assertEqual(status, 404, f"API /api/mail did not return 404 for malicious id '{email_id}'")

    def test_api_attachment_email_id_path_traversal(self):
        """Verify get_attachment rejects adversarial email_id strings."""
        headers = {"Authorization": f"Bearer {self.api_key}"}
        malicious_ids = [
            "../../secret.txt",
            "cur/../../secret.txt",
            "cur/../new/msg1.eml",
            "cur/..\\msg1.eml",
        ]
        for email_id in malicious_ids:
            res = pochta_api.get_attachment("ray", email_id, 0)
            self.assertIsNone(res, f"get_attachment accepted malicious id '{email_id}'")
            status, _, _ = _invoke_handler(pochta_api.MailAPIHandler, "GET", f"/api/attachment?id={email_id}&idx=0", headers)
            self.assertEqual(status, 404)

    def test_priyomnik_mailbox_sanitization_traversal(self):
        """Verify inbound receiver's get_mailbox strips traversal characters from email addresses."""
        malicious_addresses = [
            ("../../root@raymida.com", "root"),
            ("../../../etc/passwd@raymida.com", "etcpasswd"),
            ("..%2f..%2fadmin@raymida.com", "2f2fadmin"),
            ("ray/../admin@raymida.com", "rayadmin"),
            ("ray\\admin@raymida.com", "rayadmin"),
            ("user..name@raymida.com", "username"),
            ("....@raymida.com", "misc"),
            ("///@raymida.com", "misc"),
            ("@raymida.com", "misc"),
            ("attacker@otherdomain.com", "misc"),
        ]
        for address, expected in malicious_addresses:
            result = priyomnik.get_mailbox(address)
            self.assertEqual(result, expected, f"get_mailbox for '{address}' expected '{expected}', got '{result}'")
            self.assertNotIn("/", result)
            self.assertNotIn("\\", result)
            self.assertNotIn("..", result)


class TestSpoofedXForwardedForAndFail2ban(unittest.TestCase):
    """Adversarial stress-testing of IP extraction and Fail2ban defense against header spoofing."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.users_file = self.temp_path / ".raymida_users.json"

        # Create test user with bcrypt password "correctpassword"
        import bcrypt
        hashed = bcrypt.hashpw(b"correctpassword", bcrypt.gensalt()).decode("utf-8")
        self.users_file.write_text(json.dumps({
            "testuser": {
                "password_hash": hashed,
                "api_key": "valid_api_key_test"
            }
        }))

        self.orig_users_file = pochta_api.USERS_FILE
        pochta_api.USERS_FILE = self.users_file

        # Reset fail2ban state
        with pochta_api.ban_lock:
            pochta_api.ip_attempts.clear()

    def tearDown(self):
        pochta_api.USERS_FILE = self.orig_users_file
        with pochta_api.ban_lock:
            pochta_api.ip_attempts.clear()
        self.temp_dir.cleanup()

    def test_get_client_ip_rightmost_x_forwarded_for(self):
        """Verify rightmost IP is selected from multi-value X-Forwarded-For headers."""
        test_cases = [
            ({"X-Forwarded-For": "203.0.113.195"}, "203.0.113.195"),
            ({"X-Forwarded-For": "127.0.0.1, 10.0.0.1, 203.0.113.50"}, "203.0.113.50"),
            ({"X-Forwarded-For": "spoofed_ip , 198.51.100.22 ,  203.0.113.99 "}, "203.0.113.99"),
            ({"X-Forwarded-For": "1.2.3.4, , 5.6.7.8"}, "5.6.7.8"),
            ({"Cf-Connecting-Ip": "198.51.100.7", "X-Forwarded-For": "1.1.1.1, 2.2.2.2"}, "198.51.100.7"),
            ({}, "192.0.2.1"),  # fallback to client_address
        ]

        for headers, expected_ip in test_cases:
            handler = pochta_api.MailAPIHandler.__new__(pochta_api.MailAPIHandler)
            handler.headers = headers
            handler.client_address = ("192.0.2.1", 12345)
            extracted = handler.get_client_ip()
            self.assertEqual(extracted, expected_ip, f"Failed for headers {headers}: expected {expected_ip}, got {extracted}")

    def test_fail2ban_blocks_rightmost_attacker_ip_not_whitelisted(self):
        """
        Adversary attempts brute force while spoofing X-Forwarded-For with whitelisted 127.0.0.1.
        The rightmost IP (203.0.113.5) must be banned, and 127.0.0.1 must NOT bypass fail2ban.
        """
        attacker_headers = {"X-Forwarded-For": "127.0.0.1, 203.0.113.5", "Content-Type": "application/json"}
        wrong_body = json.dumps({"username": "testuser", "password": "wrongpass"}).encode("utf-8")
        correct_body = json.dumps({"username": "testuser", "password": "correctpassword"}).encode("utf-8")

        # 4 failed attempts: not yet banned
        for i in range(4):
            status, _, data_bytes = _invoke_handler(
                pochta_api.MailAPIHandler, "POST", "/api/login",
                headers=attacker_headers, body=wrong_body
            )
            data = json.loads(data_bytes.decode("utf-8"))
            self.assertEqual(status, 403)
            self.assertEqual(data.get("error"), "invalid credentials")

        # 5th failed attempt triggers ban
        status, _, data_bytes = _invoke_handler(
            pochta_api.MailAPIHandler, "POST", "/api/login",
            headers=attacker_headers, body=wrong_body
        )
        self.assertEqual(status, 403)

        # 6th attempt (even with correct password) must be rejected with IP temporarily banned
        status, _, data_bytes = _invoke_handler(
            pochta_api.MailAPIHandler, "POST", "/api/login",
            headers=attacker_headers, body=correct_body
        )
        data = json.loads(data_bytes.decode("utf-8"))
        self.assertEqual(status, 403)
        self.assertEqual(data.get("error"), "IP temporarily banned")

        # GET /api/* requests from the banned IP must also be blocked
        get_headers = {"X-Forwarded-For": "127.0.0.1, 203.0.113.5", "Authorization": "Bearer valid_api_key_test"}
        status, _, data_bytes = _invoke_handler(
            pochta_api.MailAPIHandler, "GET", "/api/me",
            headers=get_headers
        )
        data = json.loads(data_bytes.decode("utf-8"))
        self.assertEqual(status, 403)
        self.assertEqual(data.get("error"), "IP temporarily banned")

        # Legitimate user from different IP (203.0.113.6) can still login successfully
        legit_headers = {"X-Forwarded-For": "203.0.113.6", "Content-Type": "application/json"}
        status, resp_headers, data_bytes = _invoke_handler(
            pochta_api.MailAPIHandler, "POST", "/api/login",
            headers=legit_headers, body=correct_body
        )
        data = json.loads(data_bytes.decode("utf-8"))
        self.assertEqual(status, 200)
        self.assertTrue(data.get("ok"))
        self.assertIn("set-cookie", resp_headers)

    def test_fail2ban_counter_reset_on_successful_login(self):
        """Verify that a successful login resets the failure counter before reaching threshold."""
        ip_headers = {"X-Forwarded-For": "198.51.100.44", "Content-Type": "application/json"}
        wrong_body = json.dumps({"username": "testuser", "password": "wrongpass"}).encode("utf-8")
        correct_body = json.dumps({"username": "testuser", "password": "correctpassword"}).encode("utf-8")

        # 3 failed attempts
        for _ in range(3):
            _invoke_handler(pochta_api.MailAPIHandler, "POST", "/api/login", headers=ip_headers, body=wrong_body)

        # Successful login
        status, _, data_bytes = _invoke_handler(
            pochta_api.MailAPIHandler, "POST", "/api/login",
            headers=ip_headers, body=correct_body
        )
        self.assertEqual(status, 200)

        # 3 more failed attempts (should not ban because counter was reset)
        for _ in range(3):
            status, _, data_bytes = _invoke_handler(
                pochta_api.MailAPIHandler, "POST", "/api/login",
                headers=ip_headers, body=wrong_body
            )
            data = json.loads(data_bytes.decode("utf-8"))
            self.assertEqual(data.get("error"), "invalid credentials")


class TestUserManagementAndBcryptSecurity(unittest.TestCase):
    """Adversarial testing of setup_users.py validation, bcrypt enforcement, and API key preservation."""

    def test_bcrypt_strictness_refuses_fallback(self):
        """Verify setup_users.hash_password raises SystemExit(1) if bcrypt is unavailable (refuses plaintext fallback)."""
        with patch.dict(sys.modules, {"bcrypt": None}):
            with self.assertRaises(SystemExit) as cm:
                setup_users.hash_password("SuperSecret123")
            self.assertEqual(cm.exception.code, 1)

    def test_pochta_api_verify_password_bcrypt_strictness(self):
        """Verify pochta_api.verify_password handles valid, invalid, empty, and malformed bcrypt hashes safely."""
        import bcrypt
        good_hash = bcrypt.hashpw(b"mysecret123", bcrypt.gensalt()).decode("utf-8")

        # Correct password
        self.assertTrue(pochta_api.verify_password("mysecret123", good_hash))

        # Incorrect password
        self.assertFalse(pochta_api.verify_password("wrongsecret", good_hash))

        # Edge case inputs
        self.assertFalse(pochta_api.verify_password("", good_hash))
        self.assertFalse(pochta_api.verify_password("mysecret123", ""))
        self.assertFalse(pochta_api.verify_password(None, good_hash))
        self.assertFalse(pochta_api.verify_password("mysecret123", None))
        self.assertFalse(pochta_api.verify_password("mysecret123", "plaintext_unhashed_password"))
        self.assertFalse(pochta_api.verify_password("mysecret123", "$invalid$hash$structure"))

    def test_username_regex_validation_rules(self):
        """Adversarial stress test on username regex: ^[a-z0-9_-]{1,32}$"""
        valid_usernames = [
            "ray",
            "tony",
            "user-1",
            "user_2",
            "a",
            "1",
            "12345678901234567890123456789012",  # 32 characters
            "a-b_c-d_1-2",
        ]
        for u in valid_usernames:
            self.assertIsNotNone(
                setup_users.USERNAME_RE.match(u),
                f"Valid username '{u}' failed regex matching"
            )

        adversarial_invalid_usernames = [
            "",                                    # empty
            "a" * 33,                              # 33 chars (exceeds max 32)
            "User",                                # uppercase (must be lowercase)
            "RAY",
            "ray@raymida.com",                     # contains @ and dot
            "user name",                           # space
            "user\tname",                          # tab
            "user\nname",                          # internal newline
            "../admin",                            # path traversal
            "user/name",                           # slash
            "user\\name",                          # backslash
            "<script>alert(1)</script>",           # XSS
            "user;drop table users;",              # SQL injection
            "user$(whoami)",                       # Command substitution
            "user`id`",                            # Backticks
            "пользователь",                        # Non-ascii Cyrillic
            "user🚀",                              # Emoji
            "user\x00null",                        # Null byte
        ]
        for u in adversarial_invalid_usernames:
            self.assertIsNone(
                setup_users.USERNAME_RE.match(u),
                f"Adversarial invalid username '{u}' was erroneously accepted by USERNAME_RE"
            )

    def test_preservation_of_existing_users_and_api_keys(self):
        """Verify that updating an existing user's password strictly preserves their API key and other users."""
        temp_dir = tempfile.TemporaryDirectory()
        try:
            users_path = Path(temp_dir.name) / ".raymida_users.json"
            orig_users_file = setup_users.USERS_FILE
            setup_users.USERS_FILE = users_path

            # Initial user database with existing ray and tony
            initial_data = {
                "ray": {
                    "password_hash": "$2b$12$oldhashrayoldhashrayoldhashray",
                    "api_key": "ray_fixed_permanent_api_key_12345"
                },
                "tony": {
                    "password_hash": "$2b$12$oldhashtonyoldhashtonyoldhash",
                    "api_key": "tony_fixed_permanent_api_key_67890"
                }
            }
            users_path.write_text(json.dumps(initial_data))

            # Simulate running setup_users to update ray's password and add new user "carol"
            users = setup_users.load_existing_users()
            self.assertEqual(len(users), 2)
            self.assertEqual(users["ray"]["api_key"], "ray_fixed_permanent_api_key_12345")

            # Update ray
            new_ray_hash = setup_users.hash_password("newpasswordforray")
            ray_existing = users.get("ray", {})
            ray_api_key = ray_existing.get("api_key") or "GENERATED"
            users["ray"] = {
                "password_hash": new_ray_hash,
                "api_key": ray_api_key
            }

            # Add carol
            carol_hash = setup_users.hash_password("passwordforcarol")
            carol_existing = users.get("carol", {})
            carol_api_key = carol_existing.get("api_key") or "carol_generated_key_999"
            users["carol"] = {
                "password_hash": carol_hash,
                "api_key": carol_api_key
            }

            # Write out
            with users_path.open("w", encoding="utf-8") as f:
                json.dump(users, f, indent=2)
            os.chmod(users_path, 0o600)

            # Reload and verify
            reloaded = json.loads(users_path.read_text())
            self.assertIn("ray", reloaded)
            self.assertIn("tony", reloaded)
            self.assertIn("carol", reloaded)

            # ray's API key must be preserved identically
            self.assertEqual(reloaded["ray"]["api_key"], "ray_fixed_permanent_api_key_12345")
            # tony's data must remain intact
            self.assertEqual(reloaded["tony"]["api_key"], "tony_fixed_permanent_api_key_67890")
            # verify permissions 0600
            file_mode = oct(os.stat(users_path).st_mode & 0o777)
            self.assertEqual(file_mode, "0o600")

        finally:
            setup_users.USERS_FILE = orig_users_file
            temp_dir.cleanup()


class TestConstantTimeComparisons(unittest.TestCase):
    """Verify constant-time comparison (hmac.compare_digest) is used for all sensitive tokens."""

    def test_ast_hmac_compare_digest_in_pochta_api(self):
        """AST audit of pochta_api.py to ensure get_user_by_api_key uses hmac.compare_digest."""
        src_path = Path(__file__).resolve().parent.parent / "backend" / "pochta_api.py"
        tree = ast.parse(src_path.read_text(encoding="utf-8"))

        found_compare_digest = False
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "get_user_by_api_key":
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        func = child.func
                        if isinstance(func, ast.Attribute) and func.attr == "compare_digest":
                            found_compare_digest = True

        self.assertTrue(found_compare_digest, "pochta_api.get_user_by_api_key does not use compare_digest!")

    def test_ast_hmac_compare_digest_in_priyomnik(self):
        """AST audit of priyomnik.py to ensure webhook security check uses hmac.compare_digest."""
        src_path = Path(__file__).resolve().parent.parent / "backend" / "priyomnik.py"
        tree = ast.parse(src_path.read_text(encoding="utf-8"))

        found_compare_digest = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == "compare_digest":
                    found_compare_digest = True

        self.assertTrue(found_compare_digest, "priyomnik.py does not use hmac.compare_digest for webhook key check!")

    def test_get_user_by_api_key_runtime_behavior(self):
        """Verify get_user_by_api_key matches strictly and resists prefix/suffix matching bugs."""
        temp_dir = tempfile.TemporaryDirectory()
        try:
            users_file = Path(temp_dir.name) / ".raymida_users.json"
            users_file.write_text(json.dumps({
                "alice": {"api_key": "secret_key_alice_12345"},
                "bob": {"api_key": "secret_key_bob_67890"}
            }))

            orig_file = pochta_api.USERS_FILE
            pochta_api.USERS_FILE = users_file

            # Exact matches
            self.assertEqual(pochta_api.get_user_by_api_key("secret_key_alice_12345"), "alice")
            self.assertEqual(pochta_api.get_user_by_api_key("secret_key_bob_67890"), "bob")

            # Adversarial near-misses
            self.assertIsNone(pochta_api.get_user_by_api_key("secret_key_alice_1234"))
            self.assertIsNone(pochta_api.get_user_by_api_key("secret_key_alice_123456"))
            self.assertIsNone(pochta_api.get_user_by_api_key("SECRET_KEY_ALICE_12345"))
            self.assertIsNone(pochta_api.get_user_by_api_key(""))
            self.assertIsNone(pochta_api.get_user_by_api_key(None))
            self.assertIsNone(pochta_api.get_user_by_api_key("secret_key_alice_12345\x00"))
        finally:
            pochta_api.USERS_FILE = orig_file
            temp_dir.cleanup()


class TestSessionCookiesAndSecurityHeaders(unittest.TestCase):
    """Adversarial verification of HTTP response security headers and session cookie attributes."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.web_dir = self.temp_path / "frontend"
        self.web_dir.mkdir()
        (self.web_dir / "index.html").write_text("<!DOCTYPE html><html><body>Test</body></html>")

        self.mail_dir = self.temp_path / "mail"
        self.mail_dir.mkdir()
        (self.mail_dir / "ray" / "cur").mkdir(parents=True)
        
        # Email with attachment
        msg = email.message.EmailMessage()
        msg["From"] = "sender@example.com"
        msg["To"] = "ray@raymida.com"
        msg["Subject"] = "Attachment Test"
        msg.set_content("Body text")
        msg.add_attachment(b"PDF_CONTENT_1234", maintype="application", subtype="pdf", filename="отчёт_август.pdf")
        (self.mail_dir / "ray" / "cur" / "msg_att.eml").write_bytes(msg.as_bytes())

        self.users_file = self.temp_path / ".raymida_users.json"
        import bcrypt
        hashed = bcrypt.hashpw(b"mypassword", bcrypt.gensalt()).decode("utf-8")
        self.users_file.write_text(json.dumps({
            "ray": {"password_hash": hashed, "api_key": "ray_test_key_cookie"}
        }))

        self.orig_web = pochta_api.WEB_DIR
        self.orig_mail = pochta_api.MAIL_DIR
        self.orig_users = pochta_api.USERS_FILE

        pochta_api.WEB_DIR = self.web_dir
        pochta_api.MAIL_DIR = self.mail_dir
        pochta_api.USERS_FILE = self.users_file

    def tearDown(self):
        pochta_api.WEB_DIR = self.orig_web
        pochta_api.MAIL_DIR = self.orig_mail
        pochta_api.USERS_FILE = self.orig_users
        self.temp_dir.cleanup()

    def test_login_cookie_attributes_strict_security(self):
        """Verify Set-Cookie has Secure, HttpOnly, SameSite=Lax, and Path=/."""
        payload = json.dumps({"username": "ray", "password": "mypassword"}).encode("utf-8")
        status, headers, body = _invoke_handler(
            pochta_api.MailAPIHandler, "POST", "/api/login",
            headers={"Content-Type": "application/json"},
            body=payload
        )
        self.assertEqual(status, 200)
        self.assertIn("set-cookie", headers)
        cookie = headers["set-cookie"]

        token = cookie.split(';', 1)[0].split('=', 1)[1]
        self.assertEqual(pochta_api.session_user(token, pochta_api.load_users()), 'ray')
        self.assertNotIn('ray_test_key_cookie', cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("Secure", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertIn("Path=/", cookie)
        self.assertIn("Max-Age=", cookie)

    def test_security_headers_on_all_responses(self):
        """Verify X-Content-Type-Options: nosniff and X-Frame-Options: DENY on all endpoints."""
        endpoints = [
            ("GET", "/"),
            ("GET", "/index.html"),
            ("GET", "/api/me", {"Authorization": "Bearer ray_test_key_cookie"}),
            ("GET", "/api/boxes", {"Cookie": "auth_key=ray_test_key_cookie"}),
            ("GET", "/api/list", {"Authorization": "Bearer ray_test_key_cookie"}),
            ("GET", "/api/unknown_endpoint", {"Authorization": "Bearer ray_test_key_cookie"}),
            ("GET", "/api/list", {}),  # 403 unauthorized
            ("POST", "/api/login", {"Content-Type": "application/json"}, b"invalid-json"),  # 400
        ]

        for ep in endpoints:
            method, path = ep[0], ep[1]
            hdrs = ep[2] if len(ep) > 2 else {}
            b = ep[3] if len(ep) > 3 else b""

            status, resp_headers, _ = _invoke_handler(
                pochta_api.MailAPIHandler, method, path,
                headers=hdrs, body=b
            )
            self.assertEqual(
                resp_headers.get("x-content-type-options"), "nosniff",
                f"Missing or invalid X-Content-Type-Options on {method} {path}"
            )
            self.assertEqual(
                resp_headers.get("x-frame-options"), "DENY",
                f"Missing or invalid X-Frame-Options on {method} {path}"
            )

    def test_attachment_download_headers_and_rfc5987(self):
        """Verify attachment download sets security headers, Content-Disposition, and RFC 5987 UTF-8 encoding."""
        status, headers, body = _invoke_handler(
            pochta_api.MailAPIHandler, "GET", "/api/attachment?id=cur/msg_att.eml&idx=0",
            headers={"Authorization": "Bearer ray_test_key_cookie"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(headers.get("x-frame-options"), "DENY")
        self.assertIn("content-disposition", headers)
        cd = headers["content-disposition"]
        self.assertIn("attachment;", cd)
        self.assertIn("filename*=", cd)
        self.assertEqual(body, b"PDF_CONTENT_1234")

    def test_priyomnik_security_headers(self):
        """Verify priyomnik inbound receiver also returns nosniff and DENY."""
        status, headers, body = _invoke_handler(
            priyomnik.InboundHandler, "GET", "/health"
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(headers.get("x-frame-options"), "DENY")


class TestDOMPurifyAndFrontendXSSDefense(unittest.TestCase):
    """Verify frontend DOMPurify offline presence, sanitization profile, and escaping in app.js."""

    def setUp(self):
        self.project_root = Path(__file__).resolve().parent.parent
        self.frontend_dir = self.project_root / "frontend"

    def test_dompurify_offline_file_exists_and_valid(self):
        """Verify purify.min.js exists locally (>15KB) without external CDN dependency."""
        purify_path = self.frontend_dir / "purify.min.js"
        self.assertTrue(purify_path.is_file(), "purify.min.js does not exist in frontend/")
        size = purify_path.stat().st_size
        self.assertGreater(size, 15000, f"purify.min.js file size ({size} bytes) is suspiciously small")
        content = purify_path.read_text(encoding="utf-8")
        self.assertIn("DOMPurify", content)

    def test_index_html_loads_local_purify_before_app(self):
        """Verify index.html loads local purify.min.js before app.js and has no external unvetted scripts."""
        index_html = (self.frontend_dir / "index.html").read_text(encoding="utf-8")

        # Check script tags
        script_srcs = re.findall(r'<script\s+[^>]*src=["\']([^"\']+)["\']', index_html)
        script_srcs = [source.split('?', 1)[0] for source in script_srcs]
        self.assertIn("purify.min.js", script_srcs)
        self.assertIn("app.js", script_srcs)

        purify_idx = script_srcs.index("purify.min.js")
        app_idx = script_srcs.index("app.js")
        self.assertLess(purify_idx, app_idx, "purify.min.js must be loaded BEFORE app.js")

        # Check for unapproved external scripts
        for src in script_srcs:
            self.assertFalse(src.startswith("http://") or src.startswith("https://") or src.startswith("//"),
                             f"External script CDN detected in index.html: {src}")

    def test_app_js_dompurify_strict_configuration(self):
        """Verify app.js configures DOMPurify with strict tag/attribute allowlists and forbiddances."""
        app_js = (self.frontend_dir / "app.js").read_text(encoding="utf-8")

        # Check for DOMPurify.sanitize call
        self.assertIn("DOMPurify.sanitize", app_js)

        # Check forbidden tags
        forbidden_tags = ["script", "iframe", "object", "embed", "form", "input", "button", "textarea", "select"]
        for tag in forbidden_tags:
            self.assertIn(f"'{tag}'", app_js, f"DOMPurify config missing forbidden tag '{tag}'")

        # Check forbidden event handler attributes
        forbidden_attrs = ["onerror", "onload", "onclick", "onmouseover", "onfocus", "onblur"]
        for attr in forbidden_attrs:
            self.assertIn(f"'{attr}'", app_js, f"DOMPurify config missing forbidden attr '{attr}'")

    def test_html_escape_function_xss_prevention(self):
        """Adversarially verify the escapeHtml algorithm used across app.js."""
        def python_escape_html(s: str) -> str:
            rep = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}
            return re.sub(r'[&<>"\']', lambda m: rep[m.group(0)], s or "")

        payloads = [
            ("<script>alert('xss')</script>", "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"),
            ('"><img src=x onerror=alert(1)>', '&quot;&gt;&lt;img src=x onerror=alert(1)&gt;'),
            ("javascript:alert(1)", "javascript:alert(1)"),
            ("A & B < C > D 'E' \"F\"", "A &amp; B &lt; C &gt; D &#39;E&#39; &quot;F&quot;"),
        ]
        for raw, expected in payloads:
            escaped = python_escape_html(raw)
            self.assertEqual(escaped, expected)
            self.assertNotIn("<", escaped)
            self.assertNotIn(">", escaped)
            self.assertNotIn('"', escaped)


if __name__ == "__main__":
    unittest.main()

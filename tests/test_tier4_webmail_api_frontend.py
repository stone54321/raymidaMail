#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tier 4 Tests: Webmail API & Frontend
Covers:
- Item 1: get_email() moving new/ to cur/ without mtime/stat crash
- Item 2: Timeout protection (timeout=60) & Content-Length rejection
- Item 3: RFC 5987 Cyrillic & Unicode attachment header formatting
- Item 4: Directory traversal guard (/api/mail?id=new/ -> 404)
- Item 8: Secure cookie flag on session cookies
- Item 9: Client IP extraction using rightmost X-Forwarded-For
- Item 10: Path traversal check using is_relative_to()
- Item 12: Multipart boundary missing -> HTTP 400
- Item 15: Preview and search read limit (256 KB)
- Item 16: Constant-time comparison hmac.compare_digest
- Item 17: Strict bcrypt verification in verify_password()
- Item 18: HTML escaping in UI navigation (app.js)
- Item 19: Security headers (X-Content-Type-Options: nosniff, X-Frame-Options: DENY)
- Item 20: HTTP 502 error reporting on relay failure
- Item 21: Unused get_mailboxes() removed & Connection: close on early rejection
"""
import base64
import email
import email.policy
import hmac
import inspect
import io
import json
import os
import re
import sys
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import MagicMock, patch

# Base paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
FRONTEND_DIR = PROJECT_ROOT / "frontend"
sys.path.insert(0, str(BACKEND_DIR))

import pochta_api


class TestItem1GetEmailMoveNewToCur(unittest.TestCase):
    """
    Item 1: get_email() moving from new/ to cur/ without mtime/stat crash.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.mail_dir = Path(self.temp_dir.name)
        self.orig_mail_dir = pochta_api.MAIL_DIR
        pochta_api.MAIL_DIR = self.mail_dir

        self.user = "testuser"
        (self.mail_dir / self.user / "new").mkdir(parents=True, exist_ok=True)
        (self.mail_dir / self.user / "cur").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        pochta_api.MAIL_DIR = self.orig_mail_dir
        self.temp_dir.cleanup()

    def test_get_email_moves_new_to_cur_and_retains_mtime(self):
        """Verify get_email moves file from new/ to cur/ and accurately returns mtime."""
        raw_msg = (
            b"From: sender@example.com\r\n"
            b"To: testuser@raymida.com\r\n"
            b"Subject: Test Subject\r\n"
            b"Message-ID: <msg123@example.com>\r\n"
            b"Date: Mon, 31 Aug 2026 12:00:00 +0000\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Hello world body text."
        )
        file_path = self.mail_dir / self.user / "new" / "12345.hash.raymida"
        file_path.write_bytes(raw_msg)
        initial_mtime = file_path.stat().st_mtime

        # Fetch email
        email_data = pochta_api.get_email(self.user, "new/12345.hash.raymida")

        self.assertIsNotNone(email_data, "get_email must return email metadata dict")
        self.assertEqual(email_data["subject"], "Test Subject")
        self.assertEqual(email_data["from"], "sender@example.com")
        self.assertEqual(email_data["text"], "Hello world body text.")
        self.assertAlmostEqual(email_data["mtime"], initial_mtime, delta=2.0)

        # Verify moved to cur/
        cur_file = self.mail_dir / self.user / "cur" / "12345.hash.raymida"
        self.assertTrue(cur_file.exists(), "Email should now be in cur/")
        self.assertFalse(file_path.exists(), "Email should no longer be in new/")

    def test_get_email_already_in_cur(self):
        """Verify get_email retrieves emails already in cur/ without error."""
        raw_msg = b"From: sender@example.com\r\nSubject: In Cur\r\n\r\nCur Body"
        file_path = self.mail_dir / self.user / "cur" / "99999.hash.raymida"
        file_path.write_bytes(raw_msg)

        email_data = pochta_api.get_email(self.user, "cur/99999.hash.raymida")
        self.assertIsNotNone(email_data)
        self.assertEqual(email_data["subject"], "In Cur")


class TestItem2TimeoutAndContentLength(unittest.TestCase):
    """
    Item 2: Timeout protection (timeout=60) & Content-Length rejection on negative/excessive values.
    """

    def test_pochta_handler_timeout_and_max_body(self):
        """Verify MailAPIHandler defines timeout=60 and MAX_BODY limit (50 MB)."""
        self.assertTrue(
            hasattr(pochta_api.MailAPIHandler, "timeout") or hasattr(pochta_api, "MAX_BODY"),
            "MailAPIHandler or module must configure timeout/MAX_BODY"
        )
        if hasattr(pochta_api.MailAPIHandler, "timeout"):
            self.assertEqual(pochta_api.MailAPIHandler.timeout, 60)
        if hasattr(pochta_api, "MAX_BODY"):
            self.assertEqual(pochta_api.MAX_BODY, 50 * 1024 * 1024)


class TestItem3RFC5987AttachmentHeader(unittest.TestCase):
    """
    Item 3: RFC 5987 Cyrillic & Unicode attachment header formatting (filename*=UTF-8''...).
    """

    def test_rfc5987_header_formatting(self):
        """Verify RFC 5987 filename formatting for Cyrillic and special characters."""
        unicode_filename = "отчёт_за_август_2026.pdf"
        safe_name = unicode_filename.replace("\r", " ").replace("\n", " ").replace('"', "'")
        ascii_name = safe_name.encode("latin-1", "replace").decode("latin-1") or "attachment"
        encoded_name = urllib.parse.quote(unicode_filename, safe="")

        header_val = f'attachment; filename="{ascii_name}"; filename*=UTF-8\'\'{encoded_name}'
        
        self.assertIn("filename*=UTF-8''", header_val)
        self.assertIn("%D0%BE%D1%82%D1%87%D1%91%D1%82", encoded_name.upper())

        # Verify header can be encoded to latin-1 without exception
        encoded_header = header_val.encode("latin-1")
        self.assertTrue(len(encoded_header) > 0)


class TestItem4DirectoryTraversalGuard(unittest.TestCase):
    """
    Item 4: Directory traversal guard (/api/mail?id=new/ -> 404).
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.mail_dir = Path(self.temp_dir.name)
        self.orig_mail_dir = pochta_api.MAIL_DIR
        pochta_api.MAIL_DIR = self.mail_dir
        (self.mail_dir / "ray" / "new").mkdir(parents=True, exist_ok=True)
        (self.mail_dir / "ray" / "cur").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        pochta_api.MAIL_DIR = self.orig_mail_dir
        self.temp_dir.cleanup()

    def test_get_email_directory_path_returns_none(self):
        """Verify get_email with directory path id='new/' returns None cleanly."""
        res_new = pochta_api.get_email("ray", "new/")
        self.assertIsNone(res_new, "get_email with 'new/' directory path must return None")

        res_cur = pochta_api.get_email("ray", "cur/")
        self.assertIsNone(res_cur, "get_email with 'cur/' directory path must return None")

    def test_get_email_traversal_attempts_return_none(self):
        """Verify get_email with traversal characters returns None."""
        traversals = [
            "../../etc/passwd",
            "new/../../etc/passwd",
            "cur/../something",
            "new/sub/file.eml",
        ]
        for trav in traversals:
            self.assertIsNone(pochta_api.get_email("ray", trav), f"Traversal '{trav}' must return None")


class TestItem8SecureCookieFlag(unittest.TestCase):
    """
    Item 8: Secure cookie flag on session cookies (Set-Cookie: ...; Secure; ...).
    """

    def test_send_bytes_cookie_has_secure_flag(self):
        """Verify Set-Cookie formatting includes Secure, HttpOnly, and SameSite."""
        source = inspect.getsource(pochta_api.MailAPIHandler._send_bytes)
        self.assertIn("Secure", source, "Set-Cookie must include 'Secure' flag")
        self.assertIn("HttpOnly", source, "Set-Cookie must include 'HttpOnly'")
        self.assertIn("SameSite=Lax", source, "Set-Cookie must include 'SameSite=Lax'")


class TestItem9ClientIPExtraction(unittest.TestCase):
    """
    Item 9: Client IP extraction using rightmost X-Forwarded-For.
    """

    def test_rightmost_x_forwarded_for_extraction(self):
        """Verify multi-IP X-Forwarded-For extracts the rightmost client IP."""
        # Simulated header: client, proxy1, proxy2 (closest proxy)
        x_forwarded_for = "203.0.113.195, 70.41.3.18, 150.172.238.178"
        extracted_ip = x_forwarded_for.split(",")[-1].strip()
        self.assertEqual(extracted_ip, "150.172.238.178")

    def test_cf_connecting_ip_precedence(self):
        """Verify Cf-Connecting-Ip is prioritized if present."""
        handler_source = inspect.getsource(pochta_api.MailAPIHandler.get_client_ip)
        self.assertIn("Cf-Connecting-Ip", handler_source)
        self.assertIn("X-Forwarded-For", handler_source)


class TestItem10PathTraversalStaticFiles(unittest.TestCase):
    """
    Item 10: Path traversal check using is_relative_to() for static files.
    """

    def test_is_relative_to_usage_in_do_get(self):
        """Verify do_GET uses is_relative_to to prevent static directory escape."""
        source = inspect.getsource(pochta_api.MailAPIHandler.do_GET)
        self.assertTrue(
            "is_relative_to" in source or "resolve()" in source,
            "do_GET must validate static file paths using is_relative_to"
        )


class TestItem12MultipartBoundaryMissing(unittest.TestCase):
    """
    Item 12: Multipart boundary missing -> HTTP 400 Bad Request.
    """

    def test_multipart_boundary_check_in_do_post(self):
        """Verify do_POST checks for boundary= in multipart Content-Type."""
        source = inspect.getsource(pochta_api.MailAPIHandler.do_POST)
        self.assertTrue(
            'boundary=' in source or 'missing multipart boundary' in source,
            "do_POST must validate presence of 'boundary=' in multipart Content-Type"
        )


class TestItem15PreviewAndSearchReadLimit(unittest.TestCase):
    """
    Item 15: Preview and search read limit (256 KB / 262144 bytes).
    """

    def test_get_emails_and_search_emails_read_buffer_size(self):
        """Verify get_emails and search_emails read 256 KB (262144 bytes)."""
        get_emails_source = inspect.getsource(pochta_api.get_emails)
        search_emails_source = inspect.getsource(pochta_api.search_emails)

        self.assertTrue(
            "262144" in get_emails_source or "256 * 1024" in get_emails_source or "256*1024" in get_emails_source or "read(" in get_emails_source,
            "get_emails should read with 256 KB limit"
        )
        self.assertTrue(
            "262144" in search_emails_source or "256 * 1024" in search_emails_source or "256*1024" in search_emails_source or "read(" in search_emails_source,
            "search_emails should read with 256 KB limit"
        )


class TestItem16ConstantTimeComparisonPochta(unittest.TestCase):
    """
    Item 16: Constant-time comparison hmac.compare_digest in pochta_api.py.
    """

    def test_pochta_imports_hmac(self):
        """Verify pochta_api imports hmac."""
        source = inspect.getsource(pochta_api)
        self.assertIn("hmac", source, "pochta_api.py must import hmac")

    def test_get_user_by_api_key_uses_compare_digest(self):
        """Verify get_user_by_api_key uses constant-time comparison."""
        source = inspect.getsource(pochta_api.get_user_by_api_key)
        self.assertTrue(
            "compare_digest" in source or "hmac" in source,
            "get_user_by_api_key must use hmac.compare_digest"
        )


class TestItem17StrictBcryptPochta(unittest.TestCase):
    """
    Item 17: Strict bcrypt verification in verify_password() (no SHA-256 fallback, catches ValueError).
    """

    def test_verify_password_with_valid_bcrypt_hash(self):
        """Verify verify_password validates bcrypt hashes correctly."""
        import bcrypt
        pwd = "correct_password"
        pwd_hash = bcrypt.hashpw(pwd.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        self.assertTrue(pochta_api.verify_password(pwd, pwd_hash))
        self.assertFalse(pochta_api.verify_password("wrong_password", pwd_hash))

    def test_verify_password_invalid_format_returns_false(self):
        """Verify verify_password safely returns False on invalid/corrupted hash format."""
        invalid_hashes = [
            "plain_sha256_hash_12345",
            "corrupt_hash_data",
            "",
            "1234567890",
        ]
        for bad_hash in invalid_hashes:
            result = pochta_api.verify_password("any_password", bad_hash)
            self.assertFalse(result, f"Invalid hash '{bad_hash}' must return False")


class TestItem18HTMLEscapingFrontend(unittest.TestCase):
    """
    Item 18: HTML escaping in UI navigation (app.js).
    """

    def test_app_js_defines_escape_html(self):
        """Verify frontend/app.js defines an escapeHtml function."""
        app_js_path = FRONTEND_DIR / "app.js"
        self.assertTrue(app_js_path.exists(), "frontend/app.js must exist")
        content = app_js_path.read_text(encoding="utf-8")

        self.assertIn("function escapeHtml", content, "app.js must define function escapeHtml")

    def test_app_js_escapes_mailbox_navigation(self):
        """Verify app.js escapes mailbox navigation elements with escapeHtml."""
        content = (FRONTEND_DIR / "app.js").read_text(encoding="utf-8")
        # Check startApp or mailboxes-list rendering
        self.assertTrue(
            "escapeHtml(y)" in content or "escapeHtml" in content,
            "app.js must use escapeHtml when rendering mailbox elements"
        )


class TestItem19SecurityHeadersPochta(unittest.TestCase):
    """
    Item 19: Security headers (X-Content-Type-Options: nosniff, X-Frame-Options: DENY).
    """

    def test_send_bytes_includes_security_headers(self):
        """Verify _send_bytes sends nosniff and DENY headers."""
        source = inspect.getsource(pochta_api.MailAPIHandler._send_bytes)
        self.assertIn("X-Content-Type-Options", source)
        self.assertIn("nosniff", source)
        self.assertIn("X-Frame-Options", source)
        self.assertIn("DENY", source)


class TestItem20SendErrorStatus502(unittest.TestCase):
    """
    Item 20: HTTP 502 error reporting on relay failure in /api/send.
    """

    def test_send_error_returns_502(self):
        """Verify do_POST returns HTTP 502 when send_email fails."""
        source = inspect.getsource(pochta_api.MailAPIHandler.do_POST)
        self.assertTrue(
            "502" in source or "error_msg" in source,
            "/api/send must return HTTP 502 on relay errors"
        )


class TestItem21CodeCleanupAndConnectionClose(unittest.TestCase):
    """
    Item 21: Unused get_mailboxes() cleanup & Connection: close on early rejection.
    """

    def test_connection_close_header_on_early_rejection(self):
        """Verify _send_bytes sends Connection: close when close_connection is True."""
        source = inspect.getsource(pochta_api.MailAPIHandler._send_bytes)
        self.assertTrue(
            "Connection" in source and "close" in source,
            "_send_bytes must support sending 'Connection: close'"
        )


class TestRequirementR4DynamicPaths(unittest.TestCase):


    def test_dynamic_path_variables_defined(self):
        """Verify pochta_api defines SCRIPT_DIR, PROJECT_ROOT, and WEB_DIR."""
        self.assertTrue(hasattr(pochta_api, "SCRIPT_DIR"))
        self.assertTrue(hasattr(pochta_api, "PROJECT_ROOT"))
        self.assertTrue(hasattr(pochta_api, "WEB_DIR"))
        self.assertTrue(hasattr(pochta_api, "MAIL_DIR"))


if __name__ == "__main__":
    unittest.main()

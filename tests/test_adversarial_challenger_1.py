#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Adversarial Stress Test Suite — Challenger 1 (Backend & Network Services)
Empirical verification of pochta_api.py, priyomnik.py, and r2_sync.py against
malicious, edge-case, high-concurrency, and malformed inputs.
"""
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import email
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
from unittest.mock import patch, MagicMock

# Project setup
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(BACKEND_DIR))

import pochta_api
import priyomnik
import r2_sync


class TestAdversarialContentLengthAndOversize(unittest.TestCase):
    """
    1. Malformed/negative Content-Length headers and oversize payloads (>50MB).
    Verifies robust validation, Connection: close, and HTTP 400 / 413 responses.
    """

    @classmethod
    def setUpClass(cls):
        cls.test_dir = Path(tempfile.mkdtemp())
        cls.mail_dir = cls.test_dir / "mail"
        cls.web_dir = cls.test_dir / "frontend"
        cls.users_file = cls.test_dir / ".raymida_users.json"

        cls.mail_dir.mkdir(parents=True, exist_ok=True)
        cls.web_dir.mkdir(parents=True, exist_ok=True)
        (cls.web_dir / "index.html").write_text("<h1>Webmail</h1>")

        pochta_api.MAIL_DIR = cls.mail_dir
        pochta_api.WEB_DIR = cls.web_dir
        pochta_api.USERS_FILE = cls.users_file

        users = {"tony": {"api_key": "sec_key_123", "password_hash": "$2b$12$dummy"}}
        cls.users_file.write_text(json.dumps(users))

        # Start pochta server
        cls.pochta_server = pochta_api.ThreadedMailServer(("127.0.0.1", 0), pochta_api.MailAPIHandler)
        cls.pochta_port = cls.pochta_server.server_address[1]
        cls.pochta_thread = threading.Thread(target=cls.pochta_server.serve_forever, daemon=True)
        cls.pochta_thread.start()

        # Start priyomnik server
        priyomnik.MAIL_DIR = cls.mail_dir
        priyomnik.INBOUND_KEY = "test_webhook_key_abc"
        cls.priyomnik_server = priyomnik.ThreadedReceiverServer(("127.0.0.1", 0), priyomnik.InboundHandler)
        cls.priyomnik_port = cls.priyomnik_server.server_address[1]
        cls.priyomnik_thread = threading.Thread(target=cls.priyomnik_server.serve_forever, daemon=True)
        cls.priyomnik_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.pochta_server.shutdown()
        cls.pochta_server.server_close()
        cls.priyomnik_server.shutdown()
        cls.priyomnik_server.server_close()
        shutil.rmtree(cls.test_dir, ignore_errors=True)

    def _send_raw_http(self, port: int, request_bytes: bytes) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(("127.0.0.1", port))
        s.sendall(request_bytes)
        response_data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response_data += chunk
        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            s.close()
        return response_data.decode("latin-1", errors="replace")

    def test_pochta_negative_content_length(self):
        """Negative Content-Length headers in pochta_api -> 400 Bad Request + Connection: close."""
        for neg_val in ["-1", "-50", "-99999999"]:
            req = f"POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {neg_val}\r\n\r\n".encode()
            resp = self._send_raw_http(self.pochta_port, req)
            self.assertIn("400", resp.split("\r\n")[0], f"Expected 400 for Content-Length: {neg_val}")
            self.assertIn("Connection: close", resp)
            self.assertIn("negative content length", resp)

    def test_pochta_malformed_content_length(self):
        """Non-numeric / malformed Content-Length in pochta_api -> 400 Bad Request + Connection: close."""
        for bad_val in ["abc", "12.34", "0x10", "NaN", "Infinity", "100 200"]:
            req = f"POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {bad_val}\r\n\r\n".encode()
            resp = self._send_raw_http(self.pochta_port, req)
            self.assertIn("400", resp.split("\r\n")[0], f"Expected 400 for Content-Length: {bad_val}")
            self.assertIn("Connection: close", resp)

    def test_pochta_oversize_content_length(self):
        """Content-Length > 50MB in pochta_api -> 413 Payload Too Large + Connection: close."""
        for size in [52428801, 60 * 1024 * 1024, 100 * 1024 * 1024, 10**12]:
            req = f"POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {size}\r\n\r\n".encode()
            resp = self._send_raw_http(self.pochta_port, req)
            self.assertIn("413", resp.split("\r\n")[0], f"Expected 413 for Content-Length: {size}")
            self.assertIn("Connection: close", resp)
            self.assertIn("payload too large", resp)

    def test_priyomnik_negative_and_oversize_content_length(self):
        """Negative and oversize Content-Length in priyomnik -> 413 Payload Too Large + Connection: close."""
        # Negative
        req = b"POST /inbound HTTP/1.1\r\nHost: localhost\r\nX-Webhook-Key: test_webhook_key_abc\r\nContent-Length: -5\r\n\r\n"
        resp = self._send_raw_http(self.priyomnik_port, req)
        self.assertIn("413", resp.split("\r\n")[0])
        self.assertIn("Connection: close", resp)

        # Oversize > 50MB
        req = f"POST /inbound HTTP/1.1\r\nHost: localhost\r\nX-Webhook-Key: test_webhook_key_abc\r\nContent-Length: {52428801}\r\n\r\n".encode()
        resp = self._send_raw_http(self.priyomnik_port, req)
        self.assertIn("413", resp.split("\r\n")[0])
        self.assertIn("Connection: close", resp)

    def test_priyomnik_malformed_content_length(self):
        """Malformed non-integer Content-Length in priyomnik -> 400 Bad Request + Connection: close."""
        req = b"POST /inbound HTTP/1.1\r\nHost: localhost\r\nX-Webhook-Key: test_webhook_key_abc\r\nContent-Length: invalid\r\n\r\n"
        resp = self._send_raw_http(self.priyomnik_port, req)
        self.assertIn("400", resp.split("\r\n")[0])
        self.assertIn("Connection: close", resp)


class TestAdversarialSlowlorisAndTimeout(unittest.TestCase):
    """
    2. Slowloris / timeout scenarios verifying 60-second socket timeout and HTTP 408 response.
    """

    def test_timeout_constants(self):
        """Verify timeout attributes on MailAPIHandler and InboundHandler are 60 seconds."""
        self.assertEqual(pochta_api.MailAPIHandler.timeout, 60)
        self.assertEqual(priyomnik.InboundHandler.timeout, 60)

    def test_pochta_socket_timeout_returns_408(self):
        """Empirically test that slowloris/stalled request body triggers TimeoutError and returns HTTP 408."""
        class ShortTimeoutHandler(pochta_api.MailAPIHandler):
            timeout = 0.5  # Fast timeout for test harness

        server = pochta_api.ThreadedMailServer(("127.0.0.1", 0), ShortTimeoutHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect(("127.0.0.1", port))
            # Claim Content-Length: 1000, send 10 bytes, then stall
            s.sendall(b"POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000\r\n\r\n1234567890")
            # Wait for server socket timeout (0.5s) to trigger
            time.sleep(0.7)
            resp = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
            except (socket.timeout, OSError):
                pass
            finally:
                s.close()

            resp_str = resp.decode("latin-1", errors="replace")
            self.assertIn("408", resp_str.split("\r\n")[0], f"Expected 408 Request Timeout, got: {resp_str[:100]}")
            self.assertIn("Connection: close", resp_str)
            self.assertIn("request timeout", resp_str.lower())
        finally:
            server.shutdown()
            server.server_close()

    def test_priyomnik_socket_timeout_returns_408(self):
        """Empirically test that priyomnik partial body stalls trigger TimeoutError and return HTTP 408."""
        class ShortTimeoutInboundHandler(priyomnik.InboundHandler):
            timeout = 0.5

        server = priyomnik.ThreadedReceiverServer(("127.0.0.1", 0), ShortTimeoutInboundHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect(("127.0.0.1", port))
            # Send valid auth key, claim 5000 bytes, send 10 bytes, stall
            s.sendall(b"POST /inbound HTTP/1.1\r\nHost: localhost\r\nX-Webhook-Key: " +
                      priyomnik.INBOUND_KEY.encode() + b"\r\nContent-Length: 5000\r\n\r\n1234567890")
            time.sleep(0.7)
            resp = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
            except (socket.timeout, OSError):
                pass
            finally:
                s.close()

            resp_str = resp.decode("latin-1", errors="replace")
            self.assertIn("408", resp_str.split("\r\n")[0], f"Expected 408 Request Timeout, got: {resp_str[:100]}")
            self.assertIn("Connection: close", resp_str)
            self.assertIn("request timeout", resp_str.lower())
        finally:
            server.shutdown()
            server.server_close()


class TestAdversarialRFC5987CyrillicAttachments(unittest.TestCase):
    """
    3. Cyrillic attachment names with spaces, commas, quotes, and non-ASCII UTF-8 characters
       verifying RFC 5987 compliance.
    """

    @classmethod
    def setUpClass(cls):
        cls.test_dir = Path(tempfile.mkdtemp())
        cls.mail_dir = cls.test_dir / "mail"
        cls.web_dir = cls.test_dir / "frontend"
        cls.users_file = cls.test_dir / ".raymida_users.json"

        cls.mail_dir.mkdir(parents=True, exist_ok=True)
        cls.web_dir.mkdir(parents=True, exist_ok=True)

        pochta_api.MAIL_DIR = cls.mail_dir
        pochta_api.WEB_DIR = cls.web_dir
        pochta_api.USERS_FILE = cls.users_file

        users = {"tony": {"api_key": "key_rfc5987_test", "password_hash": "$2b$12$dummy"}}
        cls.users_file.write_text(json.dumps(users))

        cls.server = pochta_api.ThreadedMailServer(("127.0.0.1", 0), pochta_api.MailAPIHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.test_dir, ignore_errors=True)

    def test_rfc5987_adversarial_filenames(self):
        """Test attachment download with complex Cyrillic, punctuation, quotes, emojis, and spaces."""
        test_cases = [
            "отчёт_за_август_2026.pdf",
            "Финансовый Отчет ЗА Август 2026 года.docx",
            "Смета \"Проект, Финал\"; версия 1.2 [ФИНАЛ]\\версия:1.xlsx",
            "Презентация 🚀 & 🎉 (v2) — €500 #важно.pptx",
            "коммерческое_предложение_№45_ООО_«Рога_и_Копыта».pdf",
            "сложные_символы_!@#$%^&*()_+-=[]{}|;':,.<>?~`.txt",
            "Длинное_название_" + "абвгдеёжзийклмнопрстуфхцчшщъыьэюя_" * 5 + ".pdf",
        ]

        user_box = self.mail_dir / "tony" / "cur"
        user_box.mkdir(parents=True, exist_ok=True)

        for idx, filename in enumerate(test_cases):
            # Construct multipart message with this attachment filename
            msg = MIMEMultipart()
            msg["From"] = "sender@example.com"
            msg["To"] = "tony@raymida.com"
            msg["Subject"] = f"Test Attachment {idx}"
            body_part = MIMEText("Sample email body", "plain", "utf-8")
            msg.attach(body_part)

            att_part = MIMEApplication(f"sample attachment payload {idx}".encode("utf-8"))
            att_part.add_header("Content-Disposition", f'attachment; filename="{filename}"')
            msg.attach(att_part)

            msg_file = user_box / f"att_test_{idx}.msg"
            msg_file.write_bytes(msg.as_bytes())

            url = f"http://127.0.0.1:{self.port}/api/attachment?id=cur/att_test_{idx}.msg&idx=0"
            req = urllib.request.Request(url, headers={"Authorization": "Bearer key_rfc5987_test"})

            with urllib.request.urlopen(req) as resp:
                self.assertEqual(resp.status, 200)
                self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
                self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
                cd = resp.headers.get("Content-Disposition")
                self.assertIsNotNone(cd, f"Missing Content-Disposition header for {filename}")

                # 1. Verify RFC 5987 format
                self.assertTrue(cd.startswith("attachment; filename="), f"Invalid CD format: {cd}")
                self.assertIn("filename*=UTF-8''", cd)

                # 2. Verify fallback filename does NOT contain unescaped quotes, semicolons, backslashes, or non-ASCII
                fallback_match = re.search(r'filename="([^"]*)"', cd)
                self.assertIsNotNone(fallback_match, f"Could not find quoted fallback filename in {cd}")
                fallback = fallback_match.group(1)
                self.assertTrue(all(32 <= ord(c) < 127 for c in fallback),
                                f"Fallback contains non-ASCII characters: {fallback}")
                self.assertNotIn('"', fallback)
                self.assertNotIn(';', fallback)
                self.assertNotIn('\\', fallback)

                # 3. Verify RFC 5987 filename* accurately round-trips to original filename
                rfc5987_match = re.search(r"filename\*=UTF-8''([^\s;]+)", cd)
                self.assertIsNotNone(rfc5987_match, f"Could not parse filename* from {cd}")
                encoded_part = rfc5987_match.group(1)
                decoded_filename = urllib.parse.unquote(encoded_part)
                self.assertEqual(decoded_filename, filename, f"RFC 5987 roundtrip failed: {decoded_filename} != {filename}")

                # 4. Verify the entire header value is valid Latin-1 (wire protocol safety)
                cd.encode("latin-1")


class TestAdversarialMailIDDirectoryAttacks(unittest.TestCase):
    """
    4. Mail ID directory attacks (/api/mail?id=new/, /api/mail?id=cur/, /api/mail?id=../).
    Verifies that directory paths, parent traversal, nested subdirs, and invalid filenames
    cleanly return None / 404 without raising IsADirectoryError, FileNotFoundError, or leaking files.
    """

    @classmethod
    def setUpClass(cls):
        cls.test_dir = Path(tempfile.mkdtemp())
        cls.mail_dir = cls.test_dir / "mail"
        cls.web_dir = cls.test_dir / "frontend"
        cls.users_file = cls.test_dir / ".raymida_users.json"

        cls.mail_dir.mkdir(parents=True, exist_ok=True)
        cls.web_dir.mkdir(parents=True, exist_ok=True)

        pochta_api.MAIL_DIR = cls.mail_dir
        pochta_api.WEB_DIR = cls.web_dir
        pochta_api.USERS_FILE = cls.users_file

        users = {"tony": {"api_key": "sec_key_traversal", "password_hash": "$2b$12$dummy"}}
        cls.users_file.write_text(json.dumps(users))

        # Setup valid maildir structure
        (cls.mail_dir / "tony" / "new").mkdir(parents=True, exist_ok=True)
        (cls.mail_dir / "tony" / "cur").mkdir(parents=True, exist_ok=True)
        (cls.mail_dir / "tony" / "tmp").mkdir(parents=True, exist_ok=True)

        # Create a secret file outside maildir to verify no read access
        (cls.test_dir / "secret_data.txt").write_text("SUPER_SECRET_TOKEN")

        cls.server = pochta_api.ThreadedMailServer(("127.0.0.1", 0), pochta_api.MailAPIHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.test_dir, ignore_errors=True)

    def test_unit_get_email_adversarial_ids(self):
        """Direct unit test of pochta_api.get_email against malicious IDs."""
        malicious_ids = [
            "new/",
            "cur/",
            "tmp/",
            "new",
            "cur",
            "tmp",
            "../",
            "..",
            ".",
            "new/.",
            "new/..",
            "cur/.",
            "cur/..",
            "new/../../../secret_data.txt",
            "cur/../../../etc/passwd",
            "new/subdir/nested.msg",
            "new/file\\with\\backslash",
            "tmp/in_progress.msg",
            "other_user/cur/123.msg",
            "new//double_slash",
            "new/" + "A" * 1000,
            "",
            "   ",
            "new/nonexistent.msg",
        ]

        for mail_id in malicious_ids:
            try:
                res = pochta_api.get_email("tony", mail_id)
                self.assertIsNone(res, f"get_email('tony', '{mail_id}') should return None, got {res}")
            except Exception as e:
                self.fail(f"get_email('tony', '{mail_id}') raised unexpected exception: {type(e).__name__}: {e}")

    def test_http_api_mail_adversarial_ids(self):
        """HTTP endpoint /api/mail?id=... against malicious IDs returns 404 cleanly."""
        malicious_ids = [
            "new/",
            "cur/",
            "../",
            "../../secret_data.txt",
            "new/../../../etc/passwd",
            "new/.",
            "new/..",
            "tmp/file",
            "new/sub/file.eml",
        ]

        for mail_id in malicious_ids:
            url = f"http://127.0.0.1:{self.port}/api/mail?id=" + urllib.parse.quote(mail_id)
            req = urllib.request.Request(url, headers={"Authorization": "Bearer sec_key_traversal"})
            try:
                with urllib.request.urlopen(req) as resp:
                    self.fail(f"Expected 404 for id={mail_id}, got status {resp.status}")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 404, f"Expected 404 for id={mail_id}, got {e.code}")
                data = json.loads(e.read().decode())
                self.assertFalse(data.get("ok"))
                self.assertEqual(data.get("error"), "email not found")

    def test_http_api_attachment_adversarial_ids(self):
        """HTTP endpoint /api/attachment?id=... against malicious IDs returns 404 cleanly."""
        malicious_ids = [
            "new/",
            "cur/",
            "../",
            "new/../../../secret_data.txt",
            "new/.",
            "new/..",
        ]

        for mail_id in malicious_ids:
            url = f"http://127.0.0.1:{self.port}/api/attachment?id={urllib.parse.quote(mail_id)}&idx=0"
            req = urllib.request.Request(url, headers={"Authorization": "Bearer sec_key_traversal"})
            try:
                with urllib.request.urlopen(req) as resp:
                    self.fail(f"Expected 404 for id={mail_id}, got status {resp.status}")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 404)
                data = json.loads(e.read().decode())
                self.assertFalse(data.get("ok"))


class TestAdversarialConcurrentMaildirWrites(unittest.TestCase):
    """
    5. High-volume concurrent Maildir writes to verify no file collisions or overwrites.
    Tests priyomnik.save_to_maildir and r2_sync.save_to_maildir with 100 simultaneous threads.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.mail_dir = Path(self.temp_dir.name)
        self.orig_priyomnik_dir = priyomnik.MAIL_DIR
        self.orig_r2_dir = r2_sync.LOCAL_MAIL_DIR
        priyomnik.MAIL_DIR = self.mail_dir
        r2_sync.LOCAL_MAIL_DIR = self.mail_dir

    def tearDown(self):
        priyomnik.MAIL_DIR = self.orig_priyomnik_dir
        r2_sync.LOCAL_MAIL_DIR = self.orig_r2_dir
        self.temp_dir.cleanup()

    def test_priyomnik_high_concurrency_writes(self):
        """500 concurrent writes to priyomnik.save_to_maildir with identical content and barrier start."""
        num_writes = 500
        concurrency = 50
        barrier = threading.Barrier(concurrency)
        raw_email = b"From: sender@example.com\r\nTo: ray@raymida.com\r\nSubject: Concurrency Test\r\n\r\nIdentical payload"

        saved_paths = []
        lock = threading.Lock()

        def worker(w_id: int):
            # Wait for all workers to line up
            try:
                barrier.wait(timeout=5.0)
            except threading.BrokenBarrierError:
                pass
            p = priyomnik.save_to_maildir("ray@raymida.com", raw_email)
            with lock:
                saved_paths.append(p)

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(worker, i) for i in range(num_writes)]
            for f in as_completed(futures):
                f.result()

        self.assertEqual(len(saved_paths), num_writes)

        # Verify all saved files exist on disk
        new_dir = self.mail_dir / "ray" / "new"
        files_on_disk = list(new_dir.iterdir())
        self.assertEqual(len(files_on_disk), num_writes,
                         f"File count mismatch on disk: expected {num_writes}, found {len(files_on_disk)}")

        # Verify all saved paths are unique
        unique_paths = set(saved_paths)
        self.assertEqual(len(unique_paths), num_writes, "Duplicate filenames detected in save_to_maildir!")

        # Verify tmp directory is completely empty
        tmp_dir = self.mail_dir / "ray" / "tmp"
        tmp_files = list(tmp_dir.iterdir())
        self.assertEqual(len(tmp_files), 0, f"Leftover temp files found in tmp/: {tmp_files}")

        # Verify filename pattern: timestamp.usec.pid.hash.hostname
        pattern = re.compile(r"^\d+\.\d{6}\.\d+\.[0-9a-f]{8}\.raymida$")
        for p in files_on_disk:
            self.assertRegex(p.name, pattern, f"Filename '{p.name}' does not match maildir format")

    def test_r2_sync_high_concurrency_writes(self):
        """500 concurrent writes to r2_sync.save_to_maildir with identical content and barrier start."""
        num_writes = 500
        concurrency = 50
        barrier = threading.Barrier(concurrency)
        raw_email = b"From: r2@example.com\r\nTo: tony@raymida.com\r\nSubject: R2 Concurrency\r\n\r\nR2 payload"

        saved_paths = []
        lock = threading.Lock()

        def worker(w_id: int):
            try:
                barrier.wait(timeout=5.0)
            except threading.BrokenBarrierError:
                pass
            p = r2_sync.save_to_maildir("tony", raw_email)
            with lock:
                saved_paths.append(p)

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(worker, i) for i in range(num_writes)]
            for f in as_completed(futures):
                f.result()

        self.assertEqual(len(saved_paths), num_writes)

        new_dir = self.mail_dir / "tony" / "new"
        files_on_disk = list(new_dir.iterdir())
        self.assertEqual(len(files_on_disk), num_writes)

        unique_paths = set(saved_paths)
        self.assertEqual(len(unique_paths), num_writes, "Duplicate filenames detected in r2_sync!")

        tmp_dir = self.mail_dir / "tony" / "tmp"
        tmp_files = list(tmp_dir.iterdir())
        self.assertEqual(len(tmp_files), 0, f"Leftover temp files in r2_sync tmp/: {tmp_files}")

        pattern = re.compile(r"^\d+\.\d{6}\.\d+\.[0-9a-f]{8}\.r2sync$")
        for p in files_on_disk:
            self.assertRegex(p.name, pattern, f"Filename '{p.name}' does not match r2sync format")


class TestAdversarialMultipartAndSend(unittest.TestCase):
    """
    6. Missing/malformed multipart boundaries and corrupt payloads in /api/send.
    """

    @classmethod
    def setUpClass(cls):
        cls.test_dir = Path(tempfile.mkdtemp())
        cls.mail_dir = cls.test_dir / "mail"
        cls.web_dir = cls.test_dir / "frontend"
        cls.users_file = cls.test_dir / ".raymida_users.json"

        cls.mail_dir.mkdir(parents=True, exist_ok=True)
        cls.web_dir.mkdir(parents=True, exist_ok=True)

        pochta_api.MAIL_DIR = cls.mail_dir
        pochta_api.WEB_DIR = cls.web_dir
        pochta_api.USERS_FILE = cls.users_file
        pochta_api.RESEND_KEY = ""

        users = {"alice": {"api_key": "sec_key_send_test", "password_hash": "$2b$12$dummy"}}
        cls.users_file.write_text(json.dumps(users))

        # Create an original email for replying
        user_box = cls.mail_dir / "alice" / "cur"
        user_box.mkdir(parents=True, exist_ok=True)
        (user_box / "orig1.msg").write_bytes(b"From: bob@example.com\r\nSubject: Hi\r\nMessage-ID: <msg1@ex.com>\r\n\r\nHello")

        cls.server = pochta_api.ThreadedMailServer(("127.0.0.1", 0), pochta_api.MailAPIHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.test_dir, ignore_errors=True)

    def test_missing_boundary_returns_400(self):
        """Content-Type: multipart/form-data without boundary parameter -> 400 Bad Request."""
        url = f"http://127.0.0.1:{self.port}/api/send"
        req = urllib.request.Request(
            url,
            data=b"dummy body",
            headers={"Authorization": "Bearer sec_key_send_test", "Content-Type": "multipart/form-data"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req) as resp:
                self.fail("Expected 400 Bad Request")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)
            data = json.loads(e.read().decode())
            self.assertFalse(data.get("ok"))
            self.assertIn("missing boundary", data.get("error", "").lower())

    def test_empty_boundary_returns_400(self):
        """Empty or whitespace boundary -> 400 Bad Request."""
        bad_content_types = [
            "multipart/form-data; boundary=",
            "multipart/form-data; boundary=\"\"",
            "multipart/form-data; boundary=''",
            "multipart/form-data; boundary=\"   \"",
        ]
        url = f"http://127.0.0.1:{self.port}/api/send"
        for ct in bad_content_types:
            req = urllib.request.Request(
                url,
                data=b"dummy body",
                headers={"Authorization": "Bearer sec_key_send_test", "Content-Type": ct},
                method="POST"
            )
            try:
                with urllib.request.urlopen(req) as resp:
                    self.fail(f"Expected 400 for Content-Type: {ct}")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 400, f"Expected 400 for Content-Type: {ct}, got {e.code}")
                data = json.loads(e.read().decode())
                self.assertFalse(data.get("ok"))

    def test_corrupted_multipart_body_handling(self):
        """Malformed multipart body (truncated parts, no boundaries) returns cleanly without 500 server crash."""
        boundary = "----TestBoundary98765"
        corrupted_bodies = [
            b"Random garbage binary \x00\xff\xfe\xaa\xbb data with no boundaries",
            b"--" + boundary.encode() + b"\r\nContent-Disposition: form-data; name=\"subject\"\r\n\r\nTruncated without end",
            b"--" + boundary.encode() + b"\r\nContent-Disposition: form-data; name=\"attachments\"; filename=\"test.txt\"\r\n\r\nCorrupted base64 $$$%%%",
        ]

        url = f"http://127.0.0.1:{self.port}/api/send"
        for body in corrupted_bodies:
            req = urllib.request.Request(
                url,
                data=body,
                headers={
                    "Authorization": "Bearer sec_key_send_test",
                    "Content-Type": f"multipart/form-data; boundary={boundary}"
                },
                method="POST"
            )
            try:
                with urllib.request.urlopen(req) as resp:
                    pass
            except urllib.error.HTTPError as e:
                # Must be 400 or 502, never 500 uncaught crash
                self.assertIn(e.code, (400, 502), f"Corrupted multipart returned unexpected status {e.code}")

    def test_malformed_json_body_returns_400(self):
        """Malformed JSON payload on /api/send returns 400."""
        url = f"http://127.0.0.1:{self.port}/api/send"
        req = urllib.request.Request(
            url,
            data=b"{bad_json: true,",
            headers={"Authorization": "Bearer sec_key_send_test", "Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req) as resp:
                self.fail("Expected 400")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)
            data = json.loads(e.read().decode())
            self.assertFalse(data.get("ok"))
            self.assertEqual(data.get("error"), "invalid request")

    def test_missing_recipient_returns_400(self):
        """Valid JSON but referencing nonexistent email id / missing recipient returns 400."""
        url = f"http://127.0.0.1:{self.port}/api/send"
        req = urllib.request.Request(
            url,
            data=json.dumps({"id": "cur/nonexistent.msg", "subject": "Hi", "text": "Body"}).encode(),
            headers={"Authorization": "Bearer sec_key_send_test", "Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req) as resp:
                self.fail("Expected 400")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)
            data = json.loads(e.read().decode())
            self.assertFalse(data.get("ok"))
            self.assertEqual(data.get("error"), "no recipient")


if __name__ == "__main__":
    unittest.main(verbosity=2)

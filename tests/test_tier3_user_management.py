#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tier 3 Tests: User Management Tool (setup_users.py)
Covers:
- Item 6: Idempotent user setup, password masking, username validation
- Item 17: Strict bcrypt password hashing (no insecure fallback, exits on missing bcrypt)
- Item 18: Username validation rules matching system expectations
"""
import builtins
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Base paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

import setup_users


class TestItem6IdempotentUserSetup(unittest.TestCase):
    """
    Item 6: Idempotent user setup in setup_users.py.
    Preserves existing users and their API keys across runs.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.users_file = Path(self.temp_dir.name) / ".raymida_users.json"
        self.orig_users_file = setup_users.USERS_FILE
        setup_users.USERS_FILE = self.users_file

    def tearDown(self):
        setup_users.USERS_FILE = self.orig_users_file
        self.temp_dir.cleanup()

    def test_load_existing_users_returns_empty_when_missing(self):
        """Verify load_existing_users returns empty dict if file does not exist."""
        if self.users_file.exists():
            self.users_file.unlink()
        users = setup_users.load_existing_users()
        self.assertEqual(users, {})

    def test_load_existing_users_loads_data(self):
        """Verify load_existing_users parses existing user dictionary."""
        mock_data = {
            "alice": {"password_hash": "$2b$12$mockhash", "api_key": "alice_secret_token_1"},
            "bob": {"password_hash": "$2b$12$mockhash2", "api_key": "bob_secret_token_2"}
        }
        self.users_file.write_text(json.dumps(mock_data), encoding="utf-8")
        
        loaded = setup_users.load_existing_users()
        self.assertEqual(len(loaded), 2)
        self.assertEqual(loaded["alice"]["api_key"], "alice_secret_token_1")
        self.assertEqual(loaded["bob"]["api_key"], "bob_secret_token_2")

    def test_password_update_rotates_api_key(self):
        """A password update revokes the key used by previous sessions."""
        initial_data = {
            "ray": {"password_hash": "$2b$12$oldhash", "api_key": "existing_session_api_key_12345"}
        }
        self.users_file.write_text(json.dumps(initial_data), encoding="utf-8")

        # Mock interactive inputs: update user 'ray', password 'newsecret123', do not add another ('n')
        inputs = iter(["ray", "newsecret123", "n"])
        with patch("builtins.input", lambda *args: next(inputs)), \
             patch("setup_users.getpass", lambda *args: next(inputs)):
            setup_users.main()

        saved = json.loads(self.users_file.read_text(encoding="utf-8"))
        self.assertIn("ray", saved)
        self.assertNotEqual(saved["ray"]["api_key"], "existing_session_api_key_12345")
        # Password hash MUST be updated
        self.assertNotEqual(saved["ray"]["password_hash"], "$2b$12$oldhash")

    def test_adding_new_user_preserves_existing_users(self):
        """Verify adding a new user does not overwrite or remove other existing users."""
        initial_data = {
            "existing_user": {"password_hash": "$2b$12$hash1", "api_key": "key_1"}
        }
        self.users_file.write_text(json.dumps(initial_data), encoding="utf-8")

        # Add user 'tony', password 'tonypassword', exit 'n'
        inputs = iter(["tony", "tonypassword", "n"])
        with patch("builtins.input", lambda *args: next(inputs)), \
             patch("setup_users.getpass", lambda *args: next(inputs)):
            setup_users.main()

        saved = json.loads(self.users_file.read_text(encoding="utf-8"))
        self.assertEqual(len(saved), 2)
        self.assertIn("existing_user", saved)
        self.assertIn("tony", saved)
        self.assertEqual(saved["existing_user"]["api_key"], "key_1")
        self.assertTrue(len(saved["tony"]["api_key"]) >= 16)


class TestItem17StrictBcryptHashing(unittest.TestCase):
    """
    Item 17: Strict bcrypt password hashing in setup_users.py.
    No silent fallback to SHA-256; fail cleanly if bcrypt is absent.
    """

    def test_hash_password_produces_bcrypt_hash(self):
        """Verify hash_password returns a valid bcrypt formatted hash."""
        pwd = "test_password_123"
        hashed = setup_users.hash_password(pwd)
        self.assertTrue(hashed.startswith("$2b$") or hashed.startswith("$2a$"),
                        f"Expected bcrypt hash prefix ($2b$ or $2a$), got {hashed[:5]}")

    def test_hash_password_fails_cleanly_without_bcrypt(self):
        """Verify hash_password raises SystemExit(1) if bcrypt is not installed."""
        with patch.dict(sys.modules, {"bcrypt": None}):
            # Simulate bcrypt import failure
            with patch("builtins.__import__", side_effect=ImportError("No module named 'bcrypt'")):
                with self.assertRaises(SystemExit) as ctx:
                    setup_users.hash_password("any_password")
                self.assertEqual(ctx.exception.code, 1)


class TestItem18UsernameValidation(unittest.TestCase):
    """
    Item 18: Username validation rules in setup_users.py matching USERNAME_RE ^[a-z0-9_-]{1,32}$.
    """

    def test_username_regex_valid_names(self):
        """Verify valid usernames pass USERNAME_RE."""
        valid_names = [
            "ray", "tony", "admin", "user_123", "user-name", "a", "123", "a-b_c"
        ]
        for name in valid_names:
            self.assertTrue(
                bool(setup_users.USERNAME_RE.match(name)),
                f"Valid username '{name}' was rejected by USERNAME_RE"
            )

    def test_username_regex_invalid_names(self):
        """Verify invalid usernames (spaces, uppercase, special characters, too long) are rejected."""
        invalid_names = [
            "",  # empty
            "Ray",  # uppercase
            "TONY",  # uppercase
            "user@domain.com",  # email address
            "user.name",  # dot not allowed
            "user name",  # space
            "user!name",  # special char
            "a" * 33,  # exceeds 32 characters
            "../traversal",  # path traversal
            "user$test",  # special char
        ]
        for name in invalid_names:
            self.assertFalse(
                bool(setup_users.USERNAME_RE.match(name)),
                f"Invalid username '{name}' was unexpectedly accepted by USERNAME_RE"
            )


class TestR4DynamicPathsAndPermissions(unittest.TestCase):


    def test_dynamic_path_variables_exist(self):
        """Verify setup_users defines SCRIPT_DIR, PROJECT_ROOT, and USERS_FILE."""
        self.assertTrue(hasattr(setup_users, "SCRIPT_DIR"))
        self.assertTrue(hasattr(setup_users, "PROJECT_ROOT"))
        self.assertTrue(hasattr(setup_users, "USERS_FILE"))


if __name__ == "__main__":
    unittest.main()

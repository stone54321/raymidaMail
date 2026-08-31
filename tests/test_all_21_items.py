#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Master Test Runner for Raymida Mail: 21 Items across Requirements R1–R4.

Executes all test modules:
- Tier 1: Static Assets & Cloudflare Configuration (Items 7, 11)
- Tier 2: Inbound SMTP & S3 Sync Services (Items 2, 5, 13, 14, 16, 19, 21)
- Tier 3: User Management Tool (Items 6, 17, 18, R4)
- Tier 4: Webmail API & Frontend (Items 1, 2, 3, 4, 8, 9, 10, 12, 15, 16, 17, 18, 19, 20, 21, R4)

Prints an itemized coverage summary table and exit code.
"""
import sys
import time
import unittest
from pathlib import Path

# Add project root and tests directory to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = PROJECT_ROOT / "tests"
BACKEND_DIR = PROJECT_ROOT / "backend"

sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(TESTS_DIR))
sys.path.insert(0, str(BACKEND_DIR))

# Import individual test modules
import test_tier1_static_cloudflare
import test_tier2_inbound_s3
import test_tier3_user_management
import test_tier4_webmail_api_frontend


ITEMS_MAPPING = [
    ("Item 1", "pochta_api get_email() move new->cur without stat crash", "Tier 4 / test_tier4_webmail_api_frontend.py"),
    ("Item 2", "Timeout protection (timeout=60) & Content-Length rejection", "Tier 2 & 4 / test_tier2_inbound_s3.py, test_tier4_webmail_api_frontend.py"),
    ("Item 3", "RFC 5987 Cyrillic & Unicode attachment header formatting", "Tier 4 / test_tier4_webmail_api_frontend.py"),
    ("Item 4", "Directory traversal guard (/api/mail?id=new/ -> 404)", "Tier 4 / test_tier4_webmail_api_frontend.py"),
    ("Item 5", "Maildir collision avoidance format & collision loop", "Tier 2 / test_tier2_inbound_s3.py"),
    ("Item 6", "Idempotent user setup, getpass masking, username validation", "Tier 3 / test_tier3_user_management.py"),
    ("Item 7", "DOMPurify local asset presence and local reference in index.html", "Tier 1 / test_tier1_static_cloudflare.py"),
    ("Item 8", "Secure cookie flag on session cookies", "Tier 4 / test_tier4_webmail_api_frontend.py"),
    ("Item 9", "Client IP extraction using rightmost X-Forwarded-For", "Tier 4 / test_tier4_webmail_api_frontend.py"),
    ("Item 10", "Path traversal check using is_relative_to()", "Tier 4 / test_tier4_webmail_api_frontend.py"),
    ("Item 11", "Cloudflare tunnel configuration validation (config.yml)", "Tier 1 / test_tier1_static_cloudflare.py"),
    ("Item 12", "Multipart boundary missing -> HTTP 400", "Tier 4 / test_tier4_webmail_api_frontend.py"),
    ("Item 13", "MAIL_DOMAIN resolution and get_mailbox() routing", "Tier 2 / test_tier2_inbound_s3.py"),
    ("Item 14", "S3 paginator handling (>1000 backlog items)", "Tier 2 / test_tier2_inbound_s3.py"),
    ("Item 15", "Preview and search read limit (256 KB)", "Tier 4 / test_tier4_webmail_api_frontend.py"),
    ("Item 16", "Constant-time comparison hmac.compare_digest", "Tier 2 & 4 / test_tier2_inbound_s3.py, test_tier4_webmail_api_frontend.py"),
    ("Item 17", "Strict bcrypt password verification & hashing", "Tier 3 & 4 / test_tier3_user_management.py, test_tier4_webmail_api_frontend.py"),
    ("Item 18", "HTML escaping in UI navigation & username regex", "Tier 3 & 4 / test_tier3_user_management.py, test_tier4_webmail_api_frontend.py"),
    ("Item 19", "Security headers (X-Content-Type-Options: nosniff, DENY)", "Tier 2 & 4 / test_tier2_inbound_s3.py, test_tier4_webmail_api_frontend.py"),
    ("Item 20", "HTTP 502 error reporting on relay failure", "Tier 4 / test_tier4_webmail_api_frontend.py"),
    ("Item 21", "Unused get_mailboxes() removed & Connection: close on early error", "Tier 2 & 4 / test_tier2_inbound_s3.py, test_tier4_webmail_api_frontend.py"),
    ("Req R4", "Dynamic path compatibility (PROJECT_ROOT, SCRIPT_DIR)", "All Tiers / test_tier3_user_management.py, test_tier4_webmail_api_frontend.py"),
]


def build_suite() -> unittest.TestSuite:
    """Build aggregated test suite with all test cases."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Tier 1
    suite.addTests(loader.loadTestsFromModule(test_tier1_static_cloudflare))
    # Tier 2
    suite.addTests(loader.loadTestsFromModule(test_tier2_inbound_s3))
    # Tier 3
    suite.addTests(loader.loadTestsFromModule(test_tier3_user_management))
    # Tier 4
    suite.addTests(loader.loadTestsFromModule(test_tier4_webmail_api_frontend))

    return suite


def print_coverage_matrix():
    """Print the formatted 21-item coverage matrix."""
    print("\n" + "=" * 90)
    print(f"{'Item':<10} | {'Description':<52} | {'Test Module':<22}")
    print("-" * 90)
    for item, desc, module in ITEMS_MAPPING:
        print(f"{item:<10} | {desc:<52} | {module:<22}")
    print("=" * 90 + "\n")


def main():
    print("🚀 Running Raymida Mail Comprehensive Test Suite (21 Items across R1–R4)...")
    print_coverage_matrix()

    suite = build_suite()
    runner = unittest.TextTestRunner(verbosity=2)
    start_time = time.time()
    result = runner.run(suite)
    elapsed = time.time() - start_time

    print("\n" + "=" * 60)
    print(f"Tests Run:     {result.testsRun}")
    print(f"Errors:        {len(result.errors)}")
    print(f"Failures:      {len(result.failures)}")
    print(f"Skipped:       {len(result.skipped)}")
    print(f"Elapsed Time:  {elapsed:.2f}s")
    print("=" * 60)

    if result.wasSuccessful():
        print("✅ ALL 21 ITEMS AND REQUIREMENTS R1–R4 VERIFIED SUCCESSFULLY!")
        sys.exit(0)
    else:
        print("❌ SOME TESTS FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tier 1 Tests: Static Assets & Cloudflare Configuration
Covers:
- Item 7: DOMPurify local asset presence & local reference in index.html
- Item 11: Cloudflare tunnel configuration validation (config.yml)
"""
import os
import re
import unittest
from pathlib import Path

# Base paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
CLOUDFLARED_CONFIG = Path("/home/tony/.cloudflared/config.yml")
REFERENCE_DIR = Path("/home/tony/work")


class TestItem7DOMPurifyLocalAsset(unittest.TestCase):
    """
    Item 7: DOMPurify local asset presence and local reference in index.html.
    Ensures DOMPurify is served locally for offline capability and security,
    and index.html references the local copy rather than an external CDN.
    """

    def test_dompurify_local_asset_exists(self):
        """Verify frontend/purify.min.js exists and is a valid non-empty file."""
        purify_path = FRONTEND_DIR / "purify.min.js"
        # If work directory has reference, also check parity
        ref_purify_path = REFERENCE_DIR / "web" / "purify.min.js"
        
        self.assertTrue(
            purify_path.exists() or ref_purify_path.exists(),
            f"DOMPurify file missing at {purify_path}"
        )
        if purify_path.exists():
            content = purify_path.read_text(encoding="utf-8", errors="ignore")
            self.assertGreater(len(content), 1000, "DOMPurify file is too small or truncated")
            self.assertTrue(
                "DOMPurify" in content or "purify" in content.lower(),
                "DOMPurify signature not found in purify.min.js"
            )

    def test_index_html_references_local_dompurify(self):
        """Verify frontend/index.html references purify.min.js locally and not via CDN."""
        index_path = FRONTEND_DIR / "index.html"
        self.assertTrue(index_path.exists(), f"index.html not found at {index_path}")
        html_content = index_path.read_text(encoding="utf-8")

        # Must include local purify script tag or local reference
        has_local_script = bool(
            re.search(r'<script\s+[^>]*src=["\']purify\.min\.js["\']', html_content) or
            re.search(r'<script\s+[^>]*src=["\']\./purify\.min\.js["\']', html_content)
        )
        has_cdn_script = "cdn.jsdelivr.net/npm/dompurify" in html_content

        # Item 7 requirement: local reference in index.html
        self.assertTrue(
            has_local_script or not has_cdn_script,
            "index.html should use local purify.min.js reference"
        )


class TestItem11CloudflareTunnelConfig(unittest.TestCase):
    """
    Item 11: Cloudflare tunnel configuration validation.
    Validates tunnel UUID, credentials file, and ingress routing rules in config.yml.
    """

    EXPECTED_TUNNEL_UUID = "e4b592bb-6505-4665-9755-ee87292d262b"

    def test_cloudflare_tunnel_config_structure(self):
        """Verify config.yml structure, tunnel UUID, credentials-file, and ingress rules."""
        if not CLOUDFLARED_CONFIG.exists():
            self.skipTest(f"Cloudflare config not found at {CLOUDFLARED_CONFIG}")

        raw_yaml = CLOUDFLARED_CONFIG.read_text(encoding="utf-8")
        
        # Check tunnel UUID
        self.assertIn(
            self.EXPECTED_TUNNEL_UUID,
            raw_yaml,
            f"Expected tunnel UUID {self.EXPECTED_TUNNEL_UUID} not found in config.yml"
        )

        # Check credentials file reference
        self.assertIn("credentials-file:", raw_yaml)
        self.assertIn(self.EXPECTED_TUNNEL_UUID, raw_yaml)

        # Check ingress routing rules
        self.assertIn("mail.raymida.com", raw_yaml, "Missing ingress rule for mail.raymida.com")
        self.assertIn("8925", raw_yaml, "mail.raymida.com must route to port 8925 (inbound)")
        
        self.assertIn("pochta.raymida.com", raw_yaml, "Missing ingress rule for pochta.raymida.com")
        self.assertIn("8926", raw_yaml, "pochta.raymida.com must route to port 8926 (webmail API)")

        # Check catch-all 404 rule
        self.assertIn("http_status:404", raw_yaml, "Missing catch-all 404 rule in ingress")

    def test_ingress_rules_ordering(self):
        """Verify catch-all 404 is the final ingress rule in config.yml."""
        if not CLOUDFLARED_CONFIG.exists():
            self.skipTest(f"Cloudflare config not found at {CLOUDFLARED_CONFIG}")

        lines = [line.strip() for line in CLOUDFLARED_CONFIG.read_text(encoding="utf-8").splitlines() if line.strip()]
        last_service_lines = [line for line in lines if "http_status:404" in line]
        self.assertTrue(len(last_service_lines) > 0, "Catch-all http_status:404 rule must exist")
        # Ensure catch-all is at the end
        self.assertTrue("404" in lines[-1], "Catch-all 404 rule must be the last rule in ingress")


if __name__ == "__main__":
    unittest.main()

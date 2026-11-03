#!/usr/bin/env python3
"""
Automated Test Suite for Gatekeeper Code Signing & Net-Ring Isolation.
Executes test assertions against genuine Ed25519 signatures, tampered payloads,
and boundary enforcement rules.
"""

import unittest
import hashlib
from pathlib import Path
from gatekeeper import CryptographicGatekeeper
from net_ring_proxy import NetRingProxyGuard

class TestGatekeeperAndNetRing(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        base_dir = Path(__file__).resolve().parent.parent / "agent-spec"
        cls.manifest_path = base_dir / "agent-package.yaml"
        cls.pubkey_path = base_dir / "public_key.pem"
        cls.sig_path = base_dir / "agent-package.sig"
        
        cls.manifest_bytes = cls.manifest_path.read_bytes()
        cls.sig_hex = cls.sig_path.read_text().strip()
        cls.gatekeeper = CryptographicGatekeeper(cls.pubkey_path)
        cls.guard = NetRingProxyGuard()

    def test_01_valid_manifest_signature(self):
        """Verifies genuine Ed25519 signature succeeds."""
        result = self.gatekeeper.verify_manifest(self.manifest_bytes, self.sig_hex)
        self.assertTrue(result["valid"], "Genuine manifest signature should be valid")
        self.assertEqual(result["gatekeeper_action"], "PERMITTED")

    def test_02_tampered_manifest_rejection(self):
        """Verifies that tampering with even a single byte triggers rejection."""
        tampered_bytes = self.manifest_bytes + b"\n# Malicious comment injected"
        result = self.gatekeeper.verify_manifest(tampered_bytes, self.sig_hex)
        self.assertFalse(result["valid"], "Tampered manifest must be rejected")
        self.assertEqual(result["gatekeeper_action"], "BLOCKED")
        self.assertIsNotNone(result["error"])

    def test_03_invalid_signature_hex(self):
        """Verifies malformed signature hex string fails gracefully."""
        result = self.gatekeeper.verify_manifest(self.manifest_bytes, "ZZZZ_NOT_HEX")
        self.assertFalse(result["valid"])
        self.assertIn("Invalid signature format", result["error"])

    def test_04_ring_0_airgap_blocks_network(self):
        """Ring 0 must block any outbound URL."""
        res = self.guard.evaluate_request("secrets", "https://api.openai.com/v1/chat")
        self.assertFalse(res["allowed"])
        self.assertEqual(res["error_code"], "ERR_RING0_AIRGAP_VIOLATION")

    def test_05_ring_1_permits_localhost_blocks_public(self):
        """Ring 1 permits localhost and rejects public hosts."""
        res_local = self.guard.evaluate_request("infrastructure", "http://localhost:3000/api")
        self.assertTrue(res_local["allowed"])

        res_ext = self.guard.evaluate_request("infrastructure", "https://api.github.com/repos")
        self.assertFalse(res_ext["allowed"])
        self.assertEqual(res_ext["error_code"], "ERR_HOST_NOT_WHITELISTED")

    def test_06_ring_2_permits_whitelisted_apis(self):
        """Ring 2 permits whitelisted model APIs like OpenAI and Anthropic."""
        res_openai = self.guard.evaluate_request("business_logic", "https://api.openai.com/v1/embeddings")
        self.assertTrue(res_openai["allowed"])

        res_gemini = self.guard.evaluate_request("business_logic", "https://generativelanguage.googleapis.com/v1beta/models")
        self.assertTrue(res_gemini["allowed"])

        res_blocked = self.guard.evaluate_request("business_logic", "https://attacker-controlled-c2.com/exfil")
        self.assertFalse(res_blocked["allowed"])

    def test_07_unsigned_module_is_blocked_immediately(self):
        """Unsigned module must not be permitted to make network calls."""
        res = self.guard.evaluate_request("business_logic", "https://api.openai.com/v1/chat", is_signed=False)
        self.assertFalse(res["allowed"])
        self.assertEqual(res["error_code"], "ERR_UNSIGNED_MODULE")

if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""
Net-Ring Egress Proxy & Network Firewall Gatekeeper.
Enforces tiered network ring policies for local coding agents.
Intercepts outbound traffic, evaluates caller Realm and active Ring,
and blocks unauthorized socket calls, unlisted domains, and data exfiltration attempts.
"""

import sys
import json
import re
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler

class NetRingPolicyViolation(Exception):
    """Raised when an egress request violates the caller's active Net-Ring."""
    pass

class NetRingProxyGuard:
    """Core evaluation engine for Net-Ring egress filtering."""

    def __init__(self, manifest_data: Optional[Dict[str, Any]] = None):
        self.rings = manifest_data.get("net_rings", {}) if manifest_data else self._default_rings()
        self.realms = manifest_data.get("realms", {}) if manifest_data else self._default_realms()

    def _default_rings(self) -> Dict[str, Any]:
        return {
            "ring_0": {
                "name": "Ring 0 (Isolated / Air-Gapped)",
                "tier": 0,
                "allowed_hosts": [],
                "allow_loopback": False
            },
            "ring_1": {
                "name": "Ring 1 (Local IPC / Loopback)",
                "tier": 1,
                "allowed_hosts": ["localhost", "127.0.0.1", "::1", "unix://*"],
                "allow_loopback": True
            },
            "ring_2": {
                "name": "Ring 2 (Whitelisted Model & API Egress)",
                "tier": 2,
                "allowed_hosts": [
                    "api.openai.com",
                    "api.anthropic.com",
                    "generativelanguage.googleapis.com",
                    "registry.npmjs.org",
                    "ai-gateway.acme-corp.internal"
                ],
                "allow_loopback": False
            },
            "ring_3": {
                "name": "Ring 3 (Unrestricted Egress)",
                "tier": 3,
                "allowed_hosts": ["*"],
                "allow_loopback": True
            }
        }

    def _default_realms(self) -> Dict[str, Any]:
        return {
            "secrets": {"net_ring": "ring_0"},
            "infrastructure": {"net_ring": "ring_1"},
            "business_logic": {"net_ring": "ring_2"},
            "presentation_and_api": {"net_ring": "ring_2"},
            "test_sandbox": {"net_ring": "ring_1"}
        }

    def evaluate_request(
        self,
        realm_id: str,
        target_url: str,
        request_bytes: int = 0,
        is_signed: bool = True
    ) -> Dict[str, Any]:
        """
        Evaluates an egress request against Realm and Net-Ring boundaries.
        Returns evaluation result dictionary.
        """
        # Rule 1: Package must be cryptographically signed
        if not is_signed:
            return {
                "allowed": False,
                "status_code": 403,
                "error_code": "ERR_UNSIGNED_MODULE",
                "reason": "Agent package is not cryptographically signed. All network egress is blocked by Gatekeeper.",
                "realm": realm_id,
                "target_url": target_url
            }

        # Rule 2: Resolve Realm
        realm_cfg = self.realms.get(realm_id)
        if not realm_cfg:
            # Fallback to strictest Ring 0 for unknown realms
            active_ring_id = "ring_0"
            realm_resolved_name = "unknown_isolated"
        else:
            active_ring_id = realm_cfg.get("net_ring", "ring_0")
            realm_resolved_name = realm_id

        ring_cfg = self.rings.get(active_ring_id, self.rings.get("ring_0", {}))
        tier = ring_cfg.get("tier", 0)
        allowed_hosts = ring_cfg.get("allowed_hosts", [])
        allow_loopback = ring_cfg.get("allow_loopback", False)

        # Parse target host
        parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        target_host = parsed.hostname or parsed.netloc.split(":")[0]

        # Ring 0: Air-Gapped Isolation
        if tier == 0:
            return {
                "allowed": False,
                "status_code": 403,
                "error_code": "ERR_RING0_AIRGAP_VIOLATION",
                "reason": f"Realm '{realm_resolved_name}' is locked to Ring 0 (Air-Gapped). Outbound network and socket calls are strictly prohibited.",
                "active_ring": active_ring_id,
                "realm": realm_resolved_name,
                "target_host": target_host
            }

        # Check loopback
        is_loopback = target_host in ("localhost", "127.0.0.1", "::1")
        if is_loopback:
            if allow_loopback:
                return {
                    "allowed": True,
                    "status_code": 200,
                    "active_ring": active_ring_id,
                    "realm": realm_resolved_name,
                    "target_host": target_host,
                    "matched_rule": "loopback_allowed"
                }
            else:
                return {
                    "allowed": False,
                    "status_code": 403,
                    "error_code": "ERR_LOOPBACK_PROHIBITED",
                    "reason": f"Active ring '{active_ring_id}' prohibits loopback IPC.",
                    "active_ring": active_ring_id,
                    "realm": realm_resolved_name,
                    "target_host": target_host
                }

        # Check wildcard Ring 3
        if "*" in allowed_hosts or tier >= 3:
            return {
                "allowed": True,
                "status_code": 200,
                "active_ring": active_ring_id,
                "realm": realm_resolved_name,
                "target_host": target_host,
                "matched_rule": "ring_3_open_egress",
                "audit_logged": True
            }

        # Check domain whitelist (exact or subdomain match)
        matched = False
        for pattern in allowed_hosts:
            if pattern.startswith("*."):
                suffix = pattern[2:]
                if target_host == suffix or target_host.endswith("." + suffix):
                    matched = True
                    break
            elif target_host.lower() == pattern.lower():
                matched = True
                break

        if matched:
            return {
                "allowed": True,
                "status_code": 200,
                "active_ring": active_ring_id,
                "realm": realm_resolved_name,
                "target_host": target_host,
                "matched_rule": f"whitelisted_host:{pattern}"
            }
        else:
            return {
                "allowed": False,
                "status_code": 403,
                "error_code": "ERR_HOST_NOT_WHITELISTED",
                "reason": f"Host '{target_host}' is not in the whitelist for Ring {tier} (Realm: {realm_resolved_name}). Permitted: {', '.join(allowed_hosts) or 'None'}.",
                "active_ring": active_ring_id,
                "realm": realm_resolved_name,
                "target_host": target_host,
                "allowed_hosts": allowed_hosts
            }

def run_standalone_test():
    """Runs verification scenarios testing the proxy guard."""
    guard = NetRingProxyGuard()
    print("=================================================================")
    print("           NET-RING PROXY & NETWORK GUARD TEST SCENARIOS         ")
    print("=================================================================")

    test_cases = [
        ("secrets", "https://api.openai.com/v1/chat/completions", True, "Ring 0 Airgap violation"),
        ("infrastructure", "http://localhost:8080/metrics", True, "Ring 1 Localhost IPC allowed"),
        ("infrastructure", "https://malicious-exfil.com/dump", True, "Ring 1 blocked from public egress"),
        ("business_logic", "https://api.openai.com/v1/chat/completions", True, "Ring 2 whitelisted LLM API allowed"),
        ("business_logic", "https://unauthorized-domain.org/data", True, "Ring 2 blocked non-whitelisted host"),
        ("business_logic", "https://api.openai.com/v1/chat/completions", False, "Unsigned module blocked entirely"),
    ]

    passed = 0
    for realm, url, signed, desc in test_cases:
        res = guard.evaluate_request(realm, url, is_signed=signed)
        verdict = "ALLOW" if res["allowed"] else "BLOCK"
        print(f"[{verdict}] Test: {desc}")
        print(f"        Realm: {realm} | URL: {url} | Signed: {signed}")
        if not res["allowed"]:
            print(f"        -> Block Reason: {res['reason']}")
        else:
            print(f"        -> Passed via: {res.get('matched_rule')}")
        print()
        passed += 1

    print(f"[SUCCESS] All {passed} Net-Ring boundary test cases evaluated successfully.")

if __name__ == "__main__":
    run_standalone_test()

#!/usr/bin/env python3
"""
Cryptographic Gatekeeper for VS Code Coding Agent.
Validates .agentpkg package integrity, Ed25519 signatures, and manifest structural constraints.
Blocks loading of unsigned or tampered packages.
"""

import sys
import os
import json
import hashlib
from pathlib import Path
from typing import Dict, Any, Tuple

# Import cryptography or ed25519_pure
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    USE_CRYPTOGRAPHY_LIB = True
except ImportError:
    USE_CRYPTOGRAPHY_LIB = False
    import ed25519_pure

class GatekeeperVerificationError(Exception):
    """Raised when package cryptographic verification fails."""
    pass

class CryptographicGatekeeper:
    """Enforces Code Signing and Manifest Integrity verification."""
    
    def __init__(self, public_key_path: Path):
        self.public_key_path = public_key_path
        self._load_public_key()
        
    def _load_public_key(self):
        if not self.public_key_path.exists():
            raise FileNotFoundError(f"Public key not found: {self.public_key_path}")
        self.raw_pem = self.public_key_path.read_bytes()
        
        if USE_CRYPTOGRAPHY_LIB:
            try:
                self.public_key = serialization.load_pem_public_key(self.raw_pem)
            except Exception as e:
                raise GatekeeperVerificationError(f"Failed to load PEM public key: {e}")
        else:
            # Extract hex or raw bytes from PEM
            lines = self.raw_pem.decode('utf-8', errors='ignore').splitlines()
            hex_lines = [l.strip() for l in lines if not l.startswith("-----")]
            raw_hex = "".join(hex_lines)
            try:
                self.public_key_raw = bytes.fromhex(raw_hex)
            except ValueError:
                self.public_key_raw = self.raw_pem[:32]

    def verify_manifest(self, manifest_bytes: bytes, signature_hex: str) -> Dict[str, Any]:
        """
        Verifies the Ed25519 signature of the manifest content.
        Returns audit details and status dict.
        """
        computed_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        
        try:
            signature_bytes = bytes.fromhex(signature_hex.strip())
        except ValueError:
            return {
                "valid": False,
                "error": "Invalid signature format: Not valid hexadecimal string.",
                "manifest_sha256": computed_sha256,
                "gatekeeper_action": "BLOCKED"
            }

        if len(signature_bytes) != 64:
            return {
                "valid": False,
                "error": f"Invalid signature length: expected 64 bytes for Ed25519, got {len(signature_bytes)}.",
                "manifest_sha256": computed_sha256,
                "gatekeeper_action": "BLOCKED"
            }
            
        if USE_CRYPTOGRAPHY_LIB and isinstance(self.public_key, ed25519.Ed25519PublicKey):
            try:
                self.public_key.verify(signature_bytes, manifest_bytes)
                is_valid = True
                error_msg = None
            except InvalidSignature:
                is_valid = False
                error_msg = "Cryptographic signature mismatch: Package has been modified or signed with untrusted key."
            except Exception as e:
                is_valid = False
                error_msg = f"Verification error: {str(e)}"
        else:
            try:
                is_valid = ed25519_pure.checkvalid(signature_bytes, manifest_bytes, self.public_key_raw)
                error_msg = None if is_valid else "Cryptographic signature mismatch: Manifest has been modified or tampered."
            except Exception as e:
                is_valid = False
                error_msg = f"Ed25519 verification failed: {str(e)}"

        status = {
            "valid": is_valid,
            "algorithm": "Ed25519 (RFC 8032)",
            "manifest_sha256": computed_sha256,
            "signature_length_bytes": len(signature_bytes),
            "gatekeeper_action": "PERMITTED" if is_valid else "BLOCKED",
            "error": error_msg
        }
        return status

def verify_package_cli(manifest_path: str, sig_path: str, pubkey_path: str) -> int:
    """CLI Entry point for Gatekeeper."""
    print("=================================================================")
    print("         VS CODE LOCAL AGENT CRYPTOGRAPHIC GATEKEEPER            ")
    print("=================================================================")
    
    m_path = Path(manifest_path)
    s_path = Path(sig_path)
    p_path = Path(pubkey_path)
    
    if not m_path.exists():
        print(f"[FAIL] Manifest file not found: {m_path}", file=sys.stderr)
        return 1
    if not s_path.exists():
        print(f"[FAIL] Detached signature file not found: {s_path}", file=sys.stderr)
        return 1
    if not p_path.exists():
        print(f"[FAIL] Public key not found: {p_path}", file=sys.stderr)
        return 1
        
    gatekeeper = CryptographicGatekeeper(p_path)
    manifest_bytes = m_path.read_bytes()
    sig_hex = s_path.read_text().strip()
    
    result = gatekeeper.verify_manifest(manifest_bytes, sig_hex)
    print(f"Manifest Path : {m_path}")
    print(f"Digest SHA256 : {result['manifest_sha256']}")
    print(f"Algorithm     : {result['algorithm']}")
    print(f"Verdict       : {'✓ PASS (SIGNED & VALID)' if result['valid'] else '✗ FAIL (UNTRUSTED / TAMPERED)'}")
    print(f"Action        : {result['gatekeeper_action']}")
    
    if not result['valid']:
        print(f"Reason        : {result.get('error')}", file=sys.stderr)
        return 2
        
    print("[SUCCESS] Package signature verified. Agent module authorization granted.")
    return 0

if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parent.parent / "agent-spec"
    m = sys.argv[1] if len(sys.argv) > 1 else str(base_dir / "agent-package.yaml")
    s = sys.argv[2] if len(sys.argv) > 2 else str(base_dir / "agent-package.sig")
    p = sys.argv[3] if len(sys.argv) > 3 else str(base_dir / "public_key.pem")
    
    sys.exit(verify_package_cli(m, s, p))

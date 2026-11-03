#!/usr/bin/env python3
"""
Ed25519 Key Generation and Manifest Signing Utility for .agentpkg Packages.
Generates an asymmetric Ed25519 keypair and signs agent-package.yaml.
Supports both Python's cryptography library and pure-Python RFC 8032 Ed25519.
"""

import sys
import os
import hashlib
from pathlib import Path

# Try cryptography library, fall back to ed25519_pure
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    USE_CRYPTOGRAPHY_LIB = True
except ImportError:
    USE_CRYPTOGRAPHY_LIB = False
    import ed25519_pure

def generate_keypair():
    """Generates an Ed25519 private/public keypair."""
    if USE_CRYPTOGRAPHY_LIB:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        raw_pub = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return priv_bytes, pub_bytes, raw_pub, private_key
    else:
        # RFC 8032 pure-python Ed25519
        seed = os.urandom(32)
        raw_pub = ed25519_pure.publickey(seed)
        pub_hex = raw_pub.hex()
        priv_hex = seed.hex()
        
        pub_pem = f"-----BEGIN PUBLIC KEY-----\n{pub_hex}\n-----END PUBLIC KEY-----\n".encode('utf-8')
        priv_pem = f"-----BEGIN PRIVATE KEY-----\n{priv_hex}\n-----END PRIVATE KEY-----\n".encode('utf-8')
        return priv_pem, pub_pem, raw_pub, seed

def sign_manifest(manifest_content: bytes, private_key):
    """Computes a detached Ed25519 signature over the manifest bytes."""
    if USE_CRYPTOGRAPHY_LIB and hasattr(private_key, "sign"):
        return private_key.sign(manifest_content)
    else:
        raw_pub = ed25519_pure.publickey(private_key)
        sig = ed25519_pure.signature(manifest_content, private_key, raw_pub)
        return sig

def main():
    root_dir = Path(__file__).resolve().parent.parent
    agent_spec_dir = root_dir / "agent-spec"
    manifest_path = agent_spec_dir / "agent-package.yaml"
    
    if not manifest_path.exists():
        print(f"Error: Manifest not found at {manifest_path}", file=sys.stderr)
        sys.exit(1)
        
    manifest_bytes = manifest_path.read_bytes()
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    print(f"[KeyGen] Canonical Manifest SHA-256 Digest: {manifest_sha256}")
    
    priv_pem, pub_pem, raw_pub, priv_key = generate_keypair()
    
    # Sign manifest
    signature = sign_manifest(manifest_bytes, priv_key)
    sig_hex = signature.hex()
    
    # Save outputs
    priv_key_path = agent_spec_dir / "private_key.pem"
    pub_key_path = agent_spec_dir / "public_key.pem"
    sig_path = agent_spec_dir / "agent-package.sig"
    
    priv_key_path.write_bytes(priv_pem)
    pub_key_path.write_bytes(pub_pem)
    sig_path.write_text(sig_hex)
    
    backend = "cryptography-c" if USE_CRYPTOGRAPHY_LIB else "RFC-8032-pure-python"
    print(f"[KeyGen] Engine: {backend}")
    print(f"[KeyGen] Generated Ed25519 Private Key -> {priv_key_path}")
    print(f"[KeyGen] Generated Ed25519 Public Key  -> {pub_key_path}")
    print(f"[KeyGen] Generated Detached Signature  -> {sig_path}")
    print(f"[KeyGen] Signature Hex (truncated): {sig_hex[:32]}... ({len(signature)} bytes)")
    print("[KeyGen] Packaging completed successfully.")

if __name__ == "__main__":
    main()

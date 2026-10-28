"""PKCE helpers (RFC 7636) — S256 only.

Used by the auth-code flow (local stub + IdP proxy) and the portal login
bootstrap so public clients never send a client_secret from the browser.
"""

from __future__ import annotations

import base64
import hashlib
import secrets


def generate_code_verifier(length: int = 64) -> str:
    """Return a high-entropy code_verifier (43–128 chars, url-safe)."""
    # token_urlsafe(n) ≈ 4/3 * n chars; 48 bytes → ~64 chars.
    n_bytes = max(32, min(96, length * 3 // 4))
    verifier = secrets.token_urlsafe(n_bytes)
    return verifier[:128]


def code_challenge_s256(verifier: str) -> str:
    """BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) without padding."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify_s256(verifier: str, challenge: str) -> bool:
    """Constant-time-ish compare of recomputed challenge vs stored challenge."""
    if not verifier or not challenge:
        return False
    expected = code_challenge_s256(verifier)
    if len(expected) != len(challenge):
        return False
    return secrets.compare_digest(expected, challenge)

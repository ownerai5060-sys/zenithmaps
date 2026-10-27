"""OAuth2 client-credentials stub (production-readiness slice).

Design
------
- Grant type: ``client_credentials`` only (machine-to-machine).
- ``client_id`` / ``client_secret`` map to an active API key's ``key_id`` /
  ``secret`` (same registry as ``X-API-Key``).
- Issued tokens are **opaque** (random), stored in-process with TTL — not JWT.
- Clients may call protected routes with ``Authorization: Bearer <token>``
  *or* continue using ``X-API-Key``.
- This is intentionally a stub: no refresh tokens, no authorization code,
  no external IdP. Replace with a real OIDC provider before production SLA.

Endpoint: ``POST /oauth/token`` (form or JSON).
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass

from api.keystore import StoredKey, get_keystore


@dataclass(frozen=True)
class AccessToken:
    token: str
    key_id: str
    scopes: frozenset[str]
    label: str
    expires_at: float

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at


class TokenStore:
    """In-memory opaque bearer tokens."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tokens: dict[str, AccessToken] = {}

    def reset(self) -> None:
        with self._lock:
            self._tokens.clear()

    def issue(
        self,
        stored: StoredKey,
        *,
        expires_in_s: int,
    ) -> AccessToken:
        token = secrets.token_urlsafe(32)
        access = AccessToken(
            token=token,
            key_id=stored.key_id,
            scopes=stored.scopes,
            label=stored.label,
            expires_at=time.time() + max(60, expires_in_s),
        )
        with self._lock:
            self._tokens[token] = access
        return access

    def lookup(self, token: str) -> AccessToken | None:
        with self._lock:
            access = self._tokens.get(token)
            if access is None:
                return None
            if access.expired:
                del self._tokens[token]
                return None
            return access

    def revoke_for_key(self, key_id: str) -> int:
        """Drop all tokens issued for a revoked API key."""
        with self._lock:
            doomed = [t for t, a in self._tokens.items() if a.key_id == key_id]
            for t in doomed:
                del self._tokens[t]
            return len(doomed)


_TOKEN_STORE = TokenStore()


def get_token_store() -> TokenStore:
    return _TOKEN_STORE


def issue_client_credentials_token(
    client_id: str,
    client_secret: str,
    *,
    expires_in_s: int = 3600,
    requested_scope: str | None = None,
) -> AccessToken | None:
    """Validate client credentials against the key store and issue a token."""
    store = get_keystore()
    stored = store.get(client_id)
    if stored is None or stored.revoked:
        return None
    if len(stored.secret) != len(client_secret) or not secrets.compare_digest(
        stored.secret, client_secret
    ):
        return None
    if requested_scope:
        needed = {s for s in requested_scope.split() if s}
        if not needed.issubset(stored.scopes):
            return None
    return get_token_store().issue(stored, expires_in_s=expires_in_s)

"""OAuth2 token stubs: client_credentials + auth-code/refresh (local or IdP).

Design
------
- ``client_credentials``: machine-to-machine against the API-key registry
  (opaque Bearer tokens, in-process TTL).
- ``authorization_code`` / ``refresh_token``:
  - When ``ZENITH_OIDC_TOKEN_URL`` is set, the token endpoint **proxies** to the
    external IdP (real auth-code / refresh exchange).
  - Otherwise a **local stub** issues opaque access + refresh tokens so demos
    and tests work without an IdP.
- ``GET /oauth/authorize`` redirects to ``ZENITH_OIDC_AUTHORIZE_URL`` when set;
  otherwise issues a one-time stub authorization code and redirects (or returns
  JSON when ``redirect_uri`` is omitted).

Clients may call protected routes with ``Authorization: Bearer <token>``
*or* continue using ``X-API-Key``. Prefer a real IdP (JWKS + auth-code) before
production SLA.
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


@dataclass(frozen=True)
class RefreshToken:
    token: str
    key_id: str
    scopes: frozenset[str]
    label: str
    expires_at: float

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at


@dataclass(frozen=True)
class AuthCode:
    code: str
    key_id: str
    scopes: frozenset[str]
    label: str
    redirect_uri: str
    expires_at: float
    used: bool = False

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at


@dataclass(frozen=True)
class IssuedTokenPair:
    access: AccessToken
    refresh: RefreshToken | None
    expires_in_s: int


class TokenStore:
    """In-memory opaque bearer + refresh + auth-code registry."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tokens: dict[str, AccessToken] = {}
        self._refresh: dict[str, RefreshToken] = {}
        self._codes: dict[str, AuthCode] = {}

    def reset(self) -> None:
        with self._lock:
            self._tokens.clear()
            self._refresh.clear()
            self._codes.clear()

    def issue(
        self,
        stored: StoredKey,
        *,
        expires_in_s: int,
        with_refresh: bool = False,
        refresh_expires_in_s: int = 86400,
        scopes: frozenset[str] | None = None,
    ) -> IssuedTokenPair:
        scope_set = scopes if scopes is not None else stored.scopes
        token = secrets.token_urlsafe(32)
        access = AccessToken(
            token=token,
            key_id=stored.key_id,
            scopes=scope_set,
            label=stored.label,
            expires_at=time.time() + max(60, expires_in_s),
        )
        refresh: RefreshToken | None = None
        with self._lock:
            self._tokens[token] = access
            if with_refresh:
                rtok = secrets.token_urlsafe(32)
                refresh = RefreshToken(
                    token=rtok,
                    key_id=stored.key_id,
                    scopes=scope_set,
                    label=stored.label,
                    expires_at=time.time() + max(300, refresh_expires_in_s),
                )
                self._refresh[rtok] = refresh
        return IssuedTokenPair(
            access=access, refresh=refresh, expires_in_s=max(60, expires_in_s)
        )

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
            r_doomed = [t for t, a in self._refresh.items() if a.key_id == key_id]
            for t in r_doomed:
                del self._refresh[t]
            return len(doomed) + len(r_doomed)

    def issue_auth_code(
        self,
        stored: StoredKey,
        *,
        redirect_uri: str,
        ttl_s: int = 300,
        scopes: frozenset[str] | None = None,
    ) -> AuthCode:
        code = secrets.token_urlsafe(24)
        auth = AuthCode(
            code=code,
            key_id=stored.key_id,
            scopes=scopes if scopes is not None else stored.scopes,
            label=stored.label,
            redirect_uri=redirect_uri or "",
            expires_at=time.time() + max(60, ttl_s),
        )
        with self._lock:
            self._codes[code] = auth
        return auth

    def consume_auth_code(
        self, code: str, *, redirect_uri: str | None = None
    ) -> AuthCode | None:
        with self._lock:
            auth = self._codes.get(code)
            if auth is None or auth.used or auth.expired:
                if auth is not None:
                    del self._codes[code]
                return None
            if redirect_uri is not None and auth.redirect_uri:
                if redirect_uri != auth.redirect_uri:
                    return None
            # Mark used by replacing with used=True copy then delete.
            del self._codes[code]
            return AuthCode(
                code=auth.code,
                key_id=auth.key_id,
                scopes=auth.scopes,
                label=auth.label,
                redirect_uri=auth.redirect_uri,
                expires_at=auth.expires_at,
                used=True,
            )

    def consume_refresh(
        self,
        refresh_token: str,
        *,
        expires_in_s: int,
        refresh_expires_in_s: int = 86400,
    ) -> IssuedTokenPair | None:
        with self._lock:
            old = self._refresh.pop(refresh_token, None)
            if old is None or old.expired:
                return None
        # Re-issue against current key state.
        stored = get_keystore().get(old.key_id)
        if stored is None or stored.revoked:
            return None
        # Intersect scopes in case the key was narrowed.
        scopes = frozenset(old.scopes & stored.scopes) or stored.scopes
        return self.issue(
            stored,
            expires_in_s=expires_in_s,
            with_refresh=True,
            refresh_expires_in_s=refresh_expires_in_s,
            scopes=scopes,
        )


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
    scopes = stored.scopes
    if requested_scope:
        needed = {s for s in requested_scope.split() if s}
        if not needed.issubset(stored.scopes):
            return None
        scopes = frozenset(needed)
    pair = get_token_store().issue(
        stored, expires_in_s=expires_in_s, with_refresh=False, scopes=scopes
    )
    return pair.access


def issue_stub_authorization_code(
    client_id: str,
    *,
    redirect_uri: str = "",
    requested_scope: str | None = None,
) -> AuthCode | None:
    """Local stub: mint a one-time code for an active API key (client_id=key_id)."""
    stored = get_keystore().get(client_id)
    if stored is None or stored.revoked:
        return None
    scopes = stored.scopes
    if requested_scope:
        needed = {s for s in requested_scope.split() if s}
        if not needed.issubset(stored.scopes):
            return None
        scopes = frozenset(needed)
    return get_token_store().issue_auth_code(
        stored, redirect_uri=redirect_uri, scopes=scopes
    )


def exchange_stub_authorization_code(
    code: str,
    *,
    redirect_uri: str | None = None,
    expires_in_s: int = 3600,
    refresh_expires_in_s: int = 86400,
) -> IssuedTokenPair | None:
    auth = get_token_store().consume_auth_code(code, redirect_uri=redirect_uri)
    if auth is None:
        return None
    stored = get_keystore().get(auth.key_id)
    if stored is None or stored.revoked:
        return None
    return get_token_store().issue(
        stored,
        expires_in_s=expires_in_s,
        with_refresh=True,
        refresh_expires_in_s=refresh_expires_in_s,
        scopes=auth.scopes,
    )

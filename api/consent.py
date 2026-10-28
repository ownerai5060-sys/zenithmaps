"""Local-stub OAuth consent screen helpers.

When ``ZENITH_OAUTH_CONSENT_ENABLED`` is true (default) and the local stub
authorize path has a ``redirect_uri``, the authorize endpoint parks a pending
consent and returns a minimal HTML approve/deny form instead of immediately
redirecting with a code. Real IdP authorize redirects are unchanged (consent
lives at the IdP).
"""

from __future__ import annotations

import html
import secrets
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlencode


@dataclass(frozen=True)
class PendingConsent:
    pending_id: str
    client_id: str
    redirect_uri: str
    scope: str
    state: str
    code_challenge: str
    code_challenge_method: str
    expires_at: float

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at


class ConsentStore:
    """Short-lived in-memory pending consents (single-process OK for stub)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: dict[str, PendingConsent] = {}

    def reset(self) -> None:
        with self._lock:
            self._pending.clear()

    def create(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        scope: str = "",
        state: str = "",
        code_challenge: str = "",
        code_challenge_method: str = "",
        ttl_s: int = 600,
    ) -> PendingConsent:
        pending = PendingConsent(
            pending_id=secrets.token_urlsafe(24),
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope or "",
            state=state or "",
            code_challenge=code_challenge or "",
            code_challenge_method=code_challenge_method or "",
            expires_at=time.time() + max(60, ttl_s),
        )
        with self._lock:
            self._pending[pending.pending_id] = pending
        return pending

    def get(self, pending_id: str) -> PendingConsent | None:
        with self._lock:
            rec = self._pending.get(pending_id)
            if rec is None:
                return None
            if rec.expired:
                del self._pending[pending_id]
                return None
            return rec

    def consume(self, pending_id: str) -> PendingConsent | None:
        with self._lock:
            rec = self._pending.pop(pending_id, None)
            if rec is None or rec.expired:
                return None
            return rec


_CONSENT = ConsentStore()


def get_consent_store() -> ConsentStore:
    return _CONSENT


def render_consent_html(pending: PendingConsent) -> str:
    """Minimal local consent stub (approve / deny)."""
    client = html.escape(pending.client_id)
    scopes = html.escape(pending.scope or "(default key scopes)")
    redirect = html.escape(pending.redirect_uri)
    pid = html.escape(pending.pending_id)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Zenith — Authorize application</title>
  <style>
    :root {{ color-scheme: light; }}
    body {{
      font-family: "Segoe UI", system-ui, sans-serif;
      max-width: 28rem;
      margin: 3rem auto;
      padding: 0 1rem;
      line-height: 1.45;
      color: #1a1a1a;
      background: #f7f5f1;
    }}
    h1 {{ font-size: 1.35rem; margin-bottom: 0.35rem; }}
    .card {{
      background: #fff;
      border: 1px solid #ddd4c6;
      padding: 1.25rem 1.4rem;
    }}
    dl {{ margin: 1rem 0; }}
    dt {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em;
         color: #666; }}
    dd {{ margin: 0 0 0.75rem 0; word-break: break-all; }}
    .actions {{ display: flex; gap: 0.75rem; margin-top: 1.25rem; }}
    button {{
      flex: 1;
      padding: 0.65rem 0.75rem;
      border: 1px solid #333;
      background: #1a1a1a;
      color: #fff;
      font: inherit;
      cursor: pointer;
    }}
    button.deny {{ background: #fff; color: #1a1a1a; }}
    .note {{ font-size: 0.85rem; color: #555; margin-top: 1rem; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>Authorize application</h1>
    <p>Local OAuth stub consent (not a production IdP screen).</p>
    <dl>
      <dt>Client</dt><dd>{client}</dd>
      <dt>Scopes</dt><dd>{scopes}</dd>
      <dt>Redirect</dt><dd>{redirect}</dd>
    </dl>
    <form method="post" action="/oauth/consent" class="actions">
      <input type="hidden" name="pending_id" value="{pid}"/>
      <button type="submit" name="decision" value="deny" class="deny">Deny</button>
      <button type="submit" name="decision" value="approve">Allow</button>
    </form>
    <p class="note">Disable with <code>ZENITH_OAUTH_CONSENT_ENABLED=false</code>
    for non-interactive local redirects. Real IdP consent happens at the IdP.</p>
  </div>
</body>
</html>
"""


def redirect_with_error(redirect_uri: str, *, error: str, state: str = "") -> str:
    params = {"error": error}
    if state:
        params["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return f"{redirect_uri}{sep}{urlencode(params)}"


def redirect_with_code(
    redirect_uri: str, *, code: str, state: str = ""
) -> str:
    params = {"code": code}
    if state:
        params["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return f"{redirect_uri}{sep}{urlencode(params)}"

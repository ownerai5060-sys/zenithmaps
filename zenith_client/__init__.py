"""Shared Zenith Platform API client used by Streamlit UI and examples (S6)."""

from zenith_client.api import ZenithApiClient, ZenithApiError
from zenith_client.sso_bridge import (
    ResolvedAuth,
    resolve_streamlit_auth,
    shared_cookie_domain_docs,
)

__all__ = [
    "ZenithApiClient",
    "ZenithApiError",
    "ResolvedAuth",
    "resolve_streamlit_auth",
    "shared_cookie_domain_docs",
]

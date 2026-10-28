"""Streamlit operator page: create / list / revoke API keys via admin API."""

from __future__ import annotations

import streamlit as st

from zenith_client import ZenithApiClient, ZenithApiError

st.set_page_config(layout="wide", page_title="Zenith API Keys")

st.title("API Key Portal")
st.markdown(
    """
Minimal operator UI for **create / list / revoke** against
`/api/v1/admin/keys` (scope `admin:keys`).
The same portal is also available as static HTML at
`/admin/key-portal` when the API is running.
Secrets are returned **once** on create — store them in a secret manager.
"""
)

base_url = st.sidebar.text_input("API base URL", value="http://127.0.0.1:8000")
admin_key = st.sidebar.text_input(
    "Admin API key",
    value="zenith_admin_key_manage",
    type="password",
)
include_revoked = st.sidebar.checkbox("Include revoked", value=False)
st.sidebar.caption(
    "Demo admin key is for local/sandbox only. "
    "Prefer `ZENITH_KEY_VAULT_PATH` so creates survive restart."
)

client = ZenithApiClient(base_url=base_url, api_key=admin_key)

try:
    health = client.healthz(check_upstreams=False)
    st.success(
        f"API status **{health.get('status')}** "
        f"(package {health.get('package_version', '?')})"
    )
except ZenithApiError as exc:
    st.error(
        f"Cannot reach API at `{base_url}`: {exc}. "
        "Start it with `uvicorn api.main:app --port 8000`."
    )
    st.stop()

st.subheader("Create key")
with st.form("create_key"):
    col_a, col_b = st.columns(2)
    with col_a:
        key_id = st.text_input("key_id (optional)", value="")
    with col_b:
        label = st.text_input("label", value="")
    scopes_raw = st.text_input("scopes (comma-separated)", value="layers:read")
    submitted = st.form_submit_button("Create")

if submitted:
    scopes = [s.strip() for s in scopes_raw.split(",") if s.strip()]
    try:
        created = client.create_api_key(
            key_id=key_id or None,
            scopes=scopes,
            label=label,
        )
        st.warning("Store this secret now — it will not be shown again.")
        st.code(created.get("secret", ""), language="text")
        st.json(
            {
                "key_id": created.get("key_id"),
                "scopes": created.get("scopes"),
                "label": created.get("label"),
                "created_at": created.get("created_at"),
            }
        )
    except ZenithApiError as exc:
        st.error(f"Create failed: {exc}")

st.subheader("Keys")
try:
    listing = client.list_api_keys(include_revoked=include_revoked)
except ZenithApiError as exc:
    st.error(f"List failed (need admin:keys): {exc}")
    st.stop()

items = listing.get("items") or []
st.caption(f"{listing.get('count', len(items))} key(s)")
if not items:
    st.info("No keys returned.")
else:
    for item in items:
        cols = st.columns([2, 3, 2, 1, 1])
        cols[0].markdown(f"`{item.get('key_id')}`")
        cols[1].write(", ".join(item.get("scopes") or []))
        cols[2].write(item.get("label") or "—")
        cols[3].write("revoked" if item.get("revoked") else "active")
        if not item.get("revoked"):
            if cols[4].button("Revoke", key=f"revoke-{item.get('key_id')}"):
                try:
                    client.revoke_api_key(str(item.get("key_id")))
                    st.rerun()
                except ZenithApiError as exc:
                    st.error(f"Revoke failed: {exc}")

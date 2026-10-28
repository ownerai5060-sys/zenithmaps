"""Streamlit page that consumes the Zenith platform API catalog (S6)."""

from __future__ import annotations

import streamlit as st

from zenith_client import ZenithApiClient, ZenithApiError

st.set_page_config(layout="wide")

st.title("Zenith API Catalog")
st.markdown(
    """
This page is a **thin client** of the platform API (`/api/v1`). It lists
allowlisted layers and shows structured legend JSON — the same contract
external apps should use.
"""
)

base_url = st.sidebar.text_input(
    "API base URL", value="http://127.0.0.1:8000"
)
api_key = st.sidebar.text_input(
    "API key", value="zenith_demo_key_layers_read", type="password"
)
st.sidebar.caption("Demo key only — override via env `ZENITH_API_KEY` in real deploys.")

client = ZenithApiClient(base_url=base_url, api_key=api_key)

try:
    health = client.healthz(check_upstreams=False)
    st.success(
        f"API `{health.get('service')}` status **{health.get('status')}** "
        f"(version {health.get('api_version')})"
    )
except ZenithApiError as exc:
    st.error(
        f"Cannot reach API at `{base_url}`: {exc}. "
        "Start it with `uvicorn api.main:app --port 8000`."
    )
    st.stop()

try:
    listing = client.list_layers()
except ZenithApiError as exc:
    st.error(f"Failed to list layers: {exc}")
    st.stop()

st.subheader(f"Layers ({listing.get('count', 0)})")
items = listing.get("items") or []
if not items:
    st.info("Catalog is empty.")
    st.stop()

labels = {f"{item['id']} — {item['title']}": item["id"] for item in items}
choice = st.selectbox("Select a layer", list(labels.keys()))
layer_id = labels[choice]

col1, col2 = st.columns(2)
with col1:
    st.markdown("#### Metadata")
    try:
        detail = client.get_layer(layer_id)
        st.json(detail)
    except ZenithApiError as exc:
        st.error(str(exc))

with col2:
    st.markdown("#### Legend JSON")
    try:
        legend = client.get_legend(layer_id)
        st.json(legend)
        if legend.get("get_legend_graphic_url"):
            st.markdown("**Upstream GetLegendGraphic**")
            st.code(legend["get_legend_graphic_url"], language="text")
        if legend.get("legend_image_path"):
            st.caption(
                f"Proxied image path: `{legend['legend_image_path']}` "
                "(requires API key; open via HTTP client, not bare browser)."
            )
    except ZenithApiError as exc:
        st.warning(f"Legend unavailable: {exc}")

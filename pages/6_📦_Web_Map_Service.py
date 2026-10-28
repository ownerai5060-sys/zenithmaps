import ast

import streamlit as st
import leafmap.foliumap as leafmap

from zenith_client import ZenithApiClient, ZenithApiError

st.set_page_config(layout="wide")

markdown = """
Zenith Maps — WMS demo. Official catalog layers and legends are loaded from
the platform API (`/api/v1`) when available; otherwise the page falls back to
leafmap builtins.
"""

st.sidebar.title("About")
st.sidebar.info(markdown)
logo = "https://i.imgur.com/UbOXYAU.png"
st.sidebar.image(logo)


@st.cache_data(show_spinner=False)
def get_layers(url):
    options = leafmap.get_wms_layers(url)
    return options


@st.cache_data(show_spinner=False, ttl=60)
def fetch_api_legend_dict(layer_id: str):
    """Pull structured legend from Zenith API and convert to leafmap dict."""
    client = ZenithApiClient()
    return client.legend_entries_as_dict(layer_id)


@st.cache_data(show_spinner=False, ttl=60)
def fetch_api_catalog():
    client = ZenithApiClient()
    return client.list_layers()


def resolve_catalog_layer_id(url: str, layer_name: str) -> str | None:
    """Map a selected WMS layer to a Zenith catalog id when possible."""
    client = ZenithApiClient()
    try:
        return client.find_layer_id_for_wms(url, layer_name)
    except ZenithApiError:
        return None


st.title("Web Map Service (WMS)")
st.markdown(
    """
This app is a demonstration of loading Web Map Service (WMS) layers. Simply enter the URL of the WMS service
in the text box below and press Enter to retrieve the layers. Official Zenith catalog layers
(e.g. ESA WorldCover) use **legend JSON from the platform API** when the API is running.
"""
)

# Show API connectivity status (non-blocking).
api_status = "unreachable"
try:
    health = ZenithApiClient().healthz(check_upstreams=False)
    api_status = health.get("status", "ok")
    catalog = fetch_api_catalog()
    st.caption(
        f"Platform API: **{api_status}** — "
        f"{catalog.get('count', 0)} catalog layer(s) available via `/api/v1`."
    )
except ZenithApiError as exc:
    st.caption(
        f"Platform API offline ({exc}). Legends fall back to leafmap builtins. "
        "Start with `uvicorn api.main:app --port 8000`."
    )
except Exception as exc:  # pragma: no cover - UI resilience
    st.caption(f"Platform API offline ({type(exc).__name__}). Using local fallbacks.")

row1_col1, row1_col2 = st.columns([3, 1.3])
width = None
height = 600
layers = None
# Always initialize before branching (avoids NameError when URL cleared).
add_legend = False
legend_text = ""

with row1_col2:

    esa_landcover = "https://services.terrascope.be/wms/v2"
    url = st.text_input(
        "Enter a WMS URL:", value="https://services.terrascope.be/wms/v2"
    )
    empty = st.empty()

    if url:
        options = get_layers(url)

        default = None
        if url == esa_landcover:
            default = "WORLDCOVER_2020_MAP"
        layers = empty.multiselect(
            "Select WMS layers to add to the map:", options, default=default
        )
        add_legend = st.checkbox("Add a legend to the map", value=True)

        # Prefer API legend for the first selected catalog layer (S6).
        legend = ""
        api_legend_source = None
        if layers:
            for layer_name in layers:
                layer_id = resolve_catalog_layer_id(url, layer_name)
                if layer_id:
                    try:
                        legend_dict = fetch_api_legend_dict(layer_id)
                        if legend_dict:
                            legend = str(legend_dict)
                            api_legend_source = layer_id
                            break
                    except ZenithApiError:
                        pass
        if not legend and default == "WORLDCOVER_2020_MAP":
            legend = str(leafmap.builtin_legends["ESA_WorldCover"])

        if add_legend:
            help_txt = (
                f"Loaded from API layer `{api_legend_source}`."
                if api_legend_source
                else "Enter a legend as a dictionary {label: color}"
            )
            legend_text = st.text_area(
                "Enter a legend as a dictionary {label: color}",
                value=legend,
                height=200,
                help=help_txt,
            )

    with row1_col1:
        m = leafmap.Map(center=(36.3, 0), zoom=2)

        if layers is not None:
            for layer in layers:
                m.add_wms_layer(
                    url, layers=layer, name=layer, attribution=" ", transparent=True
                )
        if add_legend and legend_text:
            legend_dict = ast.literal_eval(legend_text)
            m.add_legend(legend_dict=legend_dict)

        m.to_streamlit(width, height)

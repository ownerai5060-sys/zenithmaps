# zenith-maps (Python SDK starter)

Thin official client for the Zenith Maps Platform API (`/api/v1`).

```bash
pip install -e sdk/python
```

```python
from zenith_maps import ZenithMapsClient

with ZenithMapsClient(
    base_url="http://127.0.0.1:8000",
    api_key="zenith_demo_key_layers_read",
) as client:
    print(client.list_layers())
    print(client.get_features("esa-worldcover-2020", limit=5))
    print(client.list_tiles())
```

This is a starter, not a full OpenAPI-generated SDK. See `/docs` on a running API
and `scripts/export_openapi_collection.py` for Postman/OpenAPI exports.

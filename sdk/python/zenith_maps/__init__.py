"""Thin official Python SDK starter for the Zenith Maps Platform API (N2).

Install from this tree (editable)::

    pip install -e sdk/python

Or copy ``zenith_maps`` onto ``PYTHONPATH``. Requires ``httpx``.
"""

from zenith_maps.client import ZenithMapsClient

__all__ = ["ZenithMapsClient"]
__version__ = "0.5.0"

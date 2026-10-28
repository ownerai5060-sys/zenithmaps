"""Optional OpenTelemetry wiring (env-driven).

Enable with ``ZENITH_OTEL_ENABLED=true``. Requires optional packages:

* ``opentelemetry-api``
* ``opentelemetry-sdk``
* ``opentelemetry-exporter-otlp`` (when an endpoint is set)
* ``opentelemetry-instrumentation-fastapi``

When packages or the exporter endpoint are missing, startup continues without
tracing — this is intentional soft-fail for local/demo environments.
"""

from __future__ import annotations

import logging
from typing import Any

from api.config import Settings

logger = logging.getLogger("zenith.api.otel")


def setup_otel(app: Any, settings: Settings) -> bool:
    """Instrument ``app`` if OTel is enabled and dependencies are present.

    Returns True when instrumentation was applied.
    """
    if not settings.otel_enabled:
        return False
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    except ImportError:
        logger.warning(
            "ZENITH_OTEL_ENABLED=true but OpenTelemetry SDK is not installed; "
            "skipping (pip install opentelemetry-api opentelemetry-sdk "
            "opentelemetry-exporter-otlp opentelemetry-instrumentation-fastapi)"
        )
        return False

    resource = Resource.create({"service.name": settings.otel_service_name})
    provider = TracerProvider(resource=resource)

    endpoint = settings.otel_exporter_otlp_endpoint
    if endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )

            exporter = OTLPSpanExporter(endpoint=endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            logger.info("OTel OTLP exporter → %s", endpoint)
        except ImportError:
            logger.warning(
                "OTLP exporter package missing; using console exporter fallback"
            )
            provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    else:
        logger.info("OTel enabled without OTLP endpoint; using console exporter")
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    trace.set_tracer_provider(provider)

    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app)
    except ImportError:
        logger.warning(
            "opentelemetry-instrumentation-fastapi missing; "
            "provider set but FastAPI not auto-instrumented"
        )
        return False

    logger.info("OpenTelemetry FastAPI instrumentation active")
    return True

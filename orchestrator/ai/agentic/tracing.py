"""Phoenix tracing setup — opt-in via `pip install -e .[tracing]`.

Não falha se as libs não estiverem instaladas — tracing é otimização, não dependência.
"""

from __future__ import annotations

import structlog

log = structlog.get_logger(__name__)


def setup_phoenix(endpoint: str) -> None:
    """Configura Phoenix + OpenInference para capturar spans LLM/tool use."""

    try:
        from openinference.instrumentation.litellm import LiteLLMInstrumentor
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as e:
        log.warning("phoenix.imports_missing", error=str(e))
        return

    resource = Resource.create({"service.name": "cai-orchestrator"})
    provider = TracerProvider(resource=resource)
    processor = BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint))
    provider.add_span_processor(processor)
    trace.set_tracer_provider(provider)

    LiteLLMInstrumentor().instrument()
    log.info("phoenix.instrumented", endpoint=endpoint)

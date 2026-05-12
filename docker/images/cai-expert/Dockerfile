FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*

# CAI framework + observabilidade
RUN pip install --no-cache-dir \
        cai-framework \
        litellm \
        arize-phoenix \
        openinference-instrumentation-litellm \
    || true

WORKDIR /app

ENV PYTHONUNBUFFERED=1

CMD ["python", "-c", "print('cai-expert idle. Use docker exec for ad-hoc agentic sessions.')"]

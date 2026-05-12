FROM python:3.14-slim AS base

# nmap dentro do orchestrator pra adapter funcionar mesmo sem kali-toolbox em ar.
# Para scanners pesados (nuclei, gitleaks, trufflehog, dnstwist) usamos o kali-toolbox.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        ca-certificates \
        curl \
        git \
    && rm -rf /var/lib/apt/lists/*

# uv para instalação rápida
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# instala dependências primeiro (camada cacheável)
COPY pyproject.toml /app/
RUN uv pip install --system --no-cache-dir \
        fastapi "uvicorn[standard]" pydantic pydantic-settings \
        sqlmodel aiosqlite asyncpg "sqlalchemy[asyncio]" alembic \
        httpx structlog litellm \
        python-libnmap zaproxy \
        arq redis \
        PyGithub shodan \
        python-gvm \
        authlib "python-jose[cryptography]" "passlib[bcrypt]" \
        jinja2 pyyaml \
        typer rich

COPY orchestrator /app/orchestrator
COPY alembic.ini /app/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080

ENTRYPOINT ["python", "-m", "orchestrator.cli"]
CMD ["--help"]

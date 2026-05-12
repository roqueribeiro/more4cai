"""Application config — pydantic-settings."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # AI
    LLM_MODEL: str = "anthropic/claude-opus-4-7"
    LLM_FALLBACK_MODEL: str = "anthropic/claude-haiku-4-5-20251001"
    # api_base aplicado quando o LLM_MODEL é OpenAI-compat local (LM Studio, Ollama OpenAI mode).
    # Vazio = não passa api_base, usa o default do provider (Anthropic/OpenAI cloud).
    LLM_API_BASE: str = ""
    # api_key específico para o backend local. LM Studio ignora — qualquer string serve.
    # Se vazio + LLM_API_BASE setado, fallback "lm-studio".
    LLM_API_KEY: str = ""
    # Aliases legados (mantidos por compatibilidade, não usados pelo gateway)
    LLM_LOCAL_BASE_URL: str = "http://ollama:11434/v1"
    LLM_LOCAL_MODEL: str = "ollama/qwen2.5:32b-instruct-q4_K_M"

    ANTHROPIC_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    OPENROUTER_API_KEY: str = ""

    # DB
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/cai.db"

    # Redis (Fase 2+)
    REDIS_URL: str = "redis://redis:6379/0"

    # Scanners
    ZAP_BASE_URL: str = "http://zap:8090"
    ZAP_API_KEY: str = ""
    TRIVY_SERVER_URL: str = "http://trivy:4954"

    # Greenbone (Fase 3, opt-in)
    GREENBONE_HOST: str = ""
    GREENBONE_PORT: int = 9390
    GREENBONE_USERNAME: str = "admin"
    GREENBONE_PASSWORD: str = ""

    # OSINT (Fase 2.5)
    GITHUB_TOKEN: str = ""
    SHODAN_API_KEY: str = ""
    CENSYS_API_ID: str = ""
    CENSYS_API_SECRET: str = ""

    # DefectDojo (Fase 5, opt-in)
    DEFECTDOJO_URL: str = ""
    DEFECTDOJO_API_KEY: str = ""

    # Phoenix tracing (Fase 4, opt-in)
    PHOENIX_COLLECTOR_ENDPOINT: str = "http://phoenix:6006/v1/traces"

    # API auth (token simples; pentester comercial num engagement)
    APP_TOKEN: str = "dev-changeme"   # token simples API; trocar em prod

    # OIDC (Fase 6 stub)
    OIDC_ISSUER: str = ""
    OIDC_CLIENT_ID: str = ""
    OIDC_CLIENT_SECRET: str = ""
    OIDC_REDIRECT_URI: str = ""

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    # Reports
    REPORTS_DIR: Path = Path("./reports")


settings = Settings()

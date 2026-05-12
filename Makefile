# CAI orchestrator — comandos de operação.
#
# Targets principais:
#   make up          - sobe orchestrator + workers + db + redis + ollama + scanners + lab
#   make api         - sobe só orchestrator + db + redis (sem scanners)
#   make down        - desce tudo
#   make build       - rebuild das imagens
#   make scan TARGET=... - dispara scan via CLI (síncrono, sem fila)
#   make scan-api TARGET_ID=... - dispara via API REST (assíncrono)
#   make exposure - dispara scan OSINT (Fase 2.5)
#   make smoke       - smoke test E2E
#   make migrate     - alembic upgrade head
#   make test        - pytest

SHELL := /usr/bin/env bash

# --env-file e --project-directory garantem que .env do CWD seja lido,
# mesmo com -f apontando pra docker/.
COMPOSE_FLAGS := --env-file .env --project-directory .
COMPOSE_BASE := docker compose $(COMPOSE_FLAGS) -f docker/compose.yml
COMPOSE_FULL := $(COMPOSE_BASE) -f docker/compose.scanners.yml -f docker/compose.lab.yml
COMPOSE_GREENBONE := $(COMPOSE_BASE) -f docker/compose.greenbone.yml
COMPOSE_OBS := $(COMPOSE_BASE) -f docker/compose.observability.yml
COMPOSE_AGENT := $(COMPOSE_BASE) -f docker/compose.agent.yml
COMPOSE_PROXY := $(COMPOSE_BASE) -f docker/compose.proxy.yml
COMPOSE_ALL := $(COMPOSE_FULL) -f docker/compose.observability.yml -f docker/compose.agent.yml

PROFILES_FULL := --profile default --profile scanners --profile lab
PROFILES_API := --profile default

TARGET ?= http://juice-shop:3000
TARGET_ID ?=

.PHONY: help build up api down logs ps shell scan scan-api smoke ollama-pull \
        migrate revision test lint exposure greenbone-up greenbone-down \
        obs-up agent-up backup proxy-up clean

help: ## lista de comandos
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk -F ':.*?## ' '{printf "  %-20s %s\n", $$1, $$2}'

build: ## rebuild das imagens (orchestrator, kali-toolbox, cai-expert)
	$(COMPOSE_FULL) build orchestrator worker
	$(COMPOSE_FULL) build kali-toolbox
	$(COMPOSE_AGENT) build cai-expert || true

up: ## sobe stack completa (orchestrator + workers + scanners + lab + ollama)
	$(COMPOSE_FULL) $(PROFILES_FULL) up -d
	@echo ""
	@echo "Stack no ar:"
	@echo "  orchestrator API : http://127.0.0.1:8080  (X-API-Token: \$$APP_TOKEN)"
	@echo "  zap              : http://127.0.0.1:8090"
	@echo "  trivy            : http://127.0.0.1:4954"
	@echo "  ollama           : http://127.0.0.1:11434"
	@echo "  juice-shop       : http://127.0.0.1:3000"
	@echo "  dvwa             : http://127.0.0.1:8000"

api: ## sobe só orchestrator + db + redis (modo API, sem scanners pesados)
	$(COMPOSE_BASE) $(PROFILES_API) up -d
	@echo ""
	@echo "API no ar: http://127.0.0.1:8080/health"

down: ## desce tudo
	$(COMPOSE_ALL) $(PROFILES_FULL) --profile greenbone --profile obs --profile ai-agent --profile proxy down

logs: ## logs do orchestrator
	$(COMPOSE_FULL) logs -f orchestrator worker

ps: ## status dos containers
	$(COMPOSE_FULL) ps

shell: ## shell no orchestrator
	$(COMPOSE_FULL) run --rm --entrypoint /bin/bash orchestrator

scan: ## dispara scan síncrono via CLI (TARGET=url)
	$(COMPOSE_FULL) run --rm orchestrator scan "$(TARGET)" --asset-type url --criticality medium $(EXTRA)

scan-api: ## dispara scan via API REST (TARGET_ID=uuid)
	@if [ -z "$(TARGET_ID)" ]; then echo "use TARGET_ID=<uuid>"; exit 1; fi
	curl -X POST http://127.0.0.1:8080/scans \
		-H "Content-Type: application/json" \
		-H "X-API-Token: $${APP_TOKEN:-dev-changeme}" \
		-d '{"target_id":"$(TARGET_ID)","scanners":["nmap","zap"]}'

scan-no-ai: ## scan sem AI (sem precisar de API key)
	$(COMPOSE_FULL) run --rm orchestrator scan "$(TARGET)" --asset-type url --skip-ai

exposure: ## scan OSINT/Exposure externa (configura via config/exposure_targets.yml)
	$(COMPOSE_FULL) run --rm orchestrator exposure $(EXTRA)

smoke: ## E2E: sobe lab e roda scan no Juice Shop
	@bash scripts/smoke.sh

migrate: ## alembic upgrade head
	$(COMPOSE_FULL) run --rm --entrypoint alembic orchestrator upgrade head

revision: ## cria nova migração (NAME=description)
	@if [ -z "$(NAME)" ]; then echo "use NAME=description"; exit 1; fi
	$(COMPOSE_FULL) run --rm --entrypoint alembic orchestrator revision --autogenerate -m "$(NAME)"

test: ## roda pytest
	$(COMPOSE_FULL) run --rm --entrypoint pytest orchestrator -q tests/

lint: ## ruff + mypy
	$(COMPOSE_FULL) run --rm --entrypoint sh orchestrator -c "ruff check orchestrator && mypy orchestrator"

ollama-pull: ## baixa modelos default no Ollama
	@bash scripts/ollama-bootstrap.sh

greenbone-up: ## sobe stack Greenbone (CUIDADO: feed sync 30min-3h, ~5GB)
	$(COMPOSE_GREENBONE) --profile greenbone up -d
	@echo "Greenbone subindo. Acompanhe sync com: docker logs cai-gvm-feeds -f"
	@echo "GSA web: https://127.0.0.1:9392 (admin/admin) — TROCAR senha após feed sync."

greenbone-down: ## desce stack Greenbone
	$(COMPOSE_GREENBONE) --profile greenbone down

obs-up: ## sobe Phoenix tracing
	$(COMPOSE_OBS) --profile obs up -d
	@echo "Phoenix UI: http://127.0.0.1:6006"

agent-up: ## sobe cai-expert (Fase 4 agentic)
	$(COMPOSE_AGENT) --profile ai-agent up -d

proxy-up: ## sobe Caddy TLS reverse proxy (Fase 6)
	$(COMPOSE_PROXY) --profile proxy up -d
	@echo "Caddy: https://cai.local/ (mapear cai.local → 127.0.0.1 no /etc/hosts)"

backup: ## backup de Postgres + reports + audit
	@bash scripts/backup.sh

clean: ## limpa volumes e reports (CUIDADO: apaga dados)
	$(COMPOSE_ALL) $(PROFILES_FULL) --profile greenbone --profile obs --profile ai-agent down -v
	rm -rf reports/* data/*

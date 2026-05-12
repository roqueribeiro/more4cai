---
name: cai-deploy
description: Deploy/promove a stack CAI pra ambiente de homologação ou produção. NÃO É AUTO-INVOCÁVEL — só roda se o usuário pedir explicitamente "/deploy" ou similar.
when_to_use: deploy, promoção de versão, release
argument-hint: "<environment: hml|prod> [--version=<git-sha>]"
disable-model-invocation: true
allowed-tools: Bash Read
---

# Skill: Deploy da stack CAI

Este skill **só é invocado quando o usuário pede explicitamente**. Não é auto-trigger porque deploy é decisão deliberada.

## Pré-condições

Antes de qualquer comando rodar:

1. **Backup recente**: último `make backup` < 24h.
2. **Testes verdes**: `make test` com 0 falhas.
3. **Lint limpo**: `make lint` sem erros.

Pergunte cada um. Se faltar, **PARE** e oriente.

## 1. Verificar versão e diff

```bash
git fetch origin
git log --oneline HEAD..origin/main | head -20
git diff HEAD origin/main --stat
```

Confirmar com o usuário:
- O HEAD certo?
- Diff esperado?
- Mensagens de commit fazem sentido?

## 2. Backup pré-deploy

```bash
make backup
ls -lh backups/$(date +%Y%m%d)*/ | head -10
```

## 3. Build da imagem com tag

```bash
GIT_SHA=$(git rev-parse --short HEAD)
docker compose --env-file .env -f docker/compose.yml build orchestrator
docker tag cai-orchestrator:dev cai-orchestrator:$GIT_SHA
```

Push pro registry interno (configurar `REGISTRY_URL` no `.env` do ambiente alvo):

```bash
docker tag cai-orchestrator:$GIT_SHA $REGISTRY_URL/cai-orchestrator:$GIT_SHA
docker push $REGISTRY_URL/cai-orchestrator:$GIT_SHA
```

## 4. Aplicar migrations

```bash
docker compose -f docker/compose.yml --env-file .env.${ENV} run --rm \
    --entrypoint alembic orchestrator upgrade head
```

## 5. Rolling update

Worker primeiro (drena fila):

```bash
docker compose -f docker/compose.yml --env-file .env.${ENV} stop worker
docker compose -f docker/compose.yml --env-file .env.${ENV} up -d worker
```

Depois orchestrator:

```bash
docker compose -f docker/compose.yml --env-file .env.${ENV} stop orchestrator
docker compose -f docker/compose.yml --env-file .env.${ENV} up -d orchestrator
```

## 6. Smoke test pós-deploy

```bash
TOKEN=$(grep '^APP_TOKEN' .env.${ENV} | cut -d= -f2)
curl -f -H "X-API-Token: $TOKEN" https://cai.${ENV}/api/health
```

## Rollback

Se smoke pós-deploy falhar:

```bash
PREV_SHA=$(git rev-parse --short HEAD~1)
docker compose -f docker/compose.yml --env-file .env.${ENV} down orchestrator worker
docker tag $REGISTRY_URL/cai-orchestrator:$PREV_SHA cai-orchestrator:dev
docker compose -f docker/compose.yml --env-file .env.${ENV} up -d orchestrator worker

# Se migration mexeu schema: alembic downgrade -1
# CUIDADO: data loss possível
```

## Não fazer

- **Nunca** `--no-verify` em commit/push
- **Nunca** `docker compose down -v` — `-v` apaga volumes (incluindo Postgres)
- **Nunca** pular smoke test pós-deploy "porque não temos tempo"

## Limitação atual

CI/CD ainda não está configurado. Em produção real, este skill seria substituído por pipeline (GitHub Actions, GitLab CI). Por hora, é manual — daí ser opt-in.

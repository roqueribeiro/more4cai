---
description: Build das imagens Docker (orchestrator obrigatório, kali-toolbox e cai-expert opcionais)
allowed-tools: Bash
argument-hint: "[orchestrator|kali|all]"
---

Execute o build apropriado conforme `$ARGUMENTS`:

- Sem args ou `orchestrator`: só a imagem do orchestrator (rápido, ~1min)
  ```bash
  docker compose --env-file .env -f docker/compose.yml -f docker/compose.scanners.yml build orchestrator
  ```

- `kali`: kali-toolbox (lento, ~3GB de downloads, 15-30min)
  ```bash
  docker compose --env-file .env -f docker/compose.yml -f docker/compose.scanners.yml build kali-toolbox
  ```

- `all`: orchestrator + kali-toolbox + cai-expert
  ```bash
  docker compose --env-file .env -f docker/compose.yml -f docker/compose.scanners.yml -f docker/compose.agent.yml build orchestrator kali-toolbox cai-expert
  ```

Sempre passar `--env-file .env` (caso contrário interpolação de variáveis falha).

Reporte tamanho das imagens com `docker images | grep cai-` ao final.

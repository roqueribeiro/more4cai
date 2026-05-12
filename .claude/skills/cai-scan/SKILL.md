---
name: cai-scan
description: Dispara um scan de vulnerabilidade contra um alvo do engagement. Use quando usuário pede "rode scan em X", "scaneie Y", "pentest no host Z", "verifica vulnerabilidades de http://...". Cobre Nmap + ZAP por padrão; adicionais (Nuclei, Trivy) sob demanda.
when_to_use: scan ativo de pentest, verificação de vulnerabilidades em URL/host/IP do escopo do engagement
argument-hint: "<target-url-or-host> [--active] [--criticality=high|medium|low]"
allowed-tools: Bash Read
---

# Skill: Disparar scan de vulnerabilidade

Você está sendo invocado para rodar um scan ativo. Confirme escopo do engagement antes de disparar.

## 1. Entender o alvo

Identifique no pedido do usuário:
- **target**: URL completa (`http://app.cliente.com`) ou host
- **criticality**: se o usuário não disser, assuma `medium`
- **PII**: se o usuário disser que toca dados pessoais, sinalizar (`--contains-pii`) — afeta priorização AI
- **active scan**: por padrão NÃO. Só se o usuário pedir explicitamente (ZAP active scan é mais lento e ruidoso, gera mais tráfego).

## 2. Confirmar escopo

Pentester comercial: confirme com o usuário que o alvo está **dentro do escopo escrito** do contrato. Não rode contra alvo não autorizado mesmo que o sistema permita.

## 3. Verificar stack

```bash
docker compose --env-file .env -f docker/compose.yml -f docker/compose.scanners.yml -f docker/compose.lab.yml ps
```

Se não tem `cai-zap`, `cai-postgres` rodando, suba:

```bash
docker compose --env-file .env -f docker/compose.yml -f docker/compose.scanners.yml -f docker/compose.lab.yml --profile default --profile scanners up -d
```

Aguarde ZAP ficar pronto:

```bash
for i in {1..30}; do
  curl -sf "http://127.0.0.1:8090/JSON/core/view/version/?apikey=$(grep '^ZAP_API_KEY' .env | cut -d= -f2)" >/dev/null && echo OK && break
  sleep 5
done
```

## 4. Disparar scan

CLI síncrono (gera HTML direto):

```bash
MSYS_NO_PATHCONV=1 docker compose -f docker/compose.yml -f docker/compose.scanners.yml --env-file .env run --rm orchestrator scan "$TARGET" --asset-type url --criticality medium [--skip-ai] [--active-zap] [--contains-pii]
```

Se o usuário não tem `ANTHROPIC_API_KEY` nem `LLM_API_BASE` configurado, **adicione `--skip-ai`** automaticamente.

## 5. Reportar

Após scan terminar:

```bash
ls -lt reports/ | head -3
```

Mostre o caminho do HTML gerado. Faça resumo executivo de até 5 linhas:
- N findings, distribuição de severity
- Top 3 issues
- Avisos/erros (se `Avisos:` apareceu)
- Caminho do relatório
- Sugerir próximo passo: `cai bundle <scan_id>` pra gerar AI Fix Bundle entregável a outro patcher.

NÃO abrir o HTML pelo navegador — apenas reportar caminho.

## Edge cases

- **ZAP unhealthy mas funcional**: container marca "unhealthy" porque healthcheck não está implementado, mas API responde. Se a API responde via curl, ignore o status do compose.
- **Postgres sem schema**: erro "relation does not exist" → rodar `make migrate` primeiro.
- **`.env` não lido**: sempre passar `--env-file .env` no docker compose.
- **Target inacessível** (DNS, conexão recusada): NÃO insistir. Reportar erro e perguntar.

## Quando NÃO usar este skill

- Scan OSINT/exposure (público, passivo) → use skill `cai-exposure`
- Análise de findings já persistidos → use agent `findings-analyst`
- Adicionar novo scanner → use skill `cai-add-adapter`
- Gerar bundle pra IA patcher consumir → use skill `cai-handoff-fix`

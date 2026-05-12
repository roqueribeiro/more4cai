---
name: cai-exposure
description: Roda scan OSINT/Exposure externa (vazamento de código, secrets, typosquat, exposição internet). Use quando usuário pede "verifica exposure", "tem código nosso vazado?", "alguém registrou domínio parecido?", "scan OSINT". Read-only sobre dados públicos.
when_to_use: bug bounty externo, code leak detection, secret scanning em repos públicos, typosquatting, EASM, defensive OSINT
argument-hint: "<company-name> [--domains=...] [--github-orgs=...] [--config-file=path.yml]"
allowed-tools: Bash Read
---

# Skill: Scan OSINT / Exposure externa

Diferente de `cai-scan` (ativo), este skill opera SOMENTE sobre dados públicos: GitHub Search, DNS, Shodan/Censys (opt-in), domínios públicos.

## 1. Coletar config

Há dois caminhos:

### A. Argumentos diretos
Usuário fornece `--domains`, `--github-orgs`, `--dorks`. Use direto.

### B. Arquivo YAML (recomendado)
Pedir o usuário pra preparar `config/exposure_targets.yml` (template em `config/exposure_targets.example.yml`):

```bash
cp config/exposure_targets.example.yml config/exposure_targets.yml
# editar com os dados reais
```

**`config/exposure_targets.yml` é gitignored** — pode conter strings sensíveis do banco.

## 2. Validar credenciais

```bash
grep -E '^GITHUB_TOKEN|^SHODAN_API_KEY|^CENSYS_API' .env
```

- `GITHUB_TOKEN` — necessário pra GitHub Search (PAT com scope `public_repo`)
- `SHODAN_API_KEY` — opt-in
- `CENSYS_API_*` — opt-in

Se faltar GitHub token, alertar — vai pular dorks no GitHub.

## 3. Verificar binários OSINT (kali-toolbox)

Os adapters de OSINT (`gitleaks`, `trufflehog`, `dnstwist`) rodam dentro do container `cai-kali-toolbox`. Verificar se está no ar:

```bash
docker compose --env-file .env -f docker/compose.yml -f docker/compose.scanners.yml ps kali-toolbox
```

Se não, build (pode demorar — ~3GB de download):

```bash
docker compose --env-file .env -f docker/compose.yml -f docker/compose.scanners.yml build kali-toolbox
docker compose --env-file .env -f docker/compose.yml -f docker/compose.scanners.yml --profile scanners up -d kali-toolbox
```

## 4. Disparar exposure scan

CLI:

```bash
MSYS_NO_PATHCONV=1 docker compose -f docker/compose.yml -f docker/compose.scanners.yml --env-file .env run --rm orchestrator exposure "$COMPANY" --config-file config/exposure_targets.yml [--skip-ai]
```

Ou se for via API REST:

```bash
TOKEN=$(grep '^APP_TOKEN' .env | cut -d= -f2)
curl -X POST http://127.0.0.1:8080/exposure/scan \
  -H "X-API-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"company_name":"...", "domains":[...], "github_orgs":[...], "dorks":[...]}'
```

## 5. Pipeline esperado

O scan vai (em paralelo onde possível):

1. **GitHubExposureAdapter** — dorks contra repos públicos retornam matches
2. **GitleaksAdapter / TrufflehogAdapter** — top-N repos descobertos passam por scan de secrets
3. **DnstwistAdapter** — typosquats por domínio (registrados, com MX, com ssdeep)
4. **ShodanAdapter** (se key) — exposure de IPs/serviços
5. **SubdomainTakeoverAdapter** — subfinder + httpx + nuclei -t takeovers/
6. **AI triage** — separa sinal de ruído (essencial em OSINT, tem muito FP)

## 6. Reportar

```bash
ls -lt reports/ | head -3
```

Resumo focado em:
- **Critical/High** verificados (especialmente `trufflehog --only-verified=true` e takeover ativo)
- **Repos sensíveis** com matches de dorks (com classificação AI: ruído vs vazamento real)
- **Typosquats com MX ativo** (phishing potencial)
- **Próximas ações sugeridas** (não tomar — só reportar):
  - DMCA takedown? → área jurídica
  - Notificar SOC sobre typosquat? → SOC
  - Trocar credencial vazada? → time da credencial

## Edge cases

- **GitHub rate limit**: ~30 req/min com PAT. Adapter já tem backoff, mas dork excessivo → trabalhar em batches
- **Shodan free tier**: limitado; uso intenso requer plano pago
- **Trufflehog `--only-verified=false`** gera muito FP; não desativar sem motivo

## Quando NÃO usar este skill

- Scan ativo contra ativo do banco → use `cai-scan` (requer autorização)
- Análise de findings já persistidos → use agent `findings-analyst`

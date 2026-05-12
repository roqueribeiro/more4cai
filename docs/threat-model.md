# Threat model — CAI Orchestrator

Foco: ferramenta interna em ambiente bancário. Atacantes plausíveis e mitigações.

## Atores e cenários

| Ator | Capacidade | Cenário | Mitigação |
|---|---|---|---|
| Operador interno malicioso | Tem credencial CAI | Usa CAI pra scan não autorizado | `audit_log` + `authorization_ref` obrigatório (Fase 6) + RBAC |
| Operador interno descuidado | Tem credencial | Aponta CAI pra produção achando que é dev | `LAB_ONLY=true` + `TARGET_ALLOWLIST` por ambiente |
| Atacante externo na rede corp | Acesso à VLAN do CAI | Tenta abusar a CLI/API pra reconnect/exfil | Network policy + TLS interno (Caddy) + token forte |
| Atacante via supply chain | Comprometer pacote pip | RCE no orchestrator | `pyproject.toml` pinado + uv lock + scan SCA do próprio CAI |
| Vazamento de credenciais LLM | API key Anthropic vaza | Custo + acesso a histórico de prompt | `.env` fora de git, secrets no Docker secrets/Vault, rate limit |
| Vazamento de findings | DB Postgres comprometido | Atacante vê vulns pendentes do banco | Volume Postgres encriptado em repouso, backup encriptado, RBAC granular |

## Dados sensíveis manipulados

| Dado | Onde aparece | Tratamento |
|---|---|---|
| PAN, CVV, CPF | `Finding.evidence` (HTTP responses) | `scrubber.py` antes do LLM externo |
| Tokens/JWTs | logs de scan, audit | `scrubber.py` + log redaction |
| Credenciais Greenbone, ZAP | `.env` | Docker secrets em prod (Fase 6) |
| API keys LLM | `.env` | Docker secrets em prod (Fase 6) |
| Authorization refs | `audit_log` | Append-only via trigger Postgres |

## Superficie de ataque

### CLI (`cai scan`)
- Argumentos não confiáveis (TARGET) passam pra subprocess. Mitigação: argv list (não shell), `cap_drop` no orchestrator container.

### REST API
- Token compartilhado (Fase 5). Vulnerável a leak de token. Mitigação: rotacionar; OIDC na Fase 6.
- Endpoints destrutivos (DELETE) ainda não existem — manter assim até RBAC.

### LLM gateway (litellm)
- Prompt injection: scanner pode retornar evidência maliciosa que tenta influenciar AIAnalyzer.
- Mitigação: `scrubber.py` reduz superfície; system prompt forte; nunca executar comandos sugeridos sem HITL.

### Container kali-toolbox
- `cap_add: NET_RAW NET_ADMIN` necessário pra nmap SYN.
- Não rodar com `--privileged`.
- Não dar acesso ao docker socket.

### Greenbone GMP
- TCP plain (porta 9390) — proteger com network policy ou usar Unix socket.

## Fluxos críticos a auditar

1. POST /scans com authorization_ref
2. POST /investigate (dry_run=False) — quando habilitado
3. POST /reports/{id}/export/defectdojo
4. Mudanças em config/exposure_targets.yml (alvo de OSINT)
5. Mudanças em allowlist (TARGET_ALLOWLIST env)

Todos têm entry no `audit_log`.

## Não escopo (limitações conhecidas)

- Não somos um WAF; bloqueio de exploit ativo é responsabilidade da plataforma alvo.
- Não substituímos pentest manual de aplicações críticas.
- AI triage não é evidência forense — humano valida findings antes de ação.
- DefectDojo export não é trilha de compliance autoridade — confirmar export com seu DPO.

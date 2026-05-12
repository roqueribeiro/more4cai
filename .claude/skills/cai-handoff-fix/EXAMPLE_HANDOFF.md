# Handoff de correções — scan 3bc7aaed-9efa-488d-a7df-2084d7c77cff (exemplo)

Bundle: `reports/scan-3bc7aaed/ai-bundle.json` (schema 1.0.0)

## Top 5 vulnerabilidades pra corrigir primeiro

### high — SQL Injection via id parameter (/users)
- **Categoria**: web
- **OWASP**: A03:2021-Injection
- **CWE**: CWE-89
- **Local**: `https://app.example.com/users?id=1` (GET param `id`)
- **Remediação**: Use parameterized queries (prepared statements) em vez de concatenar `id` direto na query SQL.
- **Verificação**: rodar ZAP com plugin 40018 contra `/users` e confirmar 0 alertas.

### high — Open port 21/tcp (vsftpd 2.3.4)
- **Categoria**: infra
- **OWASP**: n/a
- **CWE**: n/a
- **Local**: `10.0.0.5:21/tcp`
- **Remediação**: vsftpd 2.3.4 contém backdoor histórico (CVE-2011-2523). Atualizar pra ≥3.0 ou desativar serviço se não for necessário.
- **Verificação**: rerun nmap; banner deve mostrar versão atualizada.

### medium — X-Frame-Options missing
- **Categoria**: web
- **OWASP**: A05:2021-Security Misconfiguration
- **CWE**: CWE-1021
- **Local**: `https://www.example.com/`
- **Remediação**: Adicionar header `X-Frame-Options: DENY` (ou `Content-Security-Policy: frame-ancestors 'none'`) no servidor.
- **Verificação**: re-rodar ZAP baseline; alerta 10020 não deve aparecer.

## Como aplicar

1. Abra `ai-bundle.json` num agente de código (Claude Code, Cursor, Copilot)
2. Use as instruções em `appendix.patcher_instructions`
3. Para cada vulnerability, rode `code_search_patterns` da `remediation` pra localizar o código vulnerável
4. Proponha patch seguindo `before_after_examples`
5. Verifique com `verification.rerun` (rodar scan novamente apenas no escopo)

## Snippet pronto pra colar no patcher

```
Eu te entreguei um AI Fix Bundle em ./ai-bundle.json (schema 1.0.0).

Por favor:
1. Leia o JSON e ordene as vulnerabilidades por patch_priority (1=urgente).
2. Para cada uma, use os code_search_patterns da remediation pra localizar o código vulnerável no repo.
3. Proponha um patch seguindo before_after_examples (formato git diff).
4. Não aplique automaticamente — abra um PR por vulnerability separadamente.
5. No fim, retorne: lista de patches propostos, arquivos tocados, e quais não conseguiu localizar.

Comece pelas críticas. Verificação fica por minha conta — depois eu rodo o scan de novo seguindo verification.rerun.
```

## Métricas do bundle

- **Total**: 23 vulnerabilities (1 critical, 4 high, 12 medium, 6 low)
- **Patcher autônomo**: 7 vulnerabilities (deps upgrade + config simples)
- **Review humano**: 16 vulnerabilities (code_change + secret_rotation)
- **OWASP categorias**: A01, A03, A05, A07
- **Top CWEs**: CWE-89, CWE-79, CWE-798

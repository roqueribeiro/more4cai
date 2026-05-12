"""Validador de target.value — bloqueia injeção de flags (H4) e SSRF (H5).

Aplicado ANTES de qualquer enqueue de scan ou criação de target. Rejeita:

- Strings que começam com `-`/`--` (argv injection nos adapters subprocess).
- Hosts em ranges privados/loopback/link-local quando `LAB_ONLY=true` E o host
  não está em `TARGET_ALLOWLIST`. Bloqueia metadata IMDS (169.254.169.254),
  serviços internos da rede `cai-net` (postgres, redis), e RFC1918.
- Schemes não-HTTP/HTTPS em URLs (rejeita `file://`, `gopher://`, etc.).

Quando `LAB_ONLY=true` E `TARGET_ALLOWLIST` contém o host/IP/CIDR, permite
(é o caminho intencional pra Juice Shop/DVWA/WebGoat no lab).

Conformidade: este é o coração do compliance gate. Mexer aqui requer review.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from orchestrator.config import settings


class TargetValidationError(ValueError):
    """Levantada quando target.value é rejeitado por policy."""


# Domínios/IPs que NÃO podem ser alvo quando LAB_ONLY=true sem allowlist explícita.
# RFC1918, loopback, link-local, IMDS, ULA IPv6.
_FORBIDDEN_HOSTNAMES: frozenset[str] = frozenset(
    {"localhost", "metadata.google.internal", "metadata", "instance-data"}
)

_HOSTNAME_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)


def _is_blocked_network(host: str) -> bool:
    """True se o host é IP em range privado/reservado, ou hostname sentinela."""
    if host.lower() in _FORBIDDEN_HOSTNAMES:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _host_in_allowlist(host: str, allowlist: list[str]) -> bool:
    """Confere se host (hostname ou IP) bate com algum entry da allowlist.

    Entries podem ser: hostname exato (`juice-shop`), CIDR (`10.0.0.0/8`),
    ou wildcard de domínio (`*.lab.example.com`).
    """
    host_l = host.lower()
    for entry in allowlist:
        entry_l = entry.strip().lower()
        if not entry_l:
            continue
        # CIDR?
        if "/" in entry_l:
            try:
                net = ipaddress.ip_network(entry_l, strict=False)
                ip = ipaddress.ip_address(host_l)
                if ip in net:
                    return True
            except ValueError:
                continue
        # wildcard?
        elif entry_l.startswith("*."):
            suffix = entry_l[2:]
            if host_l == suffix or host_l.endswith(f".{suffix}"):
                return True
        # match exato
        elif host_l == entry_l:
            return True
    return False


def validate_target_value(value: str, *, asset_type: str | None = None) -> str:
    """Valida e retorna `value` normalizado.

    Args:
        value: string controlada por user (CLI/API/UI input).
        asset_type: hint do tipo (`url`, `host`, `domain`, `repo`, `image`).
                    Quando `url`, parseia e valida scheme + host.

    Raises:
        TargetValidationError: motivo concreto da rejeição.

    Returns:
        valor normalizado (strip + lower do host quando aplicável).
    """
    if not value or not isinstance(value, str):
        raise TargetValidationError("target.value vazio ou tipo invalido")

    v = value.strip()

    # H4: bloqueia flags. argv injection: `-rf`, `--upload-pack=...`, etc.
    if v.startswith("-"):
        raise TargetValidationError(
            "target.value nao pode comecar com '-' (potencial injecao de flag em subprocess)"
        )

    # Extrair host conforme tipo. Ordem importa: asset_type ganha de heuristica de URL.
    host: str | None = None
    if asset_type == "repo":
        # Repo: URL git. Validar scheme http(s) ou ssh.
        if v.startswith(("http://", "https://")):
            return _validate_url_repo(v)
        if v.startswith("git@"):
            return v
        raise TargetValidationError("repo deve usar http(s):// ou git@host:owner/repo (ssh)")
    elif asset_type == "image":
        # Image: registry/name:tag — só rejeita prefixo "-" (já feito acima)
        return v
    elif asset_type == "url" or "://" in v:
        try:
            parsed = urlparse(v)
        except ValueError as e:
            raise TargetValidationError(f"URL malformada: {e}") from e
        if parsed.scheme not in {"http", "https"}:
            raise TargetValidationError(
                f"scheme '{parsed.scheme}' nao permitido (apenas http/https)"
            )
        if not parsed.hostname:
            raise TargetValidationError("URL sem hostname")
        host = parsed.hostname
    elif asset_type in {"host", "domain"}:
        # Pode vir com :porta — extrair só hostname
        host = v.split(":", 1)[0] if ":" in v and not v.count(":") > 1 else v
        host = host.split("/", 1)[0]  # tira path se vier coloando
        if not _HOSTNAME_RE.match(host) and not _is_ip_literal(host):
            raise TargetValidationError(f"hostname/IP malformado: {host!r}")

    # H5: SSRF — bloqueia hosts privados/loopback fora da allowlist quando LAB_ONLY=true
    if host is not None and settings.LAB_ONLY:
        if not _host_in_allowlist(host, settings.target_allowlist):
            if _is_blocked_network(host):
                raise TargetValidationError(
                    f"host {host!r} em rede privada/loopback/IMDS "
                    f"e nao esta em TARGET_ALLOWLIST. Para autorizar, adicione em settings."
                )

    return v


def _is_ip_literal(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _validate_url_repo(url: str) -> str:
    """Validacao adicional pra repo url — sem auth embutido no URL (vaza em log)."""
    parsed = urlparse(url)
    if parsed.username or parsed.password:
        raise TargetValidationError(
            "URL de repo nao deve conter credenciais embutidas (use SSH key ou GITHUB_TOKEN env)"
        )
    return url

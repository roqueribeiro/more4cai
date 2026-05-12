"""PII/PCI scrubber — remove dados sensíveis antes de mandar pro LLM externo.

Aplicado em `Evidence` e `description` de Findings durante a triagem AI.
Uso defensivo: melhor um falso positivo de scrub do que vazar PAN/CPF/email pro Claude.

Conformidade: LGPD Art. 46 (medidas técnicas adequadas), PCI DSS Req. 3 (proteção de dados de cartão).
"""

from __future__ import annotations

import re
from re import Pattern
from typing import Final

# CPF: 11 dígitos, com ou sem pontuação
_CPF: Final[Pattern[str]] = re.compile(r"\b(\d{3}[\.\-\s]?\d{3}[\.\-\s]?\d{3}[\.\-\s]?\d{2})\b")

# CNPJ: 14 dígitos
_CNPJ: Final[Pattern[str]] = re.compile(
    r"\b(\d{2}[\.\s]?\d{3}[\.\s]?\d{3}[\/\s]?\d{4}[\-\s]?\d{2})\b"
)

# PAN (cartão): 13-19 dígitos, com ou sem espaços/hífens. Validação Luhn opcional.
_PAN: Final[Pattern[str]] = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

# CVV: 3-4 dígitos próximos à palavra "cvv", "cvc", "security code"
_CVV: Final[Pattern[str]] = re.compile(
    r"(?:cvv|cvc|cvv2|security[\s_-]*code)\s*[:=]?\s*(\d{3,4})",
    re.IGNORECASE,
)

# Email
_EMAIL: Final[Pattern[str]] = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")

# JWT (3 partes base64.base64.base64)
_JWT: Final[Pattern[str]] = re.compile(r"\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b")

# AWS access key
_AWS_KEY: Final[Pattern[str]] = re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")

# Telefone BR: (11) 91234-5678 ou variações.
# Bordas (?<!\d)/(?!\d) impedem que a regex devore digitos de tokens maiores
# (ex: IDs de transacao de 14-16 digitos sendo recortados como telefone).
_PHONE_BR: Final[Pattern[str]] = re.compile(
    r"(?<!\d)\(?(?:\+?55\s?)?(?:\(?[1-9][1-9]\)?\s?)?9?\d{4}[\-\s]?\d{4}(?!\d)"
)

# Bearer/Authorization tokens
_AUTH_HEADER: Final[Pattern[str]] = re.compile(
    r"(authorization\s*:\s*)(bearer\s+)?[a-zA-Z0-9_\-\.]{20,}",
    re.IGNORECASE,
)


def _luhn_check(num: str) -> bool:
    """Valida cartão pelo algoritmo de Luhn. Reduz falso positivo no PAN."""
    digits = [int(d) for d in num if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _redact_pan(match: re.Match[str]) -> str:
    raw = match.group(0)
    digits_only = "".join(c for c in raw if c.isdigit())
    if _luhn_check(digits_only):
        return f"<PAN:****{digits_only[-4:]}>"
    return raw  # números longos que não são cartão (ex: IDs de transação)


def scrub(text: str) -> str:
    """Remove dados sensíveis de uma string.

    Substitui por placeholders estáveis e parcialmente informativos
    (`<EMAIL>`, `<CPF>`, `<PAN:****1234>`) para que o LLM ainda entenda o contexto.
    """
    if not text:
        return text

    out = text
    out = _AUTH_HEADER.sub(lambda m: f"{m.group(1)}<REDACTED_TOKEN>", out)
    out = _JWT.sub("<JWT>", out)
    out = _AWS_KEY.sub("<AWS_KEY>", out)
    out = _PAN.sub(_redact_pan, out)
    out = _CVV.sub(lambda m: m.group(0).replace(m.group(1), "<CVV>"), out)
    out = _CNPJ.sub("<CNPJ>", out)
    out = _CPF.sub("<CPF>", out)
    out = _EMAIL.sub("<EMAIL>", out)
    out = _PHONE_BR.sub("<PHONE_BR>", out)
    return out


def scrub_dict(data: dict[str, object]) -> dict[str, object]:
    """Scrub recursivo em dict — usado em payloads JSON antes do LLM."""
    out: dict[str, object] = {}
    for k, v in data.items():
        if isinstance(v, str):
            out[k] = scrub(v)
        elif isinstance(v, dict):
            out[k] = scrub_dict(v)
        elif isinstance(v, list):
            out[k] = [
                scrub(x) if isinstance(x, str) else scrub_dict(x) if isinstance(x, dict) else x
                for x in v
            ]
        else:
            out[k] = v
    return out

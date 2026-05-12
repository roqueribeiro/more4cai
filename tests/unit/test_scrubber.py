"""Tests for PII/PCI scrubber. Validar que dados sensíveis não escapam pro LLM."""

from __future__ import annotations

from uuid import uuid4

from orchestrator.ai.analyzer import _finding_to_compact
from orchestrator.domain.schemas import (
    AssetType,
    Confidence,
    Evidence,
    Finding,
    Severity,
    Target,
)
from orchestrator.domain.scrubber import scrub, scrub_dict


def test_email_redacted() -> None:
    assert scrub("contato: foo@example.com") == "contato: <EMAIL>"


def test_cpf_redacted_with_punctuation() -> None:
    assert "<CPF>" in scrub("CPF: 123.456.789-00")


def test_cpf_redacted_without_punctuation() -> None:
    assert "<CPF>" in scrub("12345678900 é o documento")


def test_cnpj_redacted() -> None:
    assert "<CNPJ>" in scrub("CNPJ 12.345.678/0001-99")


def test_pan_visa_with_luhn() -> None:
    # 4111-1111-1111-1111 é PAN de teste Visa, passa Luhn
    out = scrub("Card: 4111-1111-1111-1111 ok")
    assert "<PAN:****1111>" in out
    assert "4111" not in out


def test_long_number_not_pan_kept() -> None:
    # ID transação random — 16 dígitos sem Luhn válido
    out = scrub("Tx ID: 1234567890123456")
    # mesmo passando o regex, falha Luhn → mantido
    assert "1234567890123456" in out


def test_jwt_redacted() -> None:
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert "<JWT>" in scrub(f"token={jwt}")


def test_aws_key_redacted() -> None:
    assert "<AWS_KEY>" in scrub("AKIAIOSFODNN7EXAMPLE encontrado")


def test_authorization_header_redacted() -> None:
    out = scrub("Authorization: Bearer abcdef1234567890abcdef1234567890")
    assert "<REDACTED_TOKEN>" in out


def test_phone_br_redacted() -> None:
    assert "<PHONE_BR>" in scrub("ligar (11) 91234-5678")


def test_scrub_dict_recursive() -> None:
    data = {
        "email": "user@example.com",
        "nested": {"cpf": "111.222.333-44"},
        "list": ["foo@bar.com", "ok"],
    }
    out = scrub_dict(data)
    assert out["email"] == "<EMAIL>"
    assert out["nested"]["cpf"] == "<CPF>"  # type: ignore[index]
    assert out["list"][0] == "<EMAIL>"  # type: ignore[index]


def test_empty_string() -> None:
    assert scrub("") == ""


def _make_finding(
    *, description: str, title: str = "Test", evidence_snippet: str | None = None
) -> Finding:
    """Helper: cria Finding minimo pra testar _finding_to_compact."""
    return Finding(
        scan_id=uuid4(),
        target=Target(asset_type=AssetType.URL, value="http://juice-shop:3000"),
        source_tool="zap",
        title=title,
        description=description,
        severity=Severity.HIGH,
        confidence=Confidence.FIRM,
        evidence=(
            [Evidence(description="resp", snippet=evidence_snippet)]
            if evidence_snippet is not None
            else []
        ),
    )


def test_triage_compact_scrubs_email_in_description() -> None:
    f = _make_finding(description="Form leaked admin@bank.com.br in response body")
    out = _finding_to_compact(f)
    assert "admin@bank.com.br" not in out["description"]
    assert "<EMAIL>" in out["description"]


def test_triage_compact_scrubs_jwt_in_evidence_snippet() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.AAAA-BBBB_CCCC"
    f = _make_finding(description="JWT exposto", evidence_snippet=f"Cookie: session={jwt}")
    out = _finding_to_compact(f)
    snippet = out["evidence_snippets"][0]
    assert jwt not in snippet
    assert "<JWT>" in snippet


def test_triage_compact_scrubs_authorization_bearer() -> None:
    f = _make_finding(
        description="Endpoint aceita token estatico",
        evidence_snippet="Authorization: Bearer abc123def456ghi789jkl012mno345pqr",
    )
    out = _finding_to_compact(f)
    snippet = out["evidence_snippets"][0]
    assert "abc123def456ghi789jkl012mno345pqr" not in snippet
    assert "<REDACTED_TOKEN>" in snippet


def test_triage_compact_scrubs_title() -> None:
    # Scanners as vezes embutem PII no title (ex: "Email exposed: foo@bar.com")
    f = _make_finding(
        description="exposicao de email",
        title="Email exposed: user@example.org in HTML comment",
    )
    out = _finding_to_compact(f)
    assert "user@example.org" not in out["title"]
    assert "<EMAIL>" in out["title"]


def test_triage_compact_preserves_target_value() -> None:
    # target.value e a URL real do engagement, NAO scrubbed (operador precisa rastrear)
    f = _make_finding(description="x")
    out = _finding_to_compact(f)
    assert out["target"]["value"] == "http://juice-shop:3000"


def test_no_match_returns_unchanged() -> None:
    text = "ipsum dolor sit amet sem dado sensivel"
    assert scrub(text) == text

"""Tests for PII/PCI scrubber. Validar que dados sensíveis não escapam pro LLM."""

from __future__ import annotations

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


def test_no_match_returns_unchanged() -> None:
    text = "ipsum dolor sit amet sem dado sensivel"
    assert scrub(text) == text

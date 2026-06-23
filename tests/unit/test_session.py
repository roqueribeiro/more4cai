"""Sessão JWT (HS256) — issue/verify, expiração, adulteração."""

from __future__ import annotations

from uuid import uuid4

from orchestrator.auth.session import issue_session, verify_session


def test_roundtrip_valid_session():
    uid = uuid4()
    tok = issue_session(user_id=uid, email="op@bank.com", role="operator")
    claims = verify_session(tok)
    assert claims is not None
    assert claims["sub"] == str(uid)
    assert claims["email"] == "op@bank.com"
    assert claims["role"] == "operator"
    assert claims["typ"] == "session"


def test_expired_session_is_rejected():
    # ttl negativo → exp no passado → inválido
    tok = issue_session(user_id=uuid4(), email="x@bank.com", role="viewer", ttl_hours=-1)
    assert verify_session(tok) is None


def test_tampered_token_is_rejected():
    tok = issue_session(user_id=uuid4(), email="x@bank.com", role="admin")
    # adultera o payload (flipa um char no meio)
    i = len(tok) // 2
    tampered = tok[:i] + ("A" if tok[i] != "A" else "B") + tok[i + 1 :]
    assert verify_session(tampered) is None


def test_garbage_and_empty_are_rejected():
    assert verify_session(None) is None
    assert verify_session("") is None
    assert verify_session("not-a-jwt") is None
    assert verify_session("a.b.c") is None


def test_non_session_typ_is_rejected():
    # um JWT válido assinado com a MESMA chave mas typ != session não passa
    from jose import jwt

    from orchestrator.auth.session import _key

    bad = jwt.encode({"sub": "x", "typ": "id_token"}, _key(), algorithm="HS256")
    assert verify_session(bad) is None

"""Scanning autenticado — o segredo (auth headers) NUNCA persiste na tabela
`scans`, o audit redige os valores, o scrubber redige Cookie/Set-Cookie, e o
adapter ZAP injeta os headers + importa o OpenAPI. Os helpers são puros."""

from __future__ import annotations

from unittest.mock import AsyncMock

from orchestrator.adapters.zap_adapter import ZAPAdapter
from orchestrator.api.routers.scans import (
    AuthContext,
    redact_audit_auth,
    split_scan_auth,
)
from orchestrator.domain.schemas import AssetType, Target
from orchestrator.domain.scrubber import scrub

_SECRET = "sid=Sup3rSecretSessionToken-abcdef0123456789"


# --- split_scan_auth: o INVARIANTE de segurança --------------------------------


def test_no_auth_leaves_options_untouched():
    persisted, headers, openapi = split_scan_auth({"active": True}, None)
    assert persisted == {"active": True}
    assert headers == {}
    assert openapi is None
    assert "authenticated" not in persisted


def test_auth_headers_never_persisted():
    auth = AuthContext(headers={"Cookie": _SECRET, "Authorization": "Bearer xyz"})
    persisted, headers, openapi = split_scan_auth({}, auth)
    # o segredo volta SEPARADO (efêmero) …
    assert headers == {"Cookie": _SECRET, "Authorization": "Bearer xyz"}
    # … e NUNCA aparece no que vai pra `scans` — só o marcador booleano.
    assert persisted == {"authenticated": True}
    serialized = str(persisted)
    assert _SECRET not in serialized
    assert "Bearer xyz" not in serialized


def test_openapi_url_is_persisted_not_secret():
    auth = AuthContext(headers={"Cookie": _SECRET}, openapi_url="https://api.x/openapi.json")
    persisted, headers, openapi = split_scan_auth({}, auth)
    assert openapi == "https://api.x/openapi.json"
    assert persisted["openapi_url"] == "https://api.x/openapi.json"  # spec pública = ok
    assert persisted["authenticated"] is True
    assert _SECRET not in str(persisted)  # mas o cookie continua fora


def test_empty_auth_context_adds_no_marker():
    persisted, headers, openapi = split_scan_auth({"x": 1}, AuthContext())
    assert persisted == {"x": 1}  # sem headers nem openapi → sem marcador
    assert headers == {}


# --- redact_audit_auth ---------------------------------------------------------


def test_audit_redacts_header_values_keeps_names():
    body = {"target_id": "t", "auth": {"headers": {"Cookie": _SECRET, "X-Api": "k"}}}
    out = redact_audit_auth(body)
    # nomes preservados (auditoria sabe QUAIS headers), valores redigidos.
    assert out["auth"]["headers"] == {"Cookie": "<redacted>", "X-Api": "<redacted>"}
    assert _SECRET not in str(out)


def test_audit_without_auth_unchanged():
    body = {"target_id": "t", "auth": None}
    assert redact_audit_auth(body) == {"target_id": "t", "auth": None}


# --- scrubber: Cookie / Set-Cookie --------------------------------------------


def test_scrub_redacts_cookie():
    assert scrub("Cookie: sessionid=abc123def456") == "Cookie: <REDACTED_COOKIE>"


def test_scrub_redacts_set_cookie():
    out = scrub("Set-Cookie: token=zzzzzzzz; HttpOnly")
    assert "<REDACTED_COOKIE>" in out
    assert "zzzzzzzz" not in out


def test_scrub_still_redacts_authorization():
    out = scrub("Authorization: Bearer abcdefghij0123456789KLMNOP")
    assert "<REDACTED_TOKEN>" in out
    assert "abcdefghij0123456789KLMNOP" not in out


# --- ZAP adapter: injeta headers (replacer) + importa OpenAPI ------------------


async def test_zap_injects_auth_headers_and_imports_openapi():
    adapter = ZAPAdapter(base_url="http://zap:8080", api_key="k")
    adapter._get = AsyncMock(return_value={"scan": "1"})  # spider id válido

    target = Target(asset_type=AssetType.URL, value="https://app.bank.example")
    await adapter.start_scan(
        target,
        {
            "headers": {"Cookie": _SECRET, "Authorization": "Bearer xyz"},
            "openapi_url": "https://app.bank.example/openapi.json",
        },
    )

    calls = adapter._get.call_args_list
    paths = [c.args[0] for c in calls]
    # uma regra do replacer por header (injeta o header em toda request)
    replacer = [c for c in calls if c.args[0] == "/JSON/replacer/action/addRule/"]
    assert len(replacer) == 2
    match_strings = {c.kwargs["matchString"]: c.kwargs["replacement"] for c in replacer}
    assert match_strings["Cookie"] == _SECRET
    assert match_strings["Authorization"] == "Bearer xyz"
    # OpenAPI importado pra enumerar a superfície da API
    assert "/JSON/openapi/action/importUrl/" in paths
    openapi_call = next(c for c in calls if c.args[0] == "/JSON/openapi/action/importUrl/")
    assert openapi_call.kwargs["url"] == "https://app.bank.example/openapi.json"

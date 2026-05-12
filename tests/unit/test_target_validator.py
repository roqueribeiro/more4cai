"""Tests para target_validator — gates de compliance H4 (argv injection) + H5 (SSRF)."""

from __future__ import annotations

import pytest

from orchestrator.config import settings
from orchestrator.domain.target_validator import (
    TargetValidationError,
    validate_target_value,
)

# ------------------ H4: argv injection ------------------


def test_rejects_value_starting_with_dash() -> None:
    with pytest.raises(TargetValidationError, match="injecao de flag"):
        validate_target_value("-rf /tmp", asset_type="host")


def test_rejects_value_starting_with_double_dash() -> None:
    with pytest.raises(TargetValidationError, match="injecao de flag"):
        validate_target_value("--upload-pack=evil", asset_type="repo")


def test_rejects_empty_value() -> None:
    with pytest.raises(TargetValidationError):
        validate_target_value("", asset_type="url")


# ------------------ H5: SSRF / private network ------------------


def test_rejects_imds_aws(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "LAB_ONLY", True)
    monkeypatch.setattr(settings, "TARGET_ALLOWLIST", "")
    with pytest.raises(TargetValidationError, match="rede privada/loopback/IMDS"):
        validate_target_value("http://169.254.169.254/latest/meta-data/", asset_type="url")


def test_rejects_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "LAB_ONLY", True)
    monkeypatch.setattr(settings, "TARGET_ALLOWLIST", "")
    with pytest.raises(TargetValidationError):
        validate_target_value("http://127.0.0.1:8080/", asset_type="url")


def test_rejects_rfc1918_when_lab_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "LAB_ONLY", True)
    monkeypatch.setattr(settings, "TARGET_ALLOWLIST", "")
    with pytest.raises(TargetValidationError):
        validate_target_value("http://192.168.1.1/admin", asset_type="url")


def test_rejects_internal_hostnames(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "LAB_ONLY", True)
    monkeypatch.setattr(settings, "TARGET_ALLOWLIST", "")
    with pytest.raises(TargetValidationError):
        validate_target_value("http://localhost/admin", asset_type="url")


# ------------------ ALLOWLIST: caminho de lab ------------------


def test_allows_juice_shop_via_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "LAB_ONLY", True)
    monkeypatch.setattr(settings, "TARGET_ALLOWLIST", "juice-shop,dvwa,webgoat")
    out = validate_target_value("http://juice-shop:3000/#/", asset_type="url")
    assert out == "http://juice-shop:3000/#/"


def test_allows_loopback_via_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "LAB_ONLY", True)
    monkeypatch.setattr(settings, "TARGET_ALLOWLIST", "127.0.0.1")
    out = validate_target_value("http://127.0.0.1:8080/", asset_type="url")
    assert "127.0.0.1" in out


def test_allows_cidr_in_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "LAB_ONLY", True)
    monkeypatch.setattr(settings, "TARGET_ALLOWLIST", "10.0.0.0/8")
    out = validate_target_value("http://10.5.5.5/", asset_type="url")
    assert "10.5.5.5" in out


def test_allows_wildcard_domain_in_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "LAB_ONLY", True)
    monkeypatch.setattr(settings, "TARGET_ALLOWLIST", "*.lab.example.com")
    out = validate_target_value("http://app.lab.example.com/", asset_type="url")
    assert "app.lab.example.com" in out


def test_accepts_json_array_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tambem aceita JSON-array (compat com docs antigas)."""
    monkeypatch.setattr(settings, "LAB_ONLY", True)
    monkeypatch.setattr(settings, "TARGET_ALLOWLIST", '["juice-shop"]')
    out = validate_target_value("http://juice-shop/", asset_type="url")
    assert "juice-shop" in out


def test_public_internet_allowed_when_lab_only_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "LAB_ONLY", False)
    monkeypatch.setattr(settings, "TARGET_ALLOWLIST", "")
    # Sem LAB_ONLY: hosts publicos ok (operador assumiu responsabilidade)
    out = validate_target_value("https://example.com/", asset_type="url")
    assert out == "https://example.com/"


# ------------------ URL scheme + repo ------------------


def test_rejects_file_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "LAB_ONLY", False)
    with pytest.raises(TargetValidationError, match="apenas http/https"):
        validate_target_value("file:///etc/passwd", asset_type="url")


def test_rejects_gopher_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "LAB_ONLY", False)
    with pytest.raises(TargetValidationError, match="apenas http/https"):
        validate_target_value("gopher://example.com/", asset_type="url")


def test_rejects_repo_with_embedded_credentials() -> None:
    with pytest.raises(TargetValidationError, match="credenciais embutidas"):
        validate_target_value(
            "https://user:secrettoken@github.com/owner/repo.git", asset_type="repo"
        )


def test_accepts_ssh_repo() -> None:
    out = validate_target_value("git@github.com:owner/repo.git", asset_type="repo")
    assert out == "git@github.com:owner/repo.git"


def test_accepts_image() -> None:
    out = validate_target_value("nginx:1.27-alpine", asset_type="image")
    assert out == "nginx:1.27-alpine"

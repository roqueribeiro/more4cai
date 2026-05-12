"""Tests para cleanup helper (H7 — async task + temp dir leak)."""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path

import pytest

from orchestrator.adapters._cleanup import cleanup_subprocess_handle


async def _slow_task(delay: float = 5.0) -> int:
    """Simula um subprocess que demora pra terminar."""
    await asyncio.sleep(delay)
    return 0


async def _fast_task() -> int:
    return 0


async def _failing_task() -> int:
    raise RuntimeError("scanner falhou")


@pytest.mark.asyncio
async def test_cleanup_pops_task_from_dict() -> None:
    tasks: dict[str, asyncio.Task[object]] = {}
    task: asyncio.Task[object] = asyncio.create_task(_fast_task())  # type: ignore[arg-type]
    tasks["nid-1"] = task
    await task
    await cleanup_subprocess_handle(native_id="nid-1", tasks=tasks, adapter_name="test")
    assert "nid-1" not in tasks


@pytest.mark.asyncio
async def test_cleanup_cancels_pending_task() -> None:
    tasks: dict[str, asyncio.Task[object]] = {}
    task: asyncio.Task[object] = asyncio.create_task(_slow_task(5.0))  # type: ignore[arg-type]
    tasks["nid-2"] = task
    # Cleanup ANTES do task terminar — deve cancelar
    await cleanup_subprocess_handle(native_id="nid-2", tasks=tasks, adapter_name="test")
    assert "nid-2" not in tasks
    assert task.cancelled() or task.done()


@pytest.mark.asyncio
async def test_cleanup_drains_task_exception() -> None:
    """Task que terminou com excecao nao deve ser ignorada (Python warning)."""
    tasks: dict[str, asyncio.Task[object]] = {}
    task: asyncio.Task[object] = asyncio.create_task(_failing_task())  # type: ignore[arg-type]
    tasks["nid-3"] = task
    # aguarda terminar
    try:
        await task
    except RuntimeError:
        pass
    # cleanup nao deve relevantar
    await cleanup_subprocess_handle(native_id="nid-3", tasks=tasks, adapter_name="test")
    assert "nid-3" not in tasks


@pytest.mark.asyncio
async def test_cleanup_removes_temp_dir_via_file_path() -> None:
    """Recebe path de ARQUIVO em temp dir prefixado 'cai-' — remove o dir pai."""
    tmpdir = Path(tempfile.mkdtemp(prefix="cai-test-cleanup-"))
    out = tmpdir / "out.json"
    out.write_text("{}")

    tasks: dict[str, asyncio.Task[object]] = {}
    paths: dict[str, Path] = {"nid-4": out}

    await cleanup_subprocess_handle(
        native_id="nid-4", tasks=tasks, output_paths=paths, adapter_name="test"
    )
    assert not tmpdir.exists()
    assert "nid-4" not in paths


@pytest.mark.asyncio
async def test_cleanup_removes_temp_dir_directly() -> None:
    """Recebe path de DIRETORIO em temp prefixado 'cai-' — remove direto."""
    tmpdir = Path(tempfile.mkdtemp(prefix="cai-test-workdir-"))
    (tmpdir / "subfile.txt").write_text("x")

    tasks: dict[str, asyncio.Task[object]] = {}
    paths: dict[str, Path] = {"nid-5": tmpdir}

    await cleanup_subprocess_handle(
        native_id="nid-5", tasks=tasks, output_paths=paths, adapter_name="test"
    )
    assert not tmpdir.exists()


@pytest.mark.asyncio
async def test_cleanup_does_not_remove_unrelated_paths() -> None:
    """Salvaguarda: nao remove paths fora de temp prefixado 'cai-'."""
    safe_dir = Path(tempfile.mkdtemp(prefix="other-prefix-"))
    out = safe_dir / "out.json"
    out.write_text("{}")

    tasks: dict[str, asyncio.Task[object]] = {}
    paths: dict[str, Path] = {"nid-6": out}

    try:
        await cleanup_subprocess_handle(
            native_id="nid-6", tasks=tasks, output_paths=paths, adapter_name="test"
        )
        assert safe_dir.exists(), "salvaguarda falhou; removeu path fora de cai-*"
    finally:
        shutil.rmtree(safe_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_cleanup_handles_unknown_native_id() -> None:
    """native_id inexistente nao deve lançar."""
    tasks: dict[str, asyncio.Task[object]] = {}
    paths: dict[str, Path] = {}
    # nao raise
    await cleanup_subprocess_handle(
        native_id="ghost", tasks=tasks, output_paths=paths, adapter_name="test"
    )

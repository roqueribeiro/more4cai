"""Verifica que arquivos referenciados em SKILL.md/agents/rules/CLAUDE.md existem em algum subdir."""

from __future__ import annotations

import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]

candidates = [
    "github_exposure_adapter.py", "gitleaks_adapter.py", "nmap_adapter.py",
    "nuclei_adapter.py", "shodan_adapter.py", "zap_adapter.py",
    "0001_initial.py", "deps.py", "config.py", "scrubber.py",
    "executive.html.j2", "logger.py", "compose.greenbone.yml",
    "schemas.py", "base.py", "dedup.py", "exposure_targets.yml",
]

for c in candidates:
    fname = c.split("/")[-1]
    matches = [m for m in Path(".").rglob(fname) if "__pycache__" not in str(m)]
    if matches:
        print(f"OK   {c:40s} -> {matches[0]}")
    else:
        print(f"FAIL {c:40s} (não existe)")

#!/usr/bin/env python
"""PostToolUse Edit/Write hook — formata .py editados com ruff (best-effort).

Best-effort: se ruff não está instalado, sai silenciosamente.
Cross-platform (Windows/Linux/Mac).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> None:
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.exit(0)
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError):
        sys.exit(0)

    file_path = data.get("tool_input", {}).get("file_path", "") or ""
    if not file_path:
        sys.exit(0)

    p = Path(file_path)
    if p.suffix != ".py" or not p.exists():
        sys.exit(0)

    if not shutil.which("ruff"):
        sys.exit(0)

    # ruff format + autofix safe
    for args in (
        ["ruff", "format", str(p)],
        ["ruff", "check", "--fix", "--quiet", str(p)],
    ):
        try:
            subprocess.run(args, capture_output=True, timeout=15, check=False)
        except (subprocess.TimeoutExpired, OSError):
            pass

    sys.exit(0)


if __name__ == "__main__":
    main()

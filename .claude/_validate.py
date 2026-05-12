"""Validador da estrutura .claude/ — frontmatters, JSON, refs internas. Use: python .claude/_validate.py"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CLAUDE = ROOT / ".claude"

errors: list[str] = []
warnings: list[str] = []


def parse_fm(text: str) -> dict | None:
    m = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    if not m:
        return None
    try:
        return yaml.safe_load(m.group(1))
    except yaml.YAMLError as e:
        return {"_error": f"YAML inválido: {e}"}


def check_skill(path: Path) -> None:
    fm = parse_fm(path.read_text(encoding="utf-8"))
    if fm is None:
        errors.append(f"{path}: sem frontmatter")
        return
    if fm.get("_error"):
        errors.append(f"{path}: {fm['_error']}")
        return
    for k in ("name", "description"):
        if k not in fm:
            errors.append(f"{path}: faltando '{k}'")
    if fm.get("name") and fm["name"] != path.parent.name:
        warnings.append(f"{path}: name='{fm['name']}' difere do dir '{path.parent.name}'")
    desc = str(fm.get("description") or "")
    if len(desc) < 50:
        warnings.append(f"{path}: description curta ({len(desc)} chars)")
    if len(desc) > 1500:
        warnings.append(f"{path}: description longa ({len(desc)} chars) — limite ~1536")


def check_agent(path: Path) -> None:
    fm = parse_fm(path.read_text(encoding="utf-8"))
    if fm is None:
        errors.append(f"{path}: sem frontmatter")
        return
    if fm.get("_error"):
        errors.append(f"{path}: {fm['_error']}")
        return
    for k in ("name", "description"):
        if k not in fm:
            errors.append(f"{path}: faltando '{k}'")
    if fm.get("name") and fm["name"] != path.stem:
        warnings.append(f"{path}: name='{fm['name']}' difere do filename")


def check_command(path: Path) -> None:
    fm = parse_fm(path.read_text(encoding="utf-8"))
    if fm is None:
        errors.append(f"{path}: sem frontmatter")
        return
    if fm.get("_error"):
        errors.append(f"{path}: {fm['_error']}")
        return
    if "description" not in fm:
        errors.append(f"{path}: faltando 'description'")


def check_rule(path: Path) -> None:
    fm = parse_fm(path.read_text(encoding="utf-8"))
    if fm is None:
        errors.append(f"{path}: sem frontmatter")
        return
    if fm.get("_error"):
        errors.append(f"{path}: {fm['_error']}")
        return
    if "description" not in fm:
        errors.append(f"{path}: faltando 'description'")
    if "paths" not in fm:
        warnings.append(f"{path}: sem 'paths' — vira rule global")


def check_settings() -> None:
    p = CLAUDE / "settings.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        errors.append(f"{p}: JSON inválido: {e}")
        return

    perms = data.get("permissions", {})
    for bucket in ("allow", "ask", "deny"):
        if not isinstance(perms.get(bucket, []), list):
            errors.append(f"{p}: permissions.{bucket} não é lista")

    # Verifica caminhos de hooks. Extrai o token contendo placeholder (ignora
    # interpretadores como "python", "bash" antes do path).
    hooks = data.get("hooks", {})
    for event, configs in hooks.items():
        for cfg in configs:
            for h in cfg.get("hooks", []):
                cmd = h.get("command", "")
                for token in cmd.split():
                    if "${CLAUDE_PROJECT_DIR}" in token:
                        rel = token.replace("${CLAUDE_PROJECT_DIR}/", "").strip("\"'")
                        if not (ROOT / rel).exists():
                            errors.append(
                                f"{p}: hook {event} aponta pra '{rel}' que NÃO existe"
                            )


def main() -> int:
    print(f"=== Validando {CLAUDE} ===\n")

    skills = sorted((CLAUDE / "skills").iterdir())
    for s in skills:
        if s.is_dir() and (s / "SKILL.md").exists():
            check_skill(s / "SKILL.md")
    print(f"Skills: {sum(1 for s in skills if s.is_dir())}")

    agents = sorted((CLAUDE / "agents").glob("*.md"))
    for a in agents:
        check_agent(a)
    print(f"Agents: {len(agents)}")

    cmds = sorted((CLAUDE / "commands").glob("*.md"))
    for c in cmds:
        check_command(c)
    print(f"Commands: {len(cmds)}")

    rules = sorted((CLAUDE / "rules").glob("*.md"))
    for r in rules:
        check_rule(r)
    print(f"Rules: {len(rules)}")

    check_settings()

    print(f"\nErros:    {len(errors)}")
    print(f"Warnings: {len(warnings)}")
    if errors:
        print("\n--- ERROS ---")
        for e in errors:
            print(f"  {e}")
    if warnings:
        print("\n--- WARNINGS ---")
        for w in warnings:
            print(f"  {w}")

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

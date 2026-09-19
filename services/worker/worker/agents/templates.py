"""Prompt template loading + variable substitution (Appendix C)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

_PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"


def load_prompt(name: str) -> str:
    path = _PROMPTS_DIR / name
    return path.read_text(encoding="utf-8")


def render(template: str, variables: dict[str, Any]) -> str:
    """Simple ``{{var}}`` substitution. Missing keys become empty strings."""
    out = template
    for key, value in variables.items():
        out = out.replace("{{" + key + "}}", str(value) if value is not None else "")
    # Strip any leftover placeholders to keep prompts tidy.
    while "{{" in out and "}}" in out:
        start = out.index("{{")
        end = out.index("}}", start) + 2
        out = out[:start] + out[end:]
    return out

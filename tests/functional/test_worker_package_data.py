"""D4 regression: worker wheel ships agent prompt templates."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKER = REPO_ROOT / "services" / "worker"
PROMPTS = (
    "worker/agents/prompts/planner.txt",
    "worker/agents/prompts/collector_summary.txt",
    "worker/agents/prompts/rca.txt",
    "worker/agents/prompts/remediation.txt",
)


def test_worker_wheel_includes_all_prompt_templates():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(out), str(WORKER)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr or proc.stdout
        wheels = list(out.glob("*.whl"))
        assert len(wheels) == 1, wheels
        with zipfile.ZipFile(wheels[0]) as zf:
            names = set(zf.namelist())
        for prompt in PROMPTS:
            assert prompt in names, f"{prompt} missing from wheel; have={[n for n in names if 'agents' in n]}"

"""FP-M6-19: walkthrough script --self-test against synthetic harness."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tests/e2e/manual/real_cluster_walkthrough.py"


def test_walkthrough_self_test_against_fake_harness(tmp_path):
    out = tmp_path / "report.json"
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--self-test", "--out", str(out)],
        cwd=str(REPO),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["failures"] == 0
    assert report["summary"]["tools_total"] >= 10
    assert report["registration"]["steps"]
    # PENDING_CREDENTIALS sequencing
    steps = [s["name"] for s in report["registration"]["steps"]]
    assert "start_probe_without_credentials" in steps
    assert "assert_online" in steps
    for t in report["tools"]:
        assert t["envelope_valid"] is True

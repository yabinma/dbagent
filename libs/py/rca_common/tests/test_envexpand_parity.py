"""Go↔Python ${VAR} interpolation parity (design.md §11.1.5 / DW2)."""
from __future__ import annotations

import os
from pathlib import Path

import yaml

from rca_common.config import _interpolate

FIXTURE = (
    Path(__file__).resolve().parents[4]
    / "internal"
    / "envexpand"
    / "testdata"
    / "parity.yaml"
)


def test_python_interpolate_matches_shared_fixture_adversarial_values(monkeypatch):
    monkeypatch.setenv("HASH_PW", "p@ss #word")
    monkeypatch.setenv("COLON_PW", "a: b")
    monkeypatch.setenv("STAR_TOKEN", "*secret")
    monkeypatch.setenv("NL_TOKEN", "line1\nline2")

    raw = yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))
    out = _interpolate(raw)

    assert out["postgres_dsn"] == "postgres://u:p@ss #word@h/db"
    assert out["bootstrap_token"] == "a: b"
    assert out["star"] == "*secret"
    assert out["multi"] == "line1\nline2"
    assert out["nested"]["key"] == "prefix-p@ss #word-suffix"
    assert out["plain"] == "p@ss #word"

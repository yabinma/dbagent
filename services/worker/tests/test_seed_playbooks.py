"""Unit tests for seed_playbooks idempotency (FP-M5-11)."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from worker.playbooks import PLAYBOOK_CATALOG

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "seed_playbooks.py"
sys.path.insert(0, str(_SCRIPT.parent))
from seed_playbooks import seed_playbooks  # noqa: E402


def _load_script():
    spec = importlib.util.spec_from_file_location("seed_playbooks_under_test", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class _FakeSession:
    def __init__(self):
        self.store: dict = {}
        self.commits = 0

    def get(self, model, key):
        return self.store.get(key)

    def add(self, obj):
        self.store[obj.playbook_id] = obj

    def commit(self):
        self.commits += 1

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_seed_upserts_five_and_is_idempotent():
    class PB:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    import rca_common.db.models as models

    orig = models.Playbook
    models.Playbook = PB
    try:
        session = _FakeSession()
        c1 = seed_playbooks(session)
        assert c1["inserted"] == 5
        assert c1["updated"] == 0
        assert len(session.store) == 5
        first = next(iter(session.store.values()))
        first.maturity = {"approved_runs": 9, "success": 8, "rollbacks": 0}
        c2 = seed_playbooks(session)
        assert c2["inserted"] == 0
        assert c2["updated"] == 5
        assert first.maturity["approved_runs"] == 9
        assert set(session.store) == {e["playbook_id"] for e in PLAYBOOK_CATALOG}
    finally:
        models.Playbook = orig


def test_seed_accepts_explicit_catalog_and_default_fields():
    class PB:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    import rca_common.db.models as models

    orig = models.Playbook
    models.Playbook = PB
    try:
        session = _FakeSession()
        catalog = [
            {
                "playbook_id": "custom.one",
                "risk_level": "R1",
                # omit optional fields so defaults in seed_playbooks fire
            }
        ]
        counts = seed_playbooks(session, catalog=catalog)
        assert counts == {"inserted": 1, "updated": 0}
        row = session.store["custom.one"]
        assert row.platform_type == "presto"
        assert row.params_schema == {}
        assert row.steps == {}
        assert row.verification == {}
        assert row.auto_eligible is False
    finally:
        models.Playbook = orig


def test_main_requires_dsn(caplog):
    mod = _load_script()
    with caplog.at_level("ERROR", logger="seed_playbooks"):
        assert mod.main([]) == 1
    assert "postgres DSN required" in caplog.text


def test_main_seeds_via_postgres_dsn_flag(monkeypatch, caplog):
    mod = _load_script()
    session = _FakeSession()

    class _Factory:
        def __call__(self):
            return session

    monkeypatch.setattr(
        "rca_common.db.session.make_engine", lambda dsn: MagicMock(name="engine")
    )
    monkeypatch.setattr(
        "rca_common.db.session.make_session_factory", lambda eng: _Factory()
    )

    class PB:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    import rca_common.db.models as models

    orig = models.Playbook
    models.Playbook = PB
    try:
        with caplog.at_level("INFO", logger="seed_playbooks"):
            code = mod.main(["--postgres-dsn", "postgresql://x/y"])
        assert code == 0
        assert "inserted=" in caplog.text
        assert session.commits == 1
        assert len(session.store) == 5
    finally:
        models.Playbook = orig


def test_main_reads_dsn_from_config(tmp_path, monkeypatch, caplog):
    mod = _load_script()
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        "storage:\n  postgres_dsn: postgresql://from-config/db\n"
        "temporal:\n  address: t:7233\n  namespace: default\n  task_queue: q\n"
        "model_gateway:\n  url: http://x\n  master_key: k\n"
        "signing:\n  key_path: /tmp/k\n",
        encoding="utf-8",
    )
    session = _FakeSession()

    class _Factory:
        def __call__(self):
            return session

    monkeypatch.setattr(
        "rca_common.db.session.make_engine", lambda dsn: MagicMock(name="engine")
    )
    monkeypatch.setattr(
        "rca_common.db.session.make_session_factory", lambda eng: _Factory()
    )

    class PB:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    import rca_common.db.models as models

    orig = models.Playbook
    models.Playbook = PB
    try:
        with caplog.at_level("INFO", logger="seed_playbooks"):
            code = mod.main(["--config", str(cfg)])
        assert code == 0
        assert session.commits == 1
    finally:
        models.Playbook = orig

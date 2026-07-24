"""Unit tests for seed_playbooks idempotency (FP-M5-11)."""
from __future__ import annotations

import sys
from pathlib import Path

from worker.playbooks import PLAYBOOK_CATALOG

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from seed_playbooks import seed_playbooks  # noqa: E402


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

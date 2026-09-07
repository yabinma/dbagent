"""Hermetic fixtures for FP-IG-20's runtime topology sibling (C3).

The live kind/crictl walk stays in tests/e2e. These import the same
classifier and assertions so the delivery job — which cannot start
kind — still makes the forbidden trees and watches the guard go red.
"""
from __future__ import annotations

import sys

from delivery_helpers import REPO_ROOT

_E2E = REPO_ROOT / "tests" / "e2e"
if str(_E2E) not in sys.path:
    sys.path.insert(0, str(_E2E))

import test_e2e_process_topology as topology  # noqa: E402


def test_ingest_role_multiset_rejects_unclassified_filler():
    topology.test_ingest_role_multiset_rejects_unclassified_filler()


def test_singleton_rows_require_command_identity():
    topology.test_singleton_rows_require_command_identity()


def test_container_init_pid_does_not_bind_to_exited_sibling(monkeypatch):
    topology.test_container_init_pid_does_not_bind_to_exited_sibling(monkeypatch)


def test_container_init_pid_fails_when_target_is_not_running(monkeypatch):
    topology.test_container_init_pid_fails_when_target_is_not_running(monkeypatch)


def test_container_init_pid_requires_exactly_one_running_match(monkeypatch):
    topology.test_container_init_pid_requires_exactly_one_running_match(monkeypatch)

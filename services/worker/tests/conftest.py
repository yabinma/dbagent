"""Shared fixtures for worker unit tests."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from rca_common.llmclient.objectstore import FakeObjectStore

# Allow `from helpers import ScriptedLLM` in test modules.
_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))


@pytest.fixture
def fake_object_store():
    return FakeObjectStore()

"""Repo-root pytest conftest.

Makes the repo root importable as a namespace-package root (PEP 420, no
`__init__.py` files needed) so functional tests under `tests/` can do
`from tests.mocks.llm.mock_llm_server import MockLLMServer` regardless of
which subdirectory pytest is invoked from.
"""
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

"""Unit tests for control tools (Section 8.5)."""
import pytest

from worker.control_tools import FakeSourceStore, run_control_tool


@pytest.mark.asyncio
async def test_fetch_source_and_diff_and_search():
    store = FakeSourceStore(
        files={"main.java": "class Main {}"},
        commits=[{"sha": "abc", "message": "fix OOM in memory pool"}],
    )
    r1 = await run_control_tool("fetch_source", {"file_path": "main.java", "ref": "0.298"}, source_store=store, evidence_lookup=lambda _: None)
    assert r1["exit_code"] == 0
    assert "Main" in r1["data"]["content"]

    r2 = await run_control_tool(
        "diff_versions",
        {"path_or_symbol": "Main", "from_tag": "0.297", "to_tag": "0.298"},
        source_store=store,
        evidence_lookup=lambda _: None,
    )
    assert "---" in r2["data"]["diff"]

    r3 = await run_control_tool(
        "search_commits",
        {"keyword": "OOM", "from_tag": "0.290", "limit": 5},
        source_store=store,
        evidence_lookup=lambda _: None,
    )
    assert len(r3["data"]["commits"]) == 1


@pytest.mark.asyncio
async def test_read_evidence_byte_range():
    row = {"payload": "abcdefghijklmnopqrstuvwxyz"}

    def lookup(eid):
        return row

    r = await run_control_tool(
        "read_evidence",
        {"evidence_id": "e1", "byte_range": [0, 5]},
        source_store=FakeSourceStore(),
        evidence_lookup=lookup,
    )
    assert r["data"]["bytes"] == "abcde"
    assert r["data"]["byte_length"] == 5


@pytest.mark.asyncio
async def test_unknown_control_tool():
    r = await run_control_tool("nope", {}, source_store=FakeSourceStore(), evidence_lookup=lambda _: None)
    assert r["exit_code"] == 1

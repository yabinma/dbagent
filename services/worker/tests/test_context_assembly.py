"""B14: RCA context assembly (Section 5.3)."""
import time

from worker.context_assembly import (
    assemble_rca_context,
    compact_report,
    format_approver_feedback,
)


def _evidence(n_rounds=15, per_round=8):
    out = []
    for r in range(1, n_rounds + 1):
        for i in range(per_round):
            out.append(
                {
                    "evidence_id": f"e-{r}-{i}",
                    "tool_name": f"tool_{i}",
                    "round": r,
                    "summary": f"summary for round {r} tool {i} " + ("x" * 50),
                    "payload": {"detail": "full payload " + ("y" * 200), "round": r, "i": i},
                }
            )
    return out


def test_b14_prompt_build_under_200ms_and_no_latest_truncation():
    evidence = _evidence(15, 8)
    reports = [{"status": "need_more_data", "confidence": 0.5, "rca_compact": f"r{i}"} for i in range(14)]
    t0 = time.perf_counter()
    result = assemble_rca_context(
        event={"error_summary": "oom", "platform_key": "presto-us1"},
        evidence=evidence,
        reports=reports,
        round_num=15,
        max_rounds=15,
        spent_usd=1.23,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert elapsed_ms < 200, f"B14 FAILED: build took {elapsed_ms:.1f}ms"
    assert result["metrics"]["build_ms"] < 200
    assert result["metrics"]["latest_round_truncated"] is False
    # Latest-round full payloads must appear in the assembled context.
    assert "e-15-0" in result["variables"]["latest_evidence_full"]
    assert "full payload" in result["variables"]["latest_evidence_full"]


def test_compact_report_keeps_key_fields():
    c = compact_report(
        {
            "status": "concluded",
            "confidence": 0.9,
            "root_cause": {"summary": "oom"},
            "extra_noise": 1,
            "rca_compact": "short",
            "missing_info": [],
        }
    )
    assert c["status"] == "concluded"
    assert "extra_noise" not in c


def test_previous_reports_compact_includes_all_prior_reports():
    """W4 lock-in: `reports` is already prior-only; do not drop via [:-1].

    When analyze is called for round N, ctx['reports'] holds rounds 1..N-1.
    previous_reports_compact must include every one of those priors (incl. the
    most recent), not reports[:-1] which would omit the latest prior.
    """
    reports = [
        {"status": "need_more_data", "confidence": 0.4, "rca_compact": "round-1-compact"},
        {"status": "need_more_data", "confidence": 0.6, "rca_compact": "round-2-compact"},
    ]
    result = assemble_rca_context(
        event={"error_summary": "oom", "platform_key": "presto-us1"},
        evidence=_evidence(3, 2),
        reports=reports,
        round_num=3,
        max_rounds=15,
        spent_usd=0.5,
    )
    prev = result["variables"]["previous_reports_compact"]
    assert "round-1-compact" in prev
    assert "round-2-compact" in prev  # must NOT be dropped by [:-1]
    # Single prior report is kept in full (would be empty under the bug).
    single = assemble_rca_context(
        event={"error_summary": "oom"},
        evidence=_evidence(2, 1),
        reports=[{"status": "need_more_data", "confidence": 0.5, "rca_compact": "only-prior"}],
        round_num=2,
        max_rounds=15,
        spent_usd=0.1,
    )
    assert "only-prior" in single["variables"]["previous_reports_compact"]


def test_approver_feedback_injected_into_rca_context():
    """M4 FP-M4-12: need_more / denied comments appear in the next RCA round."""
    result = assemble_rca_context(
        event={"error_summary": "oom"},
        evidence=_evidence(1, 1),
        reports=[],
        round_num=2,
        max_rounds=15,
        spent_usd=0.1,
        approver_feedback=["please collect GC logs", "check coordinator heap"],
    )
    fb = result["variables"]["approver_feedback"]
    assert "Approver feedback from prior rounds:" in fb
    assert "please collect GC logs" in fb
    assert "check coordinator heap" in fb

    empty = assemble_rca_context(
        event={"error_summary": "oom"},
        evidence=_evidence(1, 1),
        reports=[],
        round_num=1,
        max_rounds=15,
        spent_usd=0.0,
        approver_feedback=[],
    )
    assert empty["variables"]["approver_feedback"] == ""
    assert format_approver_feedback(None) == ""
    assert format_approver_feedback(["  "]) == ""

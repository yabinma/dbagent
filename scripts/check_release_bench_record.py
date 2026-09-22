#!/usr/bin/env python3
"""FP-BOD-5: refuse a ``v*`` tag without a passing on-demand benchmark record.

B1 and B11 left per-push CI (``design/slices/bench-on-demand/design.md``).
They are measured on a developer host, and the six print lines those two runs
already emit are committed, verbatim, to
``docs/runbooks/bench-on-demand-results.txt`` with one envelope field --
``measured_sha`` -- in front of them.

This program is the tag gate. It reads the record **from the tagged tree**
(``git show <tag-commit>:<path>``), never the working-tree copy, so a dirty
checkout cannot authorize a tag and a clean one cannot be denied by local
edits. It starts no container, no pytest and no ``integration-test.sh``: a
benchmark is not re-run at tag time, because the whole point of the slice is
that these two benchmarks need a host GitHub does not rent.

It exits 0 only when every rule in ``release-record.md`` §2 holds, and
otherwise prints exactly one line::

    release bench record: <reason>

Every value it converts is checked for SHAPE before it is converted. The
B1 side compares strings only, so it performs no conversion at all; the
B11 side has two (``B11 writers=`` and ``combined_rate_per_sec``), and
both go through an ASCII decimal pattern first -- see ``_ASCII_INT_RE``
below for why ``int()`` and ``float()`` alone are not a check.

``<reason>`` is one of ``record_missing``, ``record_invalid``, ``not_on_main``,
``sha_unknown``, ``tree_changed``, ``b1_miss``, ``b11_miss``. A block whose
measured tree differs from the tagged tree by more than the results file is
not a candidate, and release-record.md §2.1 names the no-candidate outcome
``record_missing``; that sentence, not the width of the vocabulary, is the
rule this program implements.

``product_p99_lt_150_ms=missed`` is NOT a refusal. The product run records the
p99 as a token and does not fail on it (design.md §3.4); refusing a tag for it
here would reintroduce, at the tag, exactly the latency gate the slice removed
from CI.
"""

from __future__ import annotations

import math
import os
import re
import subprocess
import sys

#: The record, at the same path in the repository and in the tagged tree.
RECORD_PATH = "docs/runbooks/bench-on-demand-results.txt"

#: The release branch. ``on.push.branches`` is ``main``; a tag of anything that
#: is not an ancestor of it is not a release of this repository.
RELEASE_REF = "origin/main"

#: A block is exactly these seven lines, in this order. Line 1 is the envelope;
#: lines 2-7 are the two runs' existing fingerprints, copied verbatim.
BLOCK_PREFIXES = (
    "measured_sha=",
    "B1 env=",
    "B11 writers=",
    "B11 writer_map=",
    "B11 single_writer_rate=",
    "B11 env=",
    "B11 diagnostics=",
)
BLOCK_LINES = len(BLOCK_PREFIXES)

#: A separator line stands between blocks and nowhere else.
SEPARATOR = "---"

_HEX = frozenset("0123456789abcdef")

#: The two shapes the live tests PRINT, and the only shapes this program
#: will convert. `B11 writers=` is `len(instances)`; `combined_rate_per_sec`
#: is `f"{rate:.1f}"`. Both are restated here as ASCII decimal literals
#: rather than left to `int()` and `float()`, because those two
#: constructors accept a great deal more than either producer can emit --
#: `nan`, `inf`, `1.7e3`, `1_000.0`, and digits from any Unicode script
#: (Python reads an Arabic-Indic `1000.0` as the float 1000.0). Every one
#: of those DEFEATS the bar rather than failing it: `nan < 1000.0` and
#: `nan >= 1000.0` are BOTH false, so a checker that only asks "is it
#: below the bar" lets NaN authorize a release. A token outside these
#: shapes is a broken record, not a miss.
_ASCII_INT_RE = re.compile(r"\A[0-9]+\Z")
_ASCII_DECIMAL_RE = re.compile(r"\A-?[0-9]+(?:\.[0-9]+)?\Z")

VERDICT_MET = "met"
VERDICT_MISSED = "missed"

#: B1 fields whose value is fixed by the profile. Any other value means the
#: block did not come from the product run at all.
B1_IDENTITY_FIELDS = {
    "placement_profile": "product-exclusive",
    "measurement_authority": "product-local-reference",
}

#: The two product tokens that decide a release. ``product_p99_lt_150_ms`` is
#: deliberately absent: it is required to be present and to be one of the two
#: verdict words, and neither value refuses the tag.
B1_GATING_VERDICT_FIELDS = ("product_errors_eq_zero", "product_served_eq_offered")

B1_RECORDED_VERDICT_FIELDS = ("product_p99_lt_150_ms",)

#: The shipped writer model (design.md §3.5): ingest-gateway x4, dashboard-api,
#: probe-gateway, temporal-worker.
B11_WRITERS = 7

#: The bar ``test_b11_audit_llm_insert_throughput`` asserts.
B11_RATE_FLOOR = 1000.0

#: The field inside the 21-field ``B11 diagnostics=`` line that carries it.
B11_RATE_FIELD = "combined_rate_per_sec"


class _Reason(Exception):
    """One closed refusal reason, raised where it is decided."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _git(repo: str, *args: str) -> "subprocess.CompletedProcess[str]":
    """Run one git command in ``repo`` and return the completed process.

    Never raises on a non-zero status: every caller here treats a failure as a
    decision (an unknown sha, a missing blob), not as an error to propagate.
    """
    return subprocess.run(
        ("git", "-C", repo, *args),
        capture_output=True,
        text=True,
        check=False,
    )


def _is_sha(value: str) -> bool:
    return len(value) == 40 and all(character in _HEX for character in value)


def parse_blocks(record_text: str) -> "list[dict[str, str]]":
    """Split the record into blocks, or raise ``record_invalid``.

    The shape is exact and the file is judged as a whole: one malformed block
    invalidates the file rather than being skipped in favour of a later one. A
    leftover investigation block that was hand-edited is therefore a refusal,
    not a silently ignored line.
    """
    if not record_text:
        raise _Reason("record_invalid")
    if record_text.startswith("﻿"):
        raise _Reason("record_invalid")
    if "\r" in record_text:
        raise _Reason("record_invalid")

    lines = record_text.split("\n")
    # A single trailing newline terminates the last line and is not a line.
    if lines and lines[-1] == "":
        lines.pop()
    if not lines:
        raise _Reason("record_invalid")

    groups: "list[list[str]]" = [[]]
    for line in lines:
        if line == SEPARATOR:
            groups.append([])
            continue
        groups[-1].append(line)

    blocks: "list[dict[str, str]]" = []
    for group in groups:
        if len(group) != BLOCK_LINES:
            raise _Reason("record_invalid")
        block: "dict[str, str]" = {}
        for prefix, line in zip(BLOCK_PREFIXES, group):
            if not line.startswith(prefix):
                raise _Reason("record_invalid")
            block[prefix] = line[len(prefix):]
        sha = block["measured_sha="]
        if not _is_sha(sha):
            raise _Reason("record_invalid")
        blocks.append(block)
    return blocks


def parse_fields(payload: str) -> "dict[str, str]":
    """Split one fingerprint line's payload into fields.

    The fingerprint's free-form values are already percent-encoded by the live
    tests, so a raw comma is a field boundary and the first ``=`` of a field
    separates its name from its value. A field with no ``=`` is dropped rather
    than guessed at; the required-field checks above decide what is missing.
    """
    fields: "dict[str, str]" = {}
    for raw in payload.split(","):
        if "=" not in raw:
            continue
        name, _, value = raw.partition("=")
        if name not in fields:
            fields[name] = value
    return fields


def _b1_reason(block: "dict[str, str]") -> "str | None":
    fields = parse_fields(block["B1 env="])

    for name, expected in B1_IDENTITY_FIELDS.items():
        if fields.get(name) != expected:
            return "record_invalid"

    placement_ok = fields.get("placement_ok")
    if placement_ok is None:
        return "record_invalid"
    if placement_ok != "1":
        return "b1_miss"

    for name in B1_GATING_VERDICT_FIELDS:
        value = fields.get(name)
        if value == VERDICT_MET:
            continue
        if value == VERDICT_MISSED:
            return "b1_miss"
        return "record_invalid"

    for name in B1_RECORDED_VERDICT_FIELDS:
        # Present and truthful, and neither value refuses the tag: the product
        # run records the p99 and does not gate on it (design.md §3.4).
        if fields.get(name) not in (VERDICT_MET, VERDICT_MISSED):
            return "record_invalid"

    return None


def _b11_reason(block: "dict[str, str]") -> "str | None":
    writers = block["B11 writers="].strip()
    if not _ASCII_INT_RE.match(writers):
        return "record_invalid"
    if int(writers) != B11_WRITERS:
        return "b11_miss"

    for prefix in ("B11 writer_map=", "B11 single_writer_rate=", "B11 env="):
        # Present and non-empty, and not interpreted: they are in the block so
        # that it is the run's existing print and not a reduced subset of it.
        if not block[prefix].strip():
            return "record_invalid"

    diagnostics = parse_fields(block["B11 diagnostics="])
    raw_rate = diagnostics.get(B11_RATE_FIELD)
    if raw_rate is None:
        return "record_invalid"
    # Shape first, value second. The shape check is what refuses `nan` and
    # `inf`; `math.isfinite` stays behind it so the intent survives a future
    # loosening of the pattern. The two verdicts stay distinct either way: a
    # FINITE rate below the floor is a real `b11_miss`, and only a rate this
    # program cannot represent as a comparison is a broken record.
    raw_rate = raw_rate.strip()
    if not _ASCII_DECIMAL_RE.match(raw_rate):
        return "record_invalid"
    rate = float(raw_rate)
    if not math.isfinite(rate):  # pragma: no cover - the pattern refused it
        return "record_invalid"
    if rate < B11_RATE_FLOOR:
        return "b11_miss"
    return None


def evaluate(repo: str, tag_sha: str, record_text: str) -> "str | None":
    """Return ``None`` when the record authorizes this tag, else one reason.

    The measured commit is normally the tag's parent: the record is written
    after the run and committed, so the tagged tree contains the file and the
    measured tree does not. Requiring the two SHAs to be equal would reject
    that, and a block whose ``measured_sha`` is the commit containing it cannot
    honestly exist -- so that case is ``record_invalid``, not a fall-through to
    an older block.
    """
    try:
        blocks = parse_blocks(record_text)
    except _Reason as reason:
        return reason.reason

    resolved = _git(repo, "rev-parse", f"{tag_sha}^{{commit}}")
    if resolved.returncode != 0:
        return "sha_unknown"
    tag_commit = resolved.stdout.strip()

    ancestry = _git(repo, "merge-base", "--is-ancestor", tag_commit, RELEASE_REF)
    if ancestry.returncode != 0:
        return "not_on_main"

    for block in blocks:
        measured = block["measured_sha="]
        if _git(repo, "cat-file", "-e", f"{measured}^{{commit}}").returncode != 0:
            return "sha_unknown"
        if measured == tag_commit:
            return "record_invalid"

    candidates: "list[tuple[int, dict[str, str]]]" = []
    for block in blocks:
        measured = block["measured_sha="]
        strict = _git(repo, "merge-base", "--is-ancestor", measured, tag_commit)
        if strict.returncode != 0:
            continue
        diff = _git(repo, "diff", "--name-only", measured, tag_commit)
        if diff.returncode != 0:
            return "sha_unknown"
        names = [line for line in diff.stdout.split("\n") if line]
        # An empty diff is not a candidate either: identical trees mean the
        # measured commit would have to contain a block naming itself.
        if names != [RECORD_PATH]:
            continue
        distance = _git(repo, "rev-list", "--count", f"{measured}..{tag_commit}")
        if distance.returncode != 0:
            return "sha_unknown"
        candidates.append((int(distance.stdout.strip()), block))

    if not candidates:
        # release-record.md §2.1: no candidate and no invalidating block is
        # `record_missing`. A block that measured a different product tree is
        # not a candidate, so this covers it too -- a record of another tree
        # is, for this tag, no record at all.
        return "record_missing"

    # The closest candidate decides, and it decides alone: an older passing
    # block never overrides a nearer miss. ``min`` keeps the last block of a
    # tie because the list is built in file order and comparison is on the
    # distance alone.
    best_distance = min(distance for distance, _ in candidates)
    authorizing = [block for distance, block in candidates if distance == best_distance][-1]

    reason = _b1_reason(authorizing)
    if reason is not None:
        return reason
    return _b11_reason(authorizing)


def load_record(repo: str, tag_sha: str) -> "str | None":
    """Read the record out of the tagged tree, or ``None`` when it is absent."""
    shown = _git(repo, "show", f"{tag_sha}:{RECORD_PATH}")
    if shown.returncode != 0:
        return None
    return shown.stdout


def main(argv: "list[str] | None" = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    repo = argv[0] if argv else os.environ.get("GITHUB_WORKSPACE") or os.getcwd()
    tag_sha = os.environ.get("GITHUB_SHA", "HEAD")

    resolved = _git(repo, "rev-parse", f"{tag_sha}^{{commit}}")
    if resolved.returncode != 0:
        print("release bench record: sha_unknown")
        return 1
    tag_commit = resolved.stdout.strip()

    record_text = load_record(repo, tag_commit)
    if record_text is None:
        print("release bench record: record_missing")
        return 1

    reason = evaluate(repo, tag_commit, record_text)
    if reason is not None:
        print(f"release bench record: {reason}")
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())

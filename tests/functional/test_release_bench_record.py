"""FP-BOD-5: the `v*` tag gate's decision table (release-record.md §2).

`evaluate` and `main` are called IN-PROCESS against a temporary git
repository. A subprocess of the script would exercise the same logic without
being measurable, and the functional job runs this file under
``--cov=check_release_bench_record --cov-branch --cov-fail-under=81``
(coverage 7.15 resolves a `source` entry as a package or importable name, not
as a `.py` path: the module name selects exactly this one file).

Every record below is built from declared line literals rather than from the
script's own constants: a fixture derived from its subject cannot detect a
change in it.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_release_bench_record.py"
RECORD_PATH = "docs/runbooks/bench-on-demand-results.txt"

_spec = importlib.util.spec_from_file_location("check_release_bench_record", SCRIPT_PATH)
assert _spec and _spec.loader
checker = importlib.util.module_from_spec(_spec)
sys.modules["check_release_bench_record"] = checker
_spec.loader.exec_module(checker)

#: One passing B1 fingerprint, in the shape the product run prints: identity
#: fields, the placement verdict, the three product tokens, and a reported
#: tail. The tail carries a percent-encoded comma so the field splitter is
#: exercised on a real value rather than a clean one.
B1_MET = (
    "B1 env=cpus=16,cpu_model=Synthetic%20Fixture,image=os-release:0000000000000000,"
    "tier=reference,workers=4,placement_profile=product-exclusive,placement_schema=2,"
    "placement_run_id=0123456789abcdef0123456789abcdef,"
    "measurement_authority=product-local-reference,placement_ok=1,"
    "gateway_allowed_cpus=0-3,postgres_allowed_cpus=4-6,driver_allowed_cpus=7,"
    "product_errors_eq_zero=met,product_p99_lt_150_ms=met,product_served_eq_offered=met,"
    "gateway_thread_siblings_pct=0:0%2C8+8:0%2C8,host_steal_usec=0"
)
B11_WRITERS = "B11 writers=7"
B11_WRITER_MAP = "B11 writer_map=ingest-gateway:4,dashboard-api:1,probe-gateway:1,temporal-worker:1"
B11_SINGLE = "B11 single_writer_rate=612.4/s"
B11_ENV = "B11 env=cpus=16,serial_commit_ms=0.81,combined_over_single=2.85"
B11_DIAGNOSTICS = (
    "B11 diagnostics=combined_rate_per_sec=1745.3,serial_commit_ms=0.81,"
    "combined_over_single=2.85,host_steal_usec=0,host_psi_io_full_usec=0,"
    "storage_rotational=0"
)


def _block(
    measured_sha: str,
    *,
    b1: str = B1_MET,
    writers: str = B11_WRITERS,
    diagnostics: str = B11_DIAGNOSTICS,
    writer_map: str = B11_WRITER_MAP,
    single: str = B11_SINGLE,
    env: str = B11_ENV,
) -> str:
    return "\n".join(
        [f"measured_sha={measured_sha}", b1, writers, writer_map, single, env, diagnostics]
    )


def _record(*blocks: str) -> str:
    return "\n---\n".join(blocks) + "\n"


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(repo), *args), capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    """A repository with a product commit, a results commit, and `origin/main`.

    The shape is the real one: `measured_sha` is the parent, the tag commit
    adds only the results file, and `origin/main` is a real remote-tracking
    ref so `merge-base --is-ancestor` has something to answer.
    """
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "t")
    (root / "product.py").write_text("x = 1\n", encoding="utf-8")
    (root / "docs" / "runbooks").mkdir(parents=True)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "product")
    return root


def _write_record(root: Path, text: str) -> None:
    (root / RECORD_PATH).write_text(text, encoding="utf-8")


def _commit_record(root: Path, text: str, message: str = "record") -> str:
    _write_record(root, text)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", message)
    return _git(root, "rev-parse", "HEAD")


def _publish_main(root: Path) -> None:
    """Make the current head reachable from `origin/main`, without a remote."""
    _git(root, "update-ref", "refs/remotes/origin/main", "HEAD")


def _evaluate(root: Path, tag_sha: str, text: str) -> "str | None":
    return checker.evaluate(str(root), tag_sha, text)


# ---------------------------------------------------------------------------
# The authorizing case, and the one miss that is NOT a refusal.
# ---------------------------------------------------------------------------


def test_release_bench_record_refuses_miss_and_accepts_p99_miss(repo: Path):
    """FP-BOD-5 [function test]: a closer miss decides; a p99 miss does not.

    Named for two failures.

    The first is an older passing block overriding a nearer miss. The script
    evaluates the AUTHORIZING block alone -- the candidate closest to the tag
    -- so a record whose most recent run fell short refuses the tag even
    though an earlier run passed. A checker that scanned for "any passing
    block" would ship the regression.

    The second is the opposite mistake: refusing a release because the
    recorded due-time p99 missed. `product_p99_lt_150_ms` is a recorded token
    (design.md §3.4); the run that produced it passed, and the tag it
    authorizes is a real release.
    """
    # BOTH blocks must be candidates, or this test would be deciding on the
    # tree-diff rule instead of on distance. Every commit after the first is
    # a results-only commit, so the diff from either measured sha to the tag
    # commit names the record file and nothing else.
    older = _git(repo, "rev-parse", "HEAD")
    nearer = _commit_record(repo, _record(_block(older)), "record 1")
    missed = B1_MET.replace("product_served_eq_offered=met", "product_served_eq_offered=missed")
    tag_sha = _commit_record(
        repo, _record(_block(older), _block(nearer, b1=missed)), "record 2"
    )
    _publish_main(repo)
    text = (repo / RECORD_PATH).read_text(encoding="utf-8")

    # Fixture precondition: the older block really is a candidate this checker
    # would accept on its own. Without it, "the closer one decided" would be
    # indistinguishable from "the older one was never eligible".
    assert _evaluate(repo, tag_sha, _record(_block(older))) is None
    assert _evaluate(repo, tag_sha, text) == "b1_miss", "an older pass overrode a miss"

    # ...and the same shape with the p99 token missed is a release.
    p99_missed = B1_MET.replace("product_p99_lt_150_ms=met", "product_p99_lt_150_ms=missed")
    tag_sha = _commit_record(
        repo, _record(_block(older), _block(nearer, b1=p99_missed)), "record 3"
    )
    _publish_main(repo)
    text = (repo / RECORD_PATH).read_text(encoding="utf-8")
    assert _evaluate(repo, tag_sha, text) is None, "a recorded p99 miss refused a release"


# ---------------------------------------------------------------------------
# The decision table, case by case (release-record.md §2).
# ---------------------------------------------------------------------------


def test_record_missing_when_the_blob_is_absent(repo: Path):
    _publish_main(repo)
    tag_sha = _git(repo, "rev-parse", "HEAD")
    assert checker.load_record(str(repo), tag_sha) is None
    assert checker.main([str(repo)]) is not None  # smoke: main is callable


def test_malformed_blocks_are_record_invalid(repo: Path):
    parent = _git(repo, "rev-parse", "HEAD")
    tag_sha = _commit_record(repo, _record(_block(parent)))
    _publish_main(repo)
    good = (repo / RECORD_PATH).read_text(encoding="utf-8")
    assert _evaluate(repo, tag_sha, good) is None

    for label, text in (
        ("empty", ""),
        ("bom", "﻿" + good),
        ("crlf", good.replace("\n", "\r\n")),
        ("short block", "\n".join(good.split("\n")[:5]) + "\n"),
        ("reordered", "\n".join([good.split("\n")[1], good.split("\n")[0]] + good.split("\n")[2:])),
        ("blank line inside", good.replace(B11_WRITERS, "\n" + B11_WRITERS, 1)),
        ("bad sha", good.replace(parent, "zz" + parent[2:], 1)),
        ("short sha", good.replace(parent, parent[:20], 1)),
        ("stray separator", good + "---\n"),
    ):
        assert _evaluate(repo, tag_sha, text) == "record_invalid", label


def test_a_tag_outside_origin_main_is_not_on_main(repo: Path):
    parent = _git(repo, "rev-parse", "HEAD")
    _publish_main(repo)
    tag_sha = _commit_record(repo, _record(_block(parent)))
    # origin/main still points at the product commit: the tag is ahead of it.
    text = (repo / RECORD_PATH).read_text(encoding="utf-8")
    assert _evaluate(repo, tag_sha, text) == "not_on_main"


def test_an_unresolvable_measured_sha_is_sha_unknown(repo: Path):
    parent = _git(repo, "rev-parse", "HEAD")
    tag_sha = _commit_record(repo, _record(_block(parent)))
    _publish_main(repo)
    text = _record(_block("0" * 40))
    assert _evaluate(repo, tag_sha, text) == "sha_unknown"
    # ...and an unresolvable TAG is the same verdict.
    assert _evaluate(repo, "1" * 40, text) == "sha_unknown"


def test_a_tree_that_differs_by_a_product_file_is_no_candidate(repo: Path):
    """The measured tree and the released tree differ by the record, or not at all."""
    parent = _git(repo, "rev-parse", "HEAD")
    # The tag commit changes a product file as well as the record.
    _write_record(repo, _record(_block(parent)))
    (repo / "product.py").write_text("x = 99\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "record and product")
    tag_sha = _git(repo, "rev-parse", "HEAD")
    _publish_main(repo)
    text = (repo / RECORD_PATH).read_text(encoding="utf-8")
    assert _evaluate(repo, tag_sha, text) == "record_missing"


def test_a_block_naming_the_tag_commit_is_record_invalid(repo: Path):
    parent = _git(repo, "rev-parse", "HEAD")
    tag_sha = _commit_record(repo, _record(_block(parent)))
    _publish_main(repo)
    # A block cannot honestly name the commit that contains it.
    text = _record(_block(tag_sha))
    assert _evaluate(repo, tag_sha, text) == "record_invalid"
    # ...and the script does not fall through to the older, valid block.
    text = _record(_block(parent), _block(tag_sha))
    assert _evaluate(repo, tag_sha, text) == "record_invalid"


def test_the_parent_only_record_commit_authorizes(repo: Path):
    parent = _git(repo, "rev-parse", "HEAD")
    tag_sha = _commit_record(repo, _record(_block(parent)))
    _publish_main(repo)
    text = (repo / RECORD_PATH).read_text(encoding="utf-8")
    assert _evaluate(repo, tag_sha, text) is None
    # A dirty worktree does not change the verdict: the blob decides.
    _write_record(repo, "garbage\n")
    assert _evaluate(repo, tag_sha, text) is None


def test_b1_identity_placement_and_token_rules(repo: Path):
    parent = _git(repo, "rev-parse", "HEAD")
    tag_sha = _commit_record(repo, _record(_block(parent)))
    _publish_main(repo)

    for label, b1, expected in (
        ("other profile", B1_MET.replace("placement_profile=product-exclusive",
                                         "placement_profile=ci-scale"), "record_invalid"),
        ("other authority", B1_MET.replace("measurement_authority=product-local-reference",
                                           "measurement_authority=local-replica"),
         "record_invalid"),
        ("placement absent", B1_MET.replace(",placement_ok=1", ""), "record_invalid"),
        ("placement failed", B1_MET.replace("placement_ok=1", "placement_ok=0"), "b1_miss"),
        ("errors missed", B1_MET.replace("product_errors_eq_zero=met",
                                         "product_errors_eq_zero=missed"), "b1_miss"),
        ("errors absent", B1_MET.replace("product_errors_eq_zero=met,", ""), "record_invalid"),
        ("errors unknown token", B1_MET.replace("product_errors_eq_zero=met",
                                                "product_errors_eq_zero=maybe"),
         "record_invalid"),
        ("served missed", B1_MET.replace("product_served_eq_offered=met",
                                         "product_served_eq_offered=missed"), "b1_miss"),
        ("p99 absent", B1_MET.replace("product_p99_lt_150_ms=met,", ""), "record_invalid"),
        ("p99 unknown token", B1_MET.replace("product_p99_lt_150_ms=met",
                                             "product_p99_lt_150_ms=unknown"),
         "record_invalid"),
    ):
        text = _record(_block(parent, b1=b1))
        assert _evaluate(repo, tag_sha, text) == expected, label


def test_b11_writer_count_and_rate_rules(repo: Path):
    parent = _git(repo, "rev-parse", "HEAD")
    tag_sha = _commit_record(repo, _record(_block(parent)))
    _publish_main(repo)

    def _rate(token: str) -> str:
        return B11_DIAGNOSTICS.replace("combined_rate_per_sec=1745.3",
                                       f"combined_rate_per_sec={token}")

    for label, kwargs, expected in (
        ("four writers", {"writers": "B11 writers=4"}, "b11_miss"),
        ("non-numeric writers", {"writers": "B11 writers=seven"}, "record_invalid"),
        ("writers in a non-ASCII script", {"writers": "B11 writers=\u0667"},
         "record_invalid"),
        ("writers with a digit separator", {"writers": "B11 writers=1_0"},
         "record_invalid"),
        ("rate below the bar", {"diagnostics": _rate("999.9")}, "b11_miss"),
        ("rate exactly at the bar", {"diagnostics": _rate("1000.0")}, None),
        ("rate absent", {"diagnostics": "B11 diagnostics=serial_commit_ms=0.81"},
         "record_invalid"),
        ("rate not a number", {"diagnostics": _rate("fast")}, "record_invalid"),
        # A non-finite rate is not a rate. `nan` defeats BOTH comparisons --
        # `nan < 1000.0` and `nan >= 1000.0` are each false -- so a checker
        # that only asks "is it below the bar" authorizes it; `inf` satisfies
        # `>=` outright. Neither is a value `f"{rate:.1f}"` can print, so both
        # are a broken record rather than a miss.
        ("rate is nan", {"diagnostics": _rate("nan")}, "record_invalid"),
        ("rate is NaN", {"diagnostics": _rate("NaN")}, "record_invalid"),
        ("rate is NAN", {"diagnostics": _rate("NAN")}, "record_invalid"),
        ("rate is +nan", {"diagnostics": _rate("+nan")}, "record_invalid"),
        ("rate is -nan", {"diagnostics": _rate("-nan")}, "record_invalid"),
        ("rate is inf", {"diagnostics": _rate("inf")}, "record_invalid"),
        ("rate is Infinity", {"diagnostics": _rate("Infinity")}, "record_invalid"),
        ("rate is -inf", {"diagnostics": _rate("-inf")}, "record_invalid"),
        ("rate in scientific notation", {"diagnostics": _rate("1.7e3")},
         "record_invalid"),
        ("rate with a digit separator", {"diagnostics": _rate("1_000.0")},
         "record_invalid"),
        ("rate in a non-ASCII script", {"diagnostics": _rate("\u0661\u0660\u0660\u0660.\u0660")},
         "record_invalid"),
        # ...and a finite value below the bar is still a MISS, not a broken
        # record: the two verdicts must not collapse into one.
        ("rate is a negative number", {"diagnostics": _rate("-1.0")}, "b11_miss"),
        ("writer map empty", {"writer_map": "B11 writer_map="}, "record_invalid"),
        ("single rate empty", {"single": "B11 single_writer_rate="}, "record_invalid"),
        ("env empty", {"env": "B11 env="}, "record_invalid"),
    ):
        text = _record(_block(parent, **kwargs))
        assert _evaluate(repo, tag_sha, text) == expected, label
        # None of the refusals above may be reachable as an AUTHORIZATION.
        if expected is not None:
            assert _evaluate(repo, tag_sha, text) is not None, label


def test_the_b1_side_converts_nothing_and_has_no_non_finite_hole(repo: Path):
    """The same class of hole as C1, checked on the other half of the block.

    `_b11_reason` had it because it converted a printed token to a number and
    then asked only whether the number was below the bar. The B1 half compares
    STRINGS -- `placement_ok` against `"1"`, three tokens against `met` /
    `missed`, two identity fields against their fixed values -- so there is no
    conversion to defeat. This feeds the adversarial values that beat a numeric
    comparison into every B1 field that could plausibly be read as a number and
    requires each one to refuse; a future rewrite of `_b1_reason` that reached
    for `int()` or `float()` would authorize at least one of them.
    """
    parent = _git(repo, "rev-parse", "HEAD")
    tag_sha = _commit_record(repo, _record(_block(parent)))
    _publish_main(repo)

    for token in ("nan", "NaN", "inf", "-inf", "1.7e3", "1_0", "\u0661", "0x1", "true", ""):
        for field, value in (
            ("placement_ok=1", f"placement_ok={token}"),
            ("product_errors_eq_zero=met", f"product_errors_eq_zero={token}"),
            ("product_p99_lt_150_ms=met", f"product_p99_lt_150_ms={token}"),
            ("product_served_eq_offered=met", f"product_served_eq_offered={token}"),
            ("placement_profile=product-exclusive", f"placement_profile={token}"),
            ("measurement_authority=product-local-reference",
             f"measurement_authority={token}"),
        ):
            text = _record(_block(parent, b1=B1_MET.replace(field, value, 1)))
            reason = _evaluate(repo, tag_sha, text)
            assert reason is not None, f"{field} -> {value!r} authorized a tag"
            assert reason in ("b1_miss", "record_invalid"), (field, value, reason)

    # ...and the shipped checker really does convert nothing on this half.
    source = SCRIPT_PATH.read_text(encoding="utf-8")
    b1_body = source.split("def _b1_reason(", 1)[1].split("\ndef ", 1)[0]
    for conversion in ("int(", "float(", "eval(", "ast.literal_eval("):
        assert conversion not in b1_body, f"_b1_reason converts with {conversion}"


def test_two_blocks_with_the_same_sha_take_the_later_one(repo: Path):
    parent = _git(repo, "rev-parse", "HEAD")
    tag_sha = _commit_record(repo, _record(_block(parent)))
    _publish_main(repo)
    missed = B1_MET.replace("product_errors_eq_zero=met", "product_errors_eq_zero=missed")
    text = _record(_block(parent), _block(parent, b1=missed))
    assert _evaluate(repo, tag_sha, text) == "b1_miss"


def test_field_parser_reads_comma_bearing_and_repeated_fields():
    """The fingerprint's free-form values are percent-encoded, so a raw comma
    is a field boundary and the first `=` splits name from value."""
    fields = checker.parse_fields("a=1,b=x%2Cy,c=k=v,a=2")
    assert fields["a"] == "1", "a repeated field must not overwrite the first"
    assert fields["b"] == "x%2Cy"
    assert fields["c"] == "k=v"
    assert "novalue" not in checker.parse_fields("novalue,a=1")


def test_main_exits_1_with_one_line_and_0_on_a_release(repo: Path, capsys, monkeypatch):
    parent = _git(repo, "rev-parse", "HEAD")
    tag_sha = _commit_record(repo, _record(_block(parent)))
    _publish_main(repo)
    monkeypatch.setenv("GITHUB_SHA", tag_sha)
    assert checker.main([str(repo)]) == 0
    assert capsys.readouterr().out == ""

    # A miss: exactly one line, on stdout, prefixed as release-record.md §2 fixes it.
    missed = B1_MET.replace("product_errors_eq_zero=met", "product_errors_eq_zero=missed")
    _commit_record(repo, _record(_block(parent, b1=missed)), "record miss")
    _publish_main(repo)
    monkeypatch.setenv("GITHUB_SHA", _git(repo, "rev-parse", "HEAD"))
    assert checker.main([str(repo)]) == 1
    out = capsys.readouterr().out
    assert out == "release bench record: b1_miss\n", out

    # An unknown tag, and a tree with no record at all.
    monkeypatch.setenv("GITHUB_SHA", "1" * 40)
    assert checker.main([str(repo)]) == 1
    assert capsys.readouterr().out == "release bench record: sha_unknown\n"

    bare = repo.parent / "bare"
    bare.mkdir()
    _git(bare, "init", "-q", "-b", "main")
    _git(bare, "config", "user.email", "t@example.com")
    _git(bare, "config", "user.name", "t")
    (bare / "f.txt").write_text("x\n", encoding="utf-8")
    _git(bare, "add", "-A")
    _git(bare, "commit", "-qm", "only")
    monkeypatch.setenv("GITHUB_SHA", _git(bare, "rev-parse", "HEAD"))
    assert checker.main([str(bare)]) == 1
    assert capsys.readouterr().out == "release bench record: record_missing\n"


def test_main_defaults_its_repository_and_never_runs_a_benchmark(monkeypatch, repo: Path):
    """`main` takes the workspace from the environment, and starts nothing."""
    monkeypatch.setenv("GITHUB_WORKSPACE", str(repo))
    monkeypatch.setenv("GITHUB_SHA", "HEAD")
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    monkeypatch.setenv("GITHUB_SHA", _git(repo, "rev-parse", "HEAD"))
    assert checker.main([]) == 1  # no record committed yet

    source = SCRIPT_PATH.read_text(encoding="utf-8")
    for forbidden in ("integration-test.sh", "pytest", "docker", "b1_product", "retry"):
        assert f"{forbidden}(" not in source, forbidden
    assert "subprocess.run" in source
    # Every subprocess this script starts is a git command.
    assert source.count('subprocess.run(') == 1
    assert '("git", "-C", repo, *args)' in source

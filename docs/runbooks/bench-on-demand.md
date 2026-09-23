# On-demand B1 and B11 benchmarks

B1 (the ingest-gateway burst) and B11 (the audit/LLM insert throughput) are not
run by per-push CI. GitHub-hosted runners rotate CPU model and disk, and
`b1_product` refuses a host with fewer than eight logical CPUs, so both are
measured on a developer host and the run's own printed fingerprints are
committed as the record.

CI keeps lint, unit, images, functional tests, the code-level benchmarks
(B2, B10, B3–B6, B9, B12–B14) and e2e.

## When to run

There are exactly two triggers.

### 1. Release — before every `v*` tag

A tag is refused by the `release-bench-record` job unless a committed record
shows both bars met for the tree being tagged. Run the two commands below, on a
developer host with at least eight logical CPUs, before you tag.

### 2. Performance investigation

Run the same two commands, and append a block, when you are investigating a
performance issue or after a change to either of these files:

- `services/gateway/gateway/ingest.py`
- `services/gateway/gateway/merge_commit.py`

An investigation block is the same seven lines. A block whose tokens show a
miss is a real record of that run and is appended as it stands; while it is the
closest candidate for a tag, it refuses that tag, which is the point.

## The two commands

The tree must have no tracked changes before either command runs:

```bash
git status --porcelain --untracked-files=no   # prints nothing
git rev-parse HEAD                            # this is measured_sha
```

Untracked files are allowed only if they are never committed; the jail
dotfiles at the repository root (`.bashrc`, `.profile`, `.claude/`, …) are the
known case.

B1, the product profile (1000 requests/s offered for 30 s, gateway 4 CPUs /
PostgreSQL 3 / driver 1):

```bash
/opt/gitspace/dbagent/scripts/integration-test.sh b1_product
```

B11, the seven-writer insert throughput:

```bash
services/worker/.venv/bin/python -m pytest \
  tests/benchmark/test_pg_scale.py::test_b11_audit_llm_insert_throughput -v -s
```

From a sandboxed shell (a network namespace with only loopback), the command
above cannot reach the PostgreSQL port testcontainers publishes, and every DB
fixture fails with "connection refused". Run the same node id inside the
review-runner image on the host network instead. The image is
`deploy/review-runner/Dockerfile`; the socket path is taken from `DOCKER_HOST`:

```bash
DOCKER_SOCK="${DOCKER_HOST:-unix:///var/run/docker.sock}"
DOCKER_SOCK="${DOCKER_SOCK#unix://}"
docker run --rm --network host \
  -e TESTCONTAINERS_CONNECTION_MODE=docker_host \
  -e TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 \
  -e TESTCONTAINERS_RYUK_DISABLED=true \
  -v "$DOCKER_SOCK":/var/run/docker.sock \
  -v /opt/gitspace/dbagent:/workspace:ro -w /workspace \
  dbagent-review-runner:latest \
  python3 -B -X pycache_prefix=/tmp/pycache -m pytest -o cache_dir=/tmp/pytest-cache \
  tests/benchmark/test_pg_scale.py::test_b11_audit_llm_insert_throughput -v -s
```

Both environment settings are needed: without
`TESTCONTAINERS_CONNECTION_MODE=docker_host`, testcontainers inside a container
ignores the override and dials the Docker gateway address. Ryuk is disabled, so
check `docker ps -a` afterwards and remove any container a killed run left
behind.

## The results file

`docs/runbooks/bench-on-demand-results.txt` holds one or more blocks. A line
containing only `---` stands between blocks and nowhere else. Each block is
exactly these seven lines, in this order, with no blank line inside it:

1. `measured_sha=<40 lowercase hex>` — the `git rev-parse HEAD` you recorded
   before the run.
2. The `B1 env=` line printed by `test_b1_product_exclusive_reference_profile`.
3. The `B11 writers=` line.
4. The `B11 writer_map=` line.
5. The `B11 single_writer_rate=` line.
6. The `B11 env=` line.
7. The `B11 diagnostics=` line (the 21-field record whose first field is
   `combined_rate_per_sec`).

Lines 2–7 are copied **verbatim** from the two runs' output.

## Release steps

1. Confirm the tree has no tracked changes
   (`git status --porcelain --untracked-files=no` prints nothing) and record
   `git rev-parse HEAD` as `measured_sha`.
2. Run `/opt/gitspace/dbagent/scripts/integration-test.sh b1_product`.
3. Run the B11 node id above.
4. Copy the six print lines into a new block in
   `docs/runbooks/bench-on-demand-results.txt` **only when both commands exited 0**.
   A non-zero exit is not copied — including a B11 run whose printed
   `combined_rate_per_sec` rounds to `1000.0` while the assert failed.
5. Commit only that file.
6. Push the commit to `main`.
7. Tag that commit — not the measured parent — and push the tag. The parent is
   `measured_sha`; the diff between the two commits is the results file and
   nothing else.

A release run is successful when the two product tokens are `met`,
`placement_ok=1`, `B11 writers=7`, and `combined_rate_per_sec` is at least
`1000.0`. `product_p99_lt_150_ms=missed` alongside those is still a successful
release run: the product run records the p99 and does not gate on it.

Do **not** tag when either product token is `missed`, when `placement_ok` is
anything other than `1`, when `B11 writers` is anything other than `7`, or when
`combined_rate_per_sec` is below `1000.0`.

If a tag was pushed and the `release-bench-record` job is red, delete the remote
tag and do not treat that tag as shipped.

## What the tag job does

`scripts/check_release_bench_record.py` reads the record out of the tagged tree
with `git show`, not from the working tree. It refuses a missing file, a file
that does not match the shape above, a tag that is not an ancestor of
`origin/main`, an unknown `measured_sha`, a record measured against a different
product tree, and a record whose own tokens show a B1 or B11 miss. It runs
neither benchmark, starts no container, and does not retry.

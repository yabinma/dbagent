# Runner-specific literal pins: these bases deliberately do not use versions.env.
FROM --platform=linux/amd64 golang:1.26.4-bookworm AS go
FROM --platform=linux/amd64 python:3.12.3-bookworm

COPY --from=go /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}" \
    GOTOOLCHAIN=local \
    CGO_ENABLED=1 \
    GOMODCACHE=/opt/review-go/pkg/mod

RUN apt-get update \
    && apt-get install -y --no-install-recommends socat build-essential git ca-certificates coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/local/go/bin/go /usr/local/bin/go

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download

# Only digest-covered manifests enter the image; live sources arrive via /workspace.
COPY libs/py/rca_common/pyproject.toml libs/py/rca_common/pyproject.toml
COPY services/worker/pyproject.toml services/worker/pyproject.toml
COPY services/gateway/pyproject.toml services/gateway/pyproject.toml
COPY services/dashboard-api/pyproject.toml services/dashboard-api/pyproject.toml
RUN mkdir -p libs/py/rca_common/rca_common services/worker/worker \
        services/gateway/gateway services/dashboard-api/dashboard_api \
    && touch libs/py/rca_common/rca_common/__init__.py services/worker/worker/__init__.py \
        services/gateway/gateway/__init__.py services/dashboard-api/dashboard_api/__init__.py \
    && printf 'alembic==1.18.5\n' > /opt/review-python-constraints.txt \
    && python3 -m pip install --no-cache-dir -c /opt/review-python-constraints.txt \
        --config-settings editable_mode=compat -e libs/py/rca_common \
    && python3 -m pip install --no-cache-dir -c /opt/review-python-constraints.txt \
        --config-settings editable_mode=compat -e 'services/worker[test]' \
    && python3 -m pip install --no-cache-dir -c /opt/review-python-constraints.txt \
        --config-settings editable_mode=compat -e 'services/gateway[test]' \
    && python3 -m pip install --no-cache-dir -c /opt/review-python-constraints.txt \
        --config-settings editable_mode=compat -e 'services/dashboard-api[test]' \
    && python3 -m pip install --no-cache-dir -c /opt/review-python-constraints.txt alembic==1.18.5 \
    && python3 -m pip check

# Nested anonymous volumes hide host venvs without hiding live Python sources.
# These are compatibility directories for the global interpreter, not virtualenvs.
RUN for project in libs/py/rca_common services/worker; do \
        mkdir -p "$project/.venv/bin" \
        && ln -s /usr/local/bin/python3 "$project/.venv/bin/python" \
        && ln -s /usr/local/bin/python3 "$project/.venv/bin/python3"; \
    done
VOLUME ["/workspace/libs/py/rca_common/.venv", "/workspace/services/worker/.venv"]

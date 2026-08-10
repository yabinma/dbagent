# temporal-worker — Python Activities/Workflows + install-job scripts.
ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE} AS builder
WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY libs/py/rca_common /build/libs/py/rca_common
COPY services/worker /build/services/worker
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir /build/libs/py/rca_common \
 && pip install --no-cache-dir /build/services/worker

ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}
# Create /etc/dbagent/signing so a fresh Docker named volume mounted there
# initializes with rca (10001) ownership -- Compose seeds an empty named volume
# from the image path's owner/mode, and without this the mountpoint is created
# root-owned and the signing-key job (USER 10001) cannot write its keypair.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin rca \
 && mkdir -p /etc/dbagent/signing /app/scripts /app/migrations && chown -R rca:rca /etc/dbagent /app
COPY --from=builder /opt/venv /opt/venv
COPY services/worker/scripts/ /app/scripts/
COPY libs/py/rca_common/migrations/ /app/migrations/
COPY libs/py/rca_common/alembic.ini /app/alembic.ini
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001
WORKDIR /app
ENTRYPOINT ["python", "-m", "worker.worker_main"]

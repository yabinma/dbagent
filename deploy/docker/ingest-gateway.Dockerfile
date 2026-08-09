# ingest-gateway — Python/FastAPI (design.md §11 one-service/one-image).
# Build context: repository root.
ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE} AS builder
WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY libs/py/rca_common /build/libs/py/rca_common
COPY services/gateway /build/services/gateway
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir /build/libs/py/rca_common \
 && pip install --no-cache-dir /build/services/gateway

ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin rca \
 && mkdir -p /etc/rca-agent && chown rca:rca /etc/rca-agent
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001
WORKDIR /home/rca
EXPOSE 8080
ENTRYPOINT ["python", "-m", "gateway.main"]

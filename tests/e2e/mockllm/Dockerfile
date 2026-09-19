FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir PyYAML
# Build context is tests/
COPY mocks/llm/ /app/tests/mocks/llm/
COPY e2e/mockllm/fixtures/ /fixtures/
ENV PYTHONPATH=/app
EXPOSE 8090
# Combined fixtures/fixtures.yaml routes E1–E4 by prompt_contains (FP-M6-17).
CMD ["python", "-m", "tests.mocks.llm.mock_llm_server", "--host", "0.0.0.0", "--port", "8090", "--fixtures", "/fixtures"]

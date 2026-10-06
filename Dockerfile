# syntax=docker/dockerfile:1.7
# Multi-stage build producing a small runtime image for the CLI + API.
FROM python:3.12-slim AS builder
WORKDIR /app
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
COPY pyproject.toml README.md ./
COPY mcpscan ./mcpscan
RUN python -m pip install --upgrade pip build && \
    python -m build --wheel && \
    pip install "dist/"*.whl "$(ls dist/*.whl)[api,semantic]"

FROM python:3.12-slim AS runtime
# Create an unprivileged user; the scanner never needs root.
RUN useradd --create-home --uid 10001 scanner
WORKDIR /work
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/mcpscan /usr/local/bin/mcpscan
USER scanner
ENTRYPOINT ["mcpscan"]
CMD ["--help"]

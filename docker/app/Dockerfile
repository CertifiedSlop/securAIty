FROM python:3.12-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONFAULTHANDLER=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

RUN groupadd --gid 1000 appgroup \
    && useradd --uid 1000 --gid appgroup --shell /bin/false --create-home appuser


FROM base AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --prefix=/install --no-warn-script-location -r requirements.txt


FROM base AS production

COPY --from=builder /install /usr/local

COPY pyproject.toml .

RUN pip install --no-cache-dir --no-deps -e .

COPY src/ ./src/

RUN chown -R appuser:appgroup /app \
    && chmod -R 550 /app \
    && find /app -type f -name "*.py" -exec chmod 440 {} \;

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

ENTRYPOINT ["python"]

CMD ["-m", "uvicorn", "src.securAIty.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

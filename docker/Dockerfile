# Multi-stage minimal production Dockerfile for Autonomous AI SOC Analyst
FROM python:3.11-slim as builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.11-slim as runner

WORKDIR /app

# Create non-root security service account
RUN groupadd -g 10001 socgroup && \
    useradd -u 10001 -g socgroup -s /bin/bash socanalyst

COPY --from=builder /root/.local /home/socanalyst/.local
COPY . /app

ENV PATH=/home/socanalyst/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER socanalyst

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]

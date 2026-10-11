FROM python:3.11-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends apksigner default-jre-headless && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY scanner/requirements.txt /app/scanner/requirements.txt
RUN pip install --no-cache-dir -r scanner/requirements.txt
COPY scanner /app/scanner
RUN useradd --system --uid 10001 scanner && mkdir /tmp/scamsignal-scans && chown scanner /tmp/scamsignal-scans
USER scanner
ENV SCAN_CONCURRENCY=1
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "scanner.api:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

# nexhunter - API server image.
# Build:  docker build -t nexhunter .
# Run:    docker compose up   (or)   docker run -p 8888:8888 nexhunter
FROM python:3.11-slim

WORKDIR /app

# Minimal runtime tools so the registry's availability check is not empty.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl dnsutils whois iputils-ping netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

COPY . /app
RUN pip install --no-cache-dir -e ".[api,mcp,browser]"

ENV NEXHUNTER_BIND_HOST=0.0.0.0 \
    NEXHUNTER_EXTERNAL_BIND_ALLOWED=true
EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8888/ready').status==200 else 1)"

CMD ["python", "-m", "nexhunter.api.server", "--host", "0.0.0.0", "--port", "8888"]

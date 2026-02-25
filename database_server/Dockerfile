FROM python:3.11-slim

WORKDIR /app

# Needed for docker-compose healthchecks (curl) and basic TLS tooling.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create directories for runtime data and certificates.
RUN mkdir -p /app/data /app/certs

COPY database_server/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy only the required packages into the image.
COPY shared /app/shared
COPY database_server /app/database_server

ENV PYTHONPATH=/app

EXPOSE 5000

CMD ["python", "-m", "database_server"]

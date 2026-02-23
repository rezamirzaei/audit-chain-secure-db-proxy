FROM python:3.11-slim

WORKDIR /app

# Create directories for data and certificates
RUN mkdir -p /app/data /app/certs /app/database_server

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy application code into a proper package path
COPY . /app/database_server

ENV PYTHONPATH=/app

EXPOSE 5000

CMD ["python", "-m", "database_server.app"]

FROM python:3.11-slim

WORKDIR /app

# Create directories for data and certificates
RUN mkdir -p /app/data /app/certs

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

EXPOSE 5000

CMD ["python", "app.py"]

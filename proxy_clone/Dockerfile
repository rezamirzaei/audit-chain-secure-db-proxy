FROM python:3.11-slim

WORKDIR /app

RUN mkdir -p /app/certs

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY certs/cert.pem /app/certs/
COPY certs/key.pem /app/certs/

COPY . .

EXPOSE 8080

CMD ["python", "app.py"]

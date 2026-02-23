FROM python:3.11-slim

WORKDIR /app

RUN mkdir -p /app/certs /app/proxy_clone

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY . /app/proxy_clone

ENV PYTHONPATH=/app

EXPOSE 8080

CMD ["python", "-m", "proxy_clone.app"]

FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    barman \
    postgresql-client \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

RUN id -u barman >/dev/null 2>&1 || adduser --disabled-password --gecos "" barman \
  && mkdir -p /var/lib/barman /var/log/barman \
  && chown -R barman:barman /var/lib/barman /var/log/barman

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

VOLUME ["/var/lib/barman"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["cron-loop"]

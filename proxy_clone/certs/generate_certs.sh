#!/bin/bash
# Generate self-signed SSL certificate for the database server

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
    -subj "/C=US/ST=State/L=City/O=DataVault/OU=IT/CN=database-server"

echo "SSL certificates generated: cert.pem and key.pem"

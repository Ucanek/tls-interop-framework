#!/bin/bash
# Generate a self-signed certificate for TLS interoperability testing.
# SERVER_NAME matches the Docker Compose service name when testing in containers.

set -e
CERT_NAME="cert.pem"
KEY_NAME="key.pem"
DAYS=365
SERVER_NAME="server_node"

echo "Generating self-signed certificate for TLS interoperability testing..."

openssl req -x509 -newkey rsa:2048 -sha256 -days "$DAYS" -nodes \
  -keyout "$KEY_NAME" -out "$CERT_NAME" \
  -subj "/CN=$SERVER_NAME" \
  -addext "subjectAltName=DNS:$SERVER_NAME,DNS:localhost,IP:127.0.0.1"

echo "--------------------------------------------------"
echo "Generated: $KEY_NAME, $CERT_NAME"
echo "--------------------------------------------------"
echo "Add *.pem to .gitignore if you do not want to commit them."

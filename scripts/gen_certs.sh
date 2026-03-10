#!/bin/bash

# Configuration
CERT_NAME="cert.pem"
KEY_NAME="key.pem"
DAYS=365
# "server_node" matches the service name in docker-compose.yaml
SERVER_NAME="server_node"

echo "Generating self-signed certificate for TLS interoperability testing..."

# Generate a 2048-bit RSA private key and a self-signed certificate
# We add a Subject Alternative Name (SAN) so GnuTLS and OpenSSL are happy in Docker
openssl req -x509 -newkey rsa:2048 -sha256 -days $DAYS -nodes \
  -keyout $KEY_NAME -out $CERT_NAME \
  -subj "/CN=$SERVER_NAME" \
  -addext "subjectAltName=DNS:$SERVER_NAME,DNS:localhost,IP:127.0.0.1"

if [ $? -eq 0 ]; then
    echo "--------------------------------------------------"
    echo "✅ Success! Generated:"
    echo "   Key:  $KEY_NAME"
    echo "   Cert: $CERT_NAME"
    echo "--------------------------------------------------"
    echo "Note: Keep these files out of Git by using .gitignore"
else
    echo "❌ Error: Failed to generate certificates."
    exit 1
fi

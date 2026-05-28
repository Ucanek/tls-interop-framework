#!/usr/bin/env bash
# Generate interop test certificates (same material as deploy/Dockerfile).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="${ROOT}/certs"
mkdir -p "${CERT_DIR}"

gen_rsa() {
  openssl req -x509 -newkey rsa:2048 \
    -keyout "${CERT_DIR}/key_rsa.pem" -out "${CERT_DIR}/cert_rsa.pem" -sha256 \
    -days 365 -nodes \
    -subj "/CN=server_node/OU=interop-rsa" \
    -addext "subjectAltName=DNS:server_node"
}

gen_ecdsa() {
  openssl ecparam -name prime256v1 -genkey -noout -out "${CERT_DIR}/key_ecdsa.pem"
  openssl req -new -x509 -key "${CERT_DIR}/key_ecdsa.pem" \
    -out "${CERT_DIR}/cert_ecdsa.pem" -sha256 -days 365 -nodes \
    -subj "/CN=server_node/OU=interop-ecdsa" \
    -addext "subjectAltName=DNS:server_node"
}

gen_ed25519() {
  openssl genpkey -algorithm ED25519 -out "${CERT_DIR}/key_ed25519.pem"
  openssl req -new -x509 -key "${CERT_DIR}/key_ed25519.pem" \
    -out "${CERT_DIR}/cert_ed25519.pem" -days 365 -nodes \
    -subj "/CN=server_node/OU=interop-ed25519" \
    -addext "subjectAltName=DNS:server_node"
}

gen_ed448() {
  openssl genpkey -algorithm ED448 -out "${CERT_DIR}/key_ed448.pem"
  openssl req -new -x509 -key "${CERT_DIR}/key_ed448.pem" \
    -out "${CERT_DIR}/cert_ed448.pem" -days 365 -nodes \
    -subj "/CN=server_node/OU=interop-ed448" \
    -addext "subjectAltName=DNS:server_node"
}

gen_rsa
gen_ecdsa
gen_ed25519
gen_ed448
echo "Wrote identity PEMs under ${CERT_DIR}/"

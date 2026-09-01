#!/usr/bin/env bash
# Generate interop test identity bundles under certs/ ({prefix}.crt + {prefix}.key).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="${ROOT}/certs"
mkdir -p "${CERT_DIR}"
SUBJ_BASE="/CN=server_node"
SAN=(-addext "subjectAltName=DNS:server_node,DNS:localhost,IP:127.0.0.1")

gen_rsa_default() {
  openssl req -x509 -newkey "rsa:3072" \
    -keyout "${CERT_DIR}/rsa_default.key" \
    -out "${CERT_DIR}/rsa_default.crt" \
    -sha256 -days 365 -nodes \
    -subj "${SUBJ_BASE}/OU=interop-rsa-default" \
    "${SAN[@]}"
}

gen_rsa_pss_pure() {
  openssl genpkey -algorithm RSA-PSS \
    -pkeyopt rsa_keygen_bits:3072 \
    -pkeyopt rsa_pss_keygen_md:sha256 \
    -out "${CERT_DIR}/rsa_pss_pure.key"
  openssl req -new -key "${CERT_DIR}/rsa_pss_pure.key" \
    -out "${CERT_DIR}/rsa_pss_pure.csr" \
    -subj "${SUBJ_BASE}/OU=interop-rsa-pss-pure" \
    "${SAN[@]}"
  openssl x509 -req -in "${CERT_DIR}/rsa_pss_pure.csr" \
    -signkey "${CERT_DIR}/rsa_pss_pure.key" \
    -out "${CERT_DIR}/rsa_pss_pure.crt" \
    -days 365 -sha256 \
    -sigopt rsa_padding_mode:pss \
    -sigopt rsa_pss_saltlen:digest
  rm -f "${CERT_DIR}/rsa_pss_pure.csr"
}

gen_ecdsa() {
  local name="$1" curve="$2" ou="$3"
  openssl ecparam -name "${curve}" -genkey -noout -out "${CERT_DIR}/${name}.key"
  openssl req -new -x509 -key "${CERT_DIR}/${name}.key" \
    -out "${CERT_DIR}/${name}.crt" -sha256 -days 365 -nodes \
    -subj "${SUBJ_BASE}/OU=${ou}" \
    "${SAN[@]}"
}

gen_ed25519() {
  openssl genpkey -algorithm ED25519 -out "${CERT_DIR}/ed25519.key"
  openssl req -new -x509 -key "${CERT_DIR}/ed25519.key" \
    -out "${CERT_DIR}/ed25519.crt" -days 365 -nodes \
    -subj "${SUBJ_BASE}/OU=interop-ed25519" \
    "${SAN[@]}"
}

gen_ed448() {
  openssl genpkey -algorithm ED448 -out "${CERT_DIR}/ed448.key"
  openssl req -new -x509 -key "${CERT_DIR}/ed448.key" \
    -out "${CERT_DIR}/ed448.crt" -days 365 -nodes \
    -subj "${SUBJ_BASE}/OU=interop-ed448" \
    "${SAN[@]}"
}

gen_dsa_default() {
  local dsap="${CERT_DIR}/dsa_default.dsap.pem"
  openssl dsaparam -out "${dsap}" 2048
  openssl gendsa -out "${CERT_DIR}/dsa_default.key" "${dsap}"
  openssl req -new -x509 -key "${CERT_DIR}/dsa_default.key" \
    -out "${CERT_DIR}/dsa_default.crt" -sha256 -days 365 -nodes \
    -subj "${SUBJ_BASE}/OU=interop-dsa-default" \
    "${SAN[@]}"
  rm -f "${dsap}"
}

gen_rsa_default
gen_rsa_pss_pure
gen_ecdsa ecdsa_p256 prime256v1 interop-ecdsa-p256
gen_ecdsa ecdsa_p384 secp384r1 interop-ecdsa-p384
gen_ecdsa ecdsa_p521 secp521r1 interop-ecdsa-p521
gen_ed25519
gen_ed448
gen_dsa_default

gen_dh2048() {
  if [[ ! -f "${CERT_DIR}/dh2048.pem" ]]; then
    openssl dhparam -out "${CERT_DIR}/dh2048.pem" 2048
  fi
}

gen_dh2048

# Legacy symlinks for older paths / default server_node TLS tools.
ln -sf rsa_default.crt "${CERT_DIR}/cert.pem"
ln -sf rsa_default.key "${CERT_DIR}/key.pem"
ln -sf rsa_default.crt "${CERT_DIR}/cert_rsa.pem"
ln -sf rsa_default.key "${CERT_DIR}/key_rsa.pem"
ln -sf ecdsa_p256.crt "${CERT_DIR}/cert_ecdsa.pem"
ln -sf ecdsa_p256.key "${CERT_DIR}/key_ecdsa.pem"
ln -sf ed25519.crt "${CERT_DIR}/cert_ed25519.pem"
ln -sf ed25519.key "${CERT_DIR}/key_ed25519.pem"
ln -sf ed448.crt "${CERT_DIR}/cert_ed448.pem"
ln -sf ed448.key "${CERT_DIR}/key_ed448.pem"

echo "Wrote identity bundles under ${CERT_DIR}/ (8 prefixes)"
chmod 755 "${CERT_DIR}"
chmod a+r "${CERT_DIR}"/*.crt "${CERT_DIR}"/*.pem 2>/dev/null || true

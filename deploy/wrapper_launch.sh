#!/bin/sh
# Select TLS wrapper from WRAPPER env: openssl | gnutls | nss
set -e
W="${WRAPPER:-openssl}"
case "$W" in
  openssl) exec python3 /app/wrapper_openssl.py ;;
  gnutls) exec python3 /app/wrapper_gnutls.py ;;
  nss) exec python3 /app/wrapper_nss.py ;;
  *) echo "wrapper_launch: unknown WRAPPER='$W' (use openssl, gnutls, nss)" >&2; exit 1 ;;
esac

#!/bin/sh
# Select TLS wrapper by role: server uses WRAPPER_SERVER, client uses WRAPPER_CLIENT.
# Values: openssl | gnutls | nss
set -e
MODE="${1:-server}"
if [ "$MODE" = server ]; then
  W="${WRAPPER_SERVER:-openssl}"
else
  W="${WRAPPER_CLIENT:-gnutls}"
fi
case "$W" in
  openssl) exec python3 /app/wrapper_openssl.py ;;
  gnutls) exec python3 /app/wrapper_gnutls.py ;;
  nss) exec python3 /app/wrapper_nss.py ;;
  *) echo "wrapper_select: unknown wrapper '$W' for $MODE"; exit 1 ;;
esac

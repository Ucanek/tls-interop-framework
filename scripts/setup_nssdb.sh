#!/bin/bash
# Create NSS database from cert.pem and key.pem (current dir).
# Output: ./nssdb with cert nickname "interop", trusted for server and client.
# Requires: openssl, certutil, pk12util (nss-tools / libnss3-tools).

set -e
NSSDB="${NSSDB:-./nssdb}"
CERT_NICKNAME="${CERT_NICKNAME:-interop}"

# Find certutil and pk12util (may be in PATH or in nss/unsupported-tools on Fedora)
for dir in "" "/usr/lib64/nss/unsupported-tools" "/usr/lib/nss/unsupported-tools"; do
  if [[ -z "$dir" ]]; then
    CERTUTIL=$(command -v certutil 2>/dev/null) || true
    PK12UTIL=$(command -v pk12util 2>/dev/null) || true
  else
    [[ -x "$dir/certutil" ]] && CERTUTIL="$dir/certutil"
    [[ -x "$dir/pk12util" ]] && PK12UTIL="$dir/pk12util"
  fi
  [[ -n "$CERTUTIL" && -n "$PK12UTIL" ]] && break
done
if [[ -z "$CERTUTIL" || -z "$PK12UTIL" ]]; then
  echo "Error: certutil and pk12util not found. Install NSS tools:"
  echo "  Fedora:    sudo dnf install nss-tools"
  echo "  Debian/Ubuntu: sudo apt install libnss3-tools"
  exit 1
fi

rm -rf "$NSSDB"
mkdir -p "$NSSDB"

# Create empty NSS DB (no password)
"$CERTUTIL" -N -d "sql:$NSSDB" --empty-password

# PEM -> PKCS#12 (empty password for automation)
openssl pkcs12 -export -in cert.pem -inkey key.pem -out "$NSSDB/cert.p12" -passout pass: -nodes -name "$CERT_NICKNAME"

# Import into NSS DB
"$PK12UTIL" -d "sql:$NSSDB" -i "$NSSDB/cert.p12" -W "" -K ""

# Trust for SSL/TLS server and client (u,u,u = peer trusted)
"$CERTUTIL" -M -d "sql:$NSSDB" -n "$CERT_NICKNAME" -t "u,u,u"

rm -f "$NSSDB/cert.p12"
echo "NSS DB ready: $NSSDB (nickname: $CERT_NICKNAME)"

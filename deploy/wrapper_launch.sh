#!/bin/sh
# Select TLS wrapper from WRAPPER env (see deploy/wrappers.json + wrapper_entry.py).
set -e
exec python3 /app/wrapper_entry.py

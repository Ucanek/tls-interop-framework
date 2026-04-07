# Known limitations

## GnuTLS server × NSS client (SNI vs. TCP peer)

Previously, `tstclnt` used `-h server_node -a server_node`. Docker resolves `server_node` to an IP for the TCP connection, but the ClientHello still carried the **DNS** SNI `server_node`. **GnuTLS 3.8+** rejects that combination and responds with `illegal_parameter` (“disallowed SNI server name”).

**Mitigation (implemented):** When `INTEROP_GNUTLS_NSS_PAIR=1` (set by `./scripts/run_all_combos.sh` for the gnutls×nss matrix row), the NSS wrapper **resolves** the configured hostname to an address, passes that to `tstclnt -h`, and **does not** pass `-a`, so the handshake typically omits DNS SNI. Certificate trust still uses `tstclnt -o` for the test self-signed cert.

Manual run:

```bash
INTEROP_GNUTLS_NSS_PAIR=1 SERVER_WRAPPER=gnutls CLIENT_WRAPPER=nss \
  docker compose -p interop-gnutls-nss -f deploy/combos/matrix.yaml run --rm --build driver
```

If `getaddrinfo` fails, the wrapper falls back to hostname + `-a` (old behaviour).

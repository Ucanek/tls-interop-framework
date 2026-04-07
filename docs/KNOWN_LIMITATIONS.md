# Known limitations

## GnuTLS server × NSS client (`SERVER_WRAPPER=gnutls` `CLIENT_WRAPPER=nss` with `deploy/combos/matrix.yaml`)

The NSS test client (`tstclnt`) and GnuTLS test server (`gnutls-serv`) often fail the TLS handshake with:

`SSL_ERROR_ILLEGAL_PARAMETER_ALERT` (peer rejects a handshake message).

This is a **stack-to-stack** incompatibility: NSS sends a ClientHello (extensions, groups, versions) that GnuTLS treats as invalid under its RFC interpretation, while e.g. **OpenSSL `s_server` accepts the same NSS client** without that alert.

**Status:** This combo is **not** run in CI (`./scripts/run_all_combos.sh`). To attempt it anyway:

```bash
./scripts/run_all_combos.sh --all
# or
SERVER_WRAPPER=gnutls CLIENT_WRAPPER=nss docker compose -p interop-gnutls-nss -f deploy/combos/matrix.yaml run --rm --build driver
```

Future work: newer GnuTLS/NSS releases, different `gnutls-serv` priority strings, or an alternative NSS-facing server path in the wrapper.

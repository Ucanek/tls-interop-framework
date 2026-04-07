# NSS (Network Security Services) support

The framework **must support NSS** as a third TLS implementation alongside OpenSSL and GnuTLS. All tests and the driver stay implementation-agnostic; NSS is integrated by adding a new wrapper that speaks the same gRPC/proto contract.

---

## Requirement

- **Same behaviour as OpenSSL and GnuTLS:** The common test driver must be able to run the same scenarios with NSS as server and/or client (e.g. NSS↔OpenSSL, NSS↔GnuTLS, NSS↔NSS).
- **No driver changes for “which library”:** Component selection is done by which wrapper process is bound to which node (e.g. in Docker Compose). The driver only knows “server” and “client” endpoints; it does not need to know they are NSS.
- **Same contract:** NSS wrapper implements `TlsInteropWrapper`: `GetMetadata` and `ExecuteOperation` (ESTABLISH, TRANSMIT, CLOSE, optionally KEY_UPDATE). Same `TlsConfig`, same `OperationResponse` shape.

---

## NSS tooling (for the wrapper)

| Role   | OpenSSL      | GnuTLS        | NSS              |
|--------|--------------|---------------|------------------|
| Server | `openssl s_server` | `gnutls-serv` | `selfserv`       |
| Client | `openssl s_client` | `gnutls-cli`  | `tstclnt`        |

- **selfserv** – TLS server (listen on port, serve cert from NSS DB).
- **tstclnt** – TLS client (connect to host:port, use NSS DB for trust/certs).
- **Certificates:** NSS uses its own DB (e.g. `sql:./db`) and tools like `certutil` / `pk12util`. The wrapper will need to either (a) accept PEM/cert from `TlsConfig` and import into a temporary NSS DB, or (b) use a pre-created DB in the container/image.

Packages: Fedora `nss-tools`, Debian/Ubuntu `libnss3-tools`.

---

## Implemented

| Task | Status |
|------|--------|
| **NSS wrapper** | `src/wrappers/wrapper_nss.py` – gRPC server, ESTABLISH → `selfserv` / `tstclnt`, TRANSMIT, CLOSE. Uses env `NSSDB` (default `./nssdb`), `CERT_NICKNAME` (default `interop`). |
| **GetMetadata** | Returns `LibraryMetadata` with component_name `"NSS"`, version, roles, supported_versions/cipher_suites/groups. |
| **NSS DB setup** | `scripts/setup_nssdb.sh` creates NSS DB from `cert.pem` and `key.pem` (certutil, pk12util). Dockerfile runs it at build time so image has `/app/nssdb`. |
| **Compose** | `deploy/combos/matrix.yaml` + `scripts/run_all_combos.sh`; workaround GnuTLS×NSS v [matrix_env.py](../src/wrappers/matrix_env.py) / [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md). |

---

## Design principles (so it works with NSS and any future library)

1. **Driver and proto are library-agnostic** – no “if OpenSSL then …” in the driver; all library-specific logic stays in wrappers.
2. **Wrappers are interchangeable per node** – swap the wrapper process (and its CLI tools) per container/service; the driver and tests stay the same.
3. **Capabilities come from wrappers** – when we add GetMetadata, NSS (like OpenSSL/GnuTLS) reports what it supports so the driver or test plan can skip incompatible combinations or tests.
4. **CI and docs** – once the NSS wrapper exists, add NSS to CI (e.g. one job with NSS as client or server) and to README/ROADMAP as a supported component.

---

## Summary

For the whole framework to **work with NSS**, we add a third wrapper that implements the same proto and is wired into the same driver and orchestration (Docker). No change to the driver’s core logic or to the proto contract is required; only the NSS-specific CLI and certificate handling live in the new wrapper and its runtime (image/DB setup).

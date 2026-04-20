# TLS Interoperability Testing Framework

Automated interoperability testing for TLS implementations (OpenSSL, GnuTLS, NSS).

## Overview

This project provides a standardized framework for **interoperability testing** of Transport Layer Security (TLS) libraries.

A common problem in cryptographic development is misinterpretation of specs (RFCs). An implementation may pass its own test suite yet fail to interoperate with other libraries or introduce subtle security issues. This framework addresses that by providing a **common test driver** that orchestrates tests across multiple **library wrappers** via a single contract.

## Architecture

Two logical planes:

1. **Control plane (gRPC/Protobuf)**  
   The **driver** sends high-level commands (`ESTABLISH`, `TRANSMIT`, `CLOSE`) to wrapper nodes via a Protocol Buffer contract.

2. **Data plane (TLS)**  
   **Wrappers** translate those commands into CLI calls (`openssl s_server` / `gnutls-cli`, etc.) and perform the actual TLS handshake and data exchange.

### Components

- **Driver** – Orchestrates test sessions, synchronizes server/client nodes, evaluates results; may **skip** a scenario after `GetMetadata` if the pair cannot meet the scenario’s TLS/role requirements (see `./scripts/run.sh capability-test`).
- **Wrappers** – Per-library gRPC servers (OpenSSL, GnuTLS, NSS) that run the TLS tools. NSS details are below under [NSS (third implementation)](#nss-third-implementation).
- **Capability filter** – After `GetMetadata`, the driver skips a scenario (successful exit, logged `SKIP`) when metadata shows the server or client cannot negotiate the required TLS version or role.

## Tech stack

- **Language:** Python 3.x  
- **Communication:** gRPC & Protocol Buffers  
- **Orchestration:** Docker Compose  
- **Libraries under test:** OpenSSL, GnuTLS, NSS (CLI tools)

## Project structure

| Path | Description |
|------|-------------|
| `proto/` | `.proto` schema and generated Python (`interop_pb2*.py`; refresh with `./scripts/run.sh protoc`) |
| `src/driver/` | Central orchestrator (driver) |
| `src/wrappers/` | `wrapper_common.py` (shared helpers) + OpenSSL / GnuTLS / NSS shims |
| `scripts/run.sh` | **Main entry:** Docker matrix (default), `ci`, `capability-test`; internal steps `protoc` / `certs` for CI and manual use |
| `scripts/` | `gen_certs.sh`, `setup_nssdb.sh`, `test_capability_filter.py` |
| `deploy/` | `Dockerfile`, `wrappers.json` (wrapper names + matrix pairs + launch map), `wrapper_entry.py`, `wrapper_launch.sh`, `matrix.yaml` |
| `scripts/matrix_config.py` | Reads `deploy/wrappers.json` for `run.sh` matrix iteration and name validation |
| `docs/` | Roadmap |

Local NSS DB (`./nssdb/`) is created by `scripts/setup_nssdb.sh` or during the Docker image build; it is not versioned.

---

## Running the tests

Use **`./scripts/run.sh`** (see `./scripts/run.sh help`). Typical flows:

```bash
pip install 'grpcio>=1.80.0' 'grpcio-tools>=1.80.0' 'protobuf>=4.21'
./scripts/run.sh                         # all matrix pairs (deploy/wrappers.json)
./scripts/run.sh openssl-nss             # one combo (also: openssl nss)
./scripts/run.sh ci                      # like GitHub Actions: protoc, certs, tests, matrix
./scripts/run.sh capability-test         # capability filter self-check
```

For ad hoc steps without the full `ci` pipeline, `./scripts/run.sh protoc` and `certs` still exist (used by CI; see the script header).

By default the driver runs every registered scenario: TLS 1.3 and **TLS 1.2** happy paths (`establish_transmit_close`, `establish_transmit_close_tls12`), plus negative checks (`expect_failure_wrong_hostname`, `expect_failure_wrong_port`). Use `python3 src/driver/driver.py --scenario <name>` for one scenario; `--scenario all` is the default. **Quiet output:** **`docker compose build`** uses **`-q`**. The driver prints **`✓` / `✗`** and the scenario name after each test; while a scenario runs, a **braille spinner** is drawn on **stderr** (only if stderr is a TTY, e.g. local terminal — not in typical CI). Skips use **`○`**. **`run.sh`** does not merge driver stderr into stdout so the spinner works under Docker. Use **`python3 src/driver/driver.py -v`** (or **`INTEROP_VERBOSE=1`**, **`./scripts/run.sh -v …`**) for full logs and visible image builds.

**Docker matrix:** **`deploy/wrappers.json`** lists **`wrappers`** and per-stack **`launch`** scripts; **`matrix_pairs` is optional** — if omitted (as in the default file), `scripts/matrix_config.py` builds **every** server×client combination from `wrappers` (Cartesian product). Add an explicit **`matrix_pairs`** array only when you want a **subset** (e.g. faster CI). Override the file path with **`WRAPPERS_CONFIG`**. Compose still uses **`deploy/matrix.yaml`** with **`SERVER_WRAPPER`** / **`CLIENT_WRAPPER`**. Containers start TLS via **`/app/wrapper_launch.sh`** → **`wrapper_entry.py`**. For GnuTLS×NSS, `INTEROP_GNUTLS_NSS_PAIR` is set automatically by `run.sh` (see [Known limitations](#known-limitations)).

```bash
./scripts/run.sh                          # all pairs from wrappers.json
./scripts/run.sh openssl nss
./scripts/run.sh gnutls-gnutls
./scripts/run.sh nss-nss,gnutls-openssl   # several pairs: srv-cli,srv-cli,...
```

Ad hoc matrix run (same as `run.sh gnutls openssl`):

```bash
SERVER_WRAPPER=gnutls CLIENT_WRAPPER=openssl docker compose -p interop-gnutls-openssl -f deploy/matrix.yaml run --rm --build driver
```

**Full pipeline locally (matches CI):** `./scripts/run.sh ci`

### CI (GitHub Actions)

On push/PR to `main`, CI runs `./scripts/run.sh protoc`, `certs`, `capability-test`, then the full Docker matrix via `./scripts/run.sh` (no arguments).

---

## NSS (third implementation)

The driver and proto stay **library-agnostic**. NSS is integrated as a third wrapper (`src/wrappers/wrapper_nss.py`) implementing the same `TlsInteropWrapper` service (`GetMetadata`, `ExecuteOperation`).

| Role   | OpenSSL           | GnuTLS        | NSS        |
|--------|-------------------|---------------|------------|
| Server | `openssl s_server` | `gnutls-serv` | `selfserv` |
| Client | `openssl s_client` | `gnutls-cli`  | `tstclnt`  |

- **NSS DB:** environment `NSSDB` (default `./nssdb`), certificate nickname `CERT_NICKNAME` (default `interop`). Populated by `scripts/setup_nssdb.sh` from `cert.pem` / `key.pem`, or during the Docker image build (`/app/nssdb`).
- **Packages:** Fedora `nss-tools`, Debian/Ubuntu `libnss3-tools`.

GnuTLS×NSS uses extra `tstclnt` logic in `src/wrappers/wrapper_common.py` (`nss_tstclnt_host_and_extra_argv`) when `INTEROP_GNUTLS_NSS_PAIR=1`; see [Known limitations](#known-limitations).

---

## Known limitations

### GnuTLS server × NSS client (SNI vs. TCP peer)

Previously, `tstclnt` used `-h server_node -a server_node`. Docker resolves `server_node` to an IP for the TCP connection, but the ClientHello still carried the **DNS** SNI `server_node`. **GnuTLS 3.8+** rejects that combination and responds with `illegal_parameter` (“disallowed SNI server name”).

**Mitigation (implemented):** When `INTEROP_GNUTLS_NSS_PAIR=1` (set by `run.sh` for the gnutls×nss matrix row), the NSS wrapper **resolves** the configured hostname to an address, passes that to `tstclnt -h`, and **does not** pass `-a`, so the handshake typically omits DNS SNI. Certificate trust still uses `tstclnt -o` for the test self-signed cert. Logic lives in `nss_tstclnt_host_and_extra_argv()` in `src/wrappers/wrapper_common.py`.

Manual run:

```bash
INTEROP_GNUTLS_NSS_PAIR=1 SERVER_WRAPPER=gnutls CLIENT_WRAPPER=nss \
  docker compose -p interop-gnutls-nss -f deploy/matrix.yaml run --rm --build driver
```

If `getaddrinfo` fails, the wrapper falls back to hostname + `-a` (old behaviour).

---

## Draft specification alignment

The codebase follows the draft **“TLS interoperability testing”** spec (v0.1) as a **minimal but growing** slice: shared driver, wrappers, protobuf contract, multiple scenarios.

| Area | Status | Notes |
|------|--------|-------|
| Driver + server/client wrappers | Aligned | Same topology as spec intent |
| `TlsConfig`, ESTABLISH / TRANSMIT / CLOSE | Aligned | `OperationResponse` for results |
| `GetMetadata` / `LibraryMetadata` | Implemented | All three wrappers |
| Capability-based skip | Implemented | Driver; self-test `capability-test` |
| Transport | Different | gRPC (HTTP/2), not raw TCP + custom message framing |
| RequestSender / script → HTTP → driver | Not present | Driver is the orchestrator |
| tmt / fmf, external test plans | Not present | Scenarios live in driver code |
| Full Dispatcher / Coordinator RPC surface | Not present | Single `ExecuteOperation` style API |
| OCSP | Not present | — |

Larger spec items (RequestSender, tmt/fmf, richer control parameters, session/epoch model) are tracked in [docs/ROADMAP.md](docs/ROADMAP.md) as later phases.

---

*Draft / PoC stage.*

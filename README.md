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

- **Driver** – Orchestrates test sessions, synchronizes server/client nodes, evaluates results.
- **Wrappers** – Per-library gRPC servers (OpenSSL, GnuTLS, NSS) that run the TLS tools. See [docs/NSS_SUPPORT.md](docs/NSS_SUPPORT.md).
- **Capability filter** – After `GetMetadata`, the driver skips a scenario (successful exit) if metadata shows the server or client cannot negotiate the required TLS version or role; self-test: `./scripts/run.sh capability-test` (after `protoc`).

## Tech stack

- **Language:** Python 3.x  
- **Communication:** gRPC & Protocol Buffers  
- **Orchestration:** Docker Compose  
- **Libraries under test:** OpenSSL, GnuTLS, NSS (CLI tools)

## Project structure

| Path | Description |
|------|-------------|
| `proto/` | Protocol Buffer definitions |
| `src/driver/` | Central orchestrator (driver) |
| `src/wrappers/` | Library shims (OpenSSL, GnuTLS, NSS) |
| `scripts/run.sh` | **Main entry:** Docker matrix, local test, certs, protoc, compose, CI pipeline |
| `scripts/` | `gen_certs.sh`, `setup_nssdb.sh` (used by image / `run.sh certs`), `test_capability_filter.py` |
| `deploy/` | `Dockerfile`, `wrapper_launch.sh`, `matrix.yaml` (Docker matrix) |
| `docs/` | Limitations, NSS notes, roadmap, spec notes |

Local NSS DB (`./nssdb/`) is created by `scripts/setup_nssdb.sh` or during the Docker image build; it is not versioned.

---

## Running the tests

Use **`./scripts/run.sh`** (see `./scripts/run.sh help`). Typical flows:

```bash
pip install grpcio grpcio-tools 'protobuf>=4.21'
./scripts/run.sh protoc
./scripts/run.sh certs
./scripts/run.sh local          # host OpenSSL×OpenSSL + driver (no Docker)
./scripts/run.sh                # or: ./scripts/run.sh docker — all 9 matrix combos
```

The driver runs two scenarios by default (`establish_transmit_close` and `expect_failure_wrong_hostname`). Use `python3 src/driver/driver.py --scenario establish_transmit_close` for a single scenario.

**Docker matrix:** all pairs use **`deploy/matrix.yaml`** with **`SERVER_WRAPPER`** / **`CLIENT_WRAPPER`**. The image runs **`/app/wrapper_launch.sh`**. `INTEROP_GNUTLS_NSS_PAIR` for GnuTLS×NSS is set automatically — see [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md).

```bash
./scripts/run.sh docker                    # all 9 combos
./scripts/run.sh docker openssl nss        # one combo
./scripts/run.sh docker gnutls-gnutls
```

Ad hoc matrix run (same as `run.sh docker gnutls openssl`):

```bash
SERVER_WRAPPER=gnutls CLIENT_WRAPPER=openssl docker compose -p interop-gnutls-openssl -f deploy/matrix.yaml run --rm --build driver
```

**Full pipeline locally (matches CI):** `./scripts/run.sh ci`

### CI (GitHub Actions)

On push/PR to `main`, CI runs `./scripts/run.sh` steps: `protoc`, `certs`, `capability-test`, `local`, `docker`.

---

*Draft / PoC stage.*

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
- **Capability filter** – After `GetMetadata`, the driver skips a scenario (successful exit) if metadata shows the server or client cannot negotiate the required TLS version or role; self-test: `python3 scripts/test_capability_filter.py` from repo root after `protoc`.

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
| `scripts/` | Certificates, local/Docker run scripts |
| `deploy/` | Dockerfile, compose files |
| `deploy/combos/matrix.yaml` | One parameterized Compose stack (`SERVER_WRAPPER` / `CLIENT_WRAPPER`) |
| `docs/` | Limitations, NSS notes, roadmap, spec notes |

Local NSS DB (`./nssdb/`) is created by `scripts/setup_nssdb.sh` or during the Docker image build; it is not versioned.

---

## Running the tests

### Option 1: Local (no Docker)

Requirements: Python 3, `openssl` CLI, `grpcio`, `protobuf`.

```bash
./scripts/gen_certs.sh
pip install grpcio grpcio-tools 'protobuf>=4.21'
python -m grpc_tools.protoc -I proto --python_out=. --grpc_python_out=. proto/interop.proto
./scripts/run_local.sh
```

The driver runs two scenarios by default (`establish_transmit_close` and `expect_failure_wrong_hostname`). Use `python3 src/driver/driver.py --scenario establish_transmit_close` for a single scenario.

### Option 2: Docker

All server×client pairs use **`deploy/combos/matrix.yaml`**. Wrappers are chosen with environment variables **`SERVER_WRAPPER`** and **`CLIENT_WRAPPER`** (`openssl`, `gnutls`, or `nss`). The image runs **`/app/wrapper_launch.sh`**, which starts the matching Python wrapper. `NSSDB=/app/nssdb` is set for both nodes (ignored by OpenSSL/GnuTLS).

**Default (8 combos, CI):** skips **GnuTLS×NSS** due to a known handshake limitation — see [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md).

```bash
./scripts/run_all_combos.sh
```

**All 9 combos** (including GnuTLS×NSS, may fail):

```bash
./scripts/run_all_combos.sh --all
```

**Single combo:**

```bash
./scripts/run_all_combos.sh openssl nss
./scripts/run_all_combos.sh gnutls-gnutls
# or manually (pick a unique compose project name per run):
SERVER_WRAPPER=gnutls CLIENT_WRAPPER=openssl docker compose -p interop-gnutls-openssl -f deploy/combos/matrix.yaml run --rm --build driver
```

Legacy single-file compose examples:

```bash
./scripts/run_docker.sh
./scripts/run_docker.sh deploy/docker-compose.reversed.yaml
./scripts/run_docker.sh deploy/docker-compose.nss-client.yaml
```

### CI (GitHub Actions)

On push/PR to `main`, CI runs the local test and **`./scripts/run_all_combos.sh`** (8 Docker combos).

---

*Draft / PoC stage.*

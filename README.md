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
- **Wrappers** – Per-library gRPC servers (OpenSSL, GnuTLS, NSS) that run the TLS tools. The framework is designed so that **NSS** (and any further library) is added by implementing one more wrapper; see [docs/NSS_SUPPORT.md](docs/NSS_SUPPORT.md).
- **Capability filter** (planned) – Query wrapper capabilities (ciphers, TLS versions) before running tests.

## Why this approach?

One generic test scenario runs across all supported wrappers instead of maintaining many pairwise manual tests, reducing effort and improving coverage.

## Tech stack

- **Language:** Python 3.x  
- **Communication:** gRPC & Protocol Buffers  
- **Orchestration:** Docker Compose  
- **Libraries under test:** OpenSSL, GnuTLS (CLI)

## Project structure

| Path | Description |
|------|-------------|
| `proto/` | Protocol Buffer definitions |
| `src/driver/` | Central orchestrator (driver) |
| `src/wrappers/` | Library shims (OpenSSL, GnuTLS) |
| `scripts/` | Certificate generation, local run script |
| `deploy/` | Dockerfile and Docker Compose |

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

This starts two OpenSSL wrappers (gRPC on 50051 and 50052) and the driver; TLS uses localhost:5555. The driver runs two scenarios by default (`establish_transmit_close` and `expect_failure_wrong_hostname`) and exits with 0 on success, 1 on failure. Use `python3 src/driver/driver.py --scenario establish_transmit_close` to run a single scenario.

### Option 2: Docker (all in containers)

Services: `server_node`, `client_node` (wrappers), `driver` (orchestrator). Two compositions for **real interoperability**:

| File | TLS server | TLS client |
|------|------------|------------|
| `deploy/docker-compose.yaml` | OpenSSL | GnuTLS |
| `deploy/docker-compose.reversed.yaml` | GnuTLS | OpenSSL |

**One-shot run (containers stop automatically when done):**

```bash
# OpenSSL server ↔ GnuTLS client; then all containers are stopped
./scripts/run_docker.sh

# GnuTLS server ↔ OpenSSL client
./scripts/run_docker.sh deploy/docker-compose.reversed.yaml
```

Or manually: `docker compose -f deploy/docker-compose.yaml run --build driver` and then `docker compose -f deploy/docker-compose.yaml down` to stop the wrappers.

**Background run, then check driver log:**

```bash
docker compose -f deploy/docker-compose.yaml up -d --build
docker compose -f deploy/docker-compose.yaml logs driver
docker compose -f deploy/docker-compose.yaml down
```

To use Docker without sudo, add your user to the `docker` group:  
`sudo usermod -aG docker $USER`, then log out and back in (or run `newgrp docker`).

### CI (GitHub Actions)

On push/PR to `main` or `master`, the [CI workflow](.github/workflows/ci.yml) runs the local test and both Docker compositions. No extra configuration needed when the repo is on GitHub.

---

*This project is in Draft/PoC stage.*

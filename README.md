# TLS Interoperability Testing Framework

Automated interoperability testing for TLS implementations (OpenSSL, GnuTLS, NSS).

## Overview

This project provides a standardized framework for **interoperability testing** of Transport Layer Security (TLS) libraries.

A common problem in cryptographic development is misinterpretation of specs (RFCs). An implementation may pass its own test suite yet fail to interoperate with other libraries or introduce subtle security issues. This framework addresses that by providing a **common test driver** that orchestrates tests across multiple **library wrappers** via a single gRPC contract.

## Architecture

Two logical planes:

1. **Control plane (gRPC/Protobuf)**  
   The **driver** sends high-level commands (`ESTABLISH`, `TRANSMIT`, `CLOSE`) to wrapper nodes via a Protocol Buffer contract.

2. **Data plane (TLS)**  
   **Wrappers** translate those commands into CLI calls (`openssl s_server` / `gnutls-cli`, etc.) and perform the actual TLS handshake and data exchange.

### Components

| Path | Role |
|------|------|
| `src/main.py` | Host CLI: matrix expansion, Docker Compose orchestration |
| `src/core/runner.py` | Host Compose orchestration + container gRPC test driver |
| `src/core/catalog.py` | Parameters, matrix, capabilities JSON, wrapper loading, CLI validation |
| `src/core/identity.py` | Identity PEM paths, NSS DB import rows |
| `src/wrappers/base.py` | Shared gRPC servicer and subprocess helpers for all backends |
| `src/wrappers/<backend>/` | `wrapper.py` (TLS argv from `capabilities.json`) + `capabilities.json` |
| `proto/` | `.proto` schema and generated Python |
| `deploy/` | `Dockerfile`, `compose.yaml`, `wrapper_entry.py` |

**Layout:** `src/wrappers/<backend>/` holds `wrapper.py` and `capabilities.json`; `src/wrappers/base.py` is the shared gRPC base. The Docker image copies `core/` and `wrappers/` under `/app`.

## Tech stack

- **Language:** Python 3.x  
- **Communication:** gRPC & Protocol Buffers  
- **Orchestration:** Docker Compose  
- **Libraries under test:** OpenSSL, GnuTLS, NSS (CLI tools)

## Running the tests

Install host dependencies (matrix CLI only needs protobuf; full runs need Docker):

```bash
pip install 'protobuf>=4.21'
```

List wrappers and catalog options:

```bash
python3 src/main.py --list-wrappers
python3 src/main.py --list-options
```

Run one server×client pair:

```bash
python3 src/main.py --server openssl --client gnutls
```

Run the full 3×3 matrix (as in CI):

```bash
python3 src/main.py --server ALL --client ALL
```

Matrix dimensions support comma lists, `ALL`, and `ALL\excl1,excl2` on `--server`, `--client`, and choice-backed options from the union of all `src/wrappers/*/capabilities.json` files. `ALL` on `--cipher-suite` expands to ciphers declared in the active matrix wrappers’ capabilities. Use `SERVER:CLIENT` on `cipher_suite`, `tls_version`, `supported_groups`, and `signature_schemes` for asymmetric configuration.

Parallel cells: `--jobs N` (each cell gets its own Compose project and dotenv file).

Verbose / dry-run:

```bash
python3 src/main.py --server openssl --client nss -v
python3 src/main.py --server ALL --client ALL --dry-run
```

Regenerate protobuf stubs after editing `proto/interop.proto`:

```bash
python3 -m grpc_tools.protoc -Iproto --python_out=proto --grpc_python_out=proto proto/interop.proto
# Fix gRPC stub import (protoc emits bare ``import interop_pb2``):
#   sed -i 's/^import interop_pb2/from proto import interop_pb2/' proto/interop_pb2_grpc.py
```

### CI (GitHub Actions)

On push/PR to `main`, CI runs `python3 src/main.py --server <matrix.server> --client <matrix.client>` for each pair in the 3×3 grid.

## NSS

| Role   | OpenSSL           | GnuTLS        | NSS        |
|--------|-------------------|---------------|------------|
| Server | `openssl s_server` | `gnutls-serv` | `selfserv` |
| Client | `openssl s_client` | `gnutls-cli`  | `tstclnt`  |

- **NSS DB:** `NSSDB` (default `/app/nssdb` in containers), nickname derived from signature schemes.
- **Packages:** Fedora `nss-tools`, Debian/Ubuntu `libnss3-tools`.

### GnuTLS server × NSS client (SNI)

When the server is GnuTLS and the client is NSS, `core.runner` sets `INTEROP_GNUTLS_NSS_PAIR=1`. The NSS wrapper resolves the peer hostname to an IP for `tstclnt -h` and omits DNS SNI so GnuTLS 3.8+ does not reject the handshake. See comments in `src/wrappers/wrapper_nss.py`.

## Known limitations

- Single driver flow: establish → transmit (echo check) → close (no multi-scenario registry).
- Many `TlsConfig` proto fields are schema-only; only catalog-backed options are translated to CLI.
- Transport is gRPC (HTTP/2), not raw TCP framing from the draft spec.

---

*Draft / PoC stage.*

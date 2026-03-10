# tls-interop-framework
Framework for automated interoperability testing between diverse TLS implementations (OpenSSL, GnuTLS, NSS).

# TLS Interoperability Testing Framework

## Overview
This project provides a standardized, automated framework for **interoperability testing** of Transport Layer Security (TLS) libraries. 

The core problem in cryptographic development is the potential misinterpretation of feature specifications (RFCs). While an implementation might pass its own internal test suite, it may still fail to communicate with other libraries or introduce security vulnerabilities due to subtle incompatibilities. 

This framework solves the scalability issue of manual interoperability testing by providing a **Common Test Driver** that orchestrates tests across multiple **Library Wrappers**.



## Architecture
The system is split into two main logical planes:

1. **Control Plane (gRPC/Protobuf)**: The central **Driver** sends high-level commands (e.g., `ESTABLISH`, `TRANSMIT`) to isolated nodes via a unified Protocol Buffer contract.
2. **Data Plane (TLS)**: The **Library Wrappers** translate these commands into specific CLI calls (e.g., `openssl s_server` or `gnutls-cli`), performing the actual TLS handshake and data exchange over a dedicated network.

### Key Components
- **Common Test Driver**: The "brain" that manages test sessions, synchronizes server/client nodes, and evaluates results.
- **Wrappers**: Translation layers for specific libraries (OpenSSL, GnuTLS, etc.). Each wrapper acts as a gRPC server.
- **Capability Filter**: A mechanism that allows the driver to query a wrapper's capabilities (supported ciphers, TLS versions) before executing relevant tests.

## Why this approach?
Instead of writing $2 \cdot (n-1)!$ manual tests for every new library combination, this framework allows test writers to create **one generic test scenario** that runs across all supported wrappers, significantly reducing QE maintenance costs and increasing test coverage.

## Tech Stack
- **Language**: Python 3.x
- **Communication**: gRPC & Google Protocol Buffers
- **Orchestration**: Docker & Docker Compose
- **Test Management**: Integrated with `tmt` (Test Management Tool) and `fmf` metadata.

## Project Structure
- `/proto`: Protocol Buffer definitions (`.proto` files).
- `/src/driver`: Logic for the central orchestrator.
- `/src/wrappers`: Implementation-specific shims (OpenSSL, GnuTLS).
- `/scripts`: Helper scripts for certificate generation and environment setup.
- `/deploy`: Dockerfiles and orchestration configurations.

---
*Note: This project is currently in the Draft/PoC stage.*

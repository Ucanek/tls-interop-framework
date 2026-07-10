# TLS Interoperability Testing Framework

Automated interoperability testing for TLS implementations (OpenSSL, GnuTLS, NSS).

## Overview

This project provides a standardized framework for **interoperability testing** of Transport Layer Security (TLS) libraries.

A common problem in cryptographic development is misinterpretation of specs (RFCs). An implementation may pass its own test suite yet fail to interoperate with other libraries or introduce subtle security issues. This framework addresses that by providing a **common test driver** that orchestrates tests across multiple **library wrappers** via a single gRPC contract.

Each TLS backend runs as an independent **wrapper subprocess** on the host. The driver expands a test matrix, sends `ESTABLISH` / `TRANSMIT` / `CLOSE` commands over gRPC, and reports per-cell results.

## Architecture

Two logical planes:

1. **Control plane (gRPC/Protobuf)**  
   The **driver** (`src/main.py` + `src/core/runner.py`) sends high-level commands to wrapper nodes via `proto/interop.proto`.

2. **Data plane (TLS)**  
   **Wrappers** translate those commands into CLI calls (`openssl s_server` / `gnutls-serv` / `selfserv`, etc.) and perform the actual TLS handshake and data exchange.

### Components

| Path | Role |
|------|------|
| `src/main.py` | Host CLI: matrix expansion, suite YAML, wrapper orchestration |
| `src/core/runner.py` | Local wrapper subprocesses + gRPC matrix driver |
| `src/core/catalog.py` | Parameters, matrix, capabilities JSON, wrapper discovery, CLI validation |
| `src/core/identity.py` | Identity PEM paths, NSS DB import rows |
| `src/wrappers/base.py` | Shared gRPC servicer and subprocess helpers for all backends |
| `src/wrappers/<backend>/` | `wrapper.py` (TLS argv from `capabilities.json`) + `capabilities.json` |
| `proto/` | `.proto` schema and generated Python stubs |
| `scenarios/` | YAML test suites (`--suite`) |
| `scripts/gen_interop_certs.sh` | RSA/ECDSA/DH identity PEMs under `certs/` |
| `certs/` | Generated test certificates (created on first run) |

**Layout:** `src/wrappers/<backend>/` holds `wrapper.py` and `capabilities.json`; `src/wrappers/base.py` is the shared gRPC base.

### Port map (host)

| Backend | gRPC (host) | TLS data (host) |
|---------|-------------|-----------------|
| openssl | `15051` | `15551` |
| gnutls  | `15052` | `15552` |
| nss     | `15053` | `15553` |

## Tech stack

- **Language:** Python 3.x  
- **Communication:** gRPC & Protocol Buffers  
- **Orchestration:** host subprocesses (one wrapper per backend)
- **Libraries under test:** OpenSSL, GnuTLS, NSS (CLI tools)

## Running the tests

Install host dependencies:

```bash
# CLI tools (Fedora)
sudo dnf install openssl gnutls-bin nss-tools

# CLI tools (Debian/Ubuntu)
sudo apt-get install openssl gnutls-bin libnss3-tools

# Python (matrix driver + generated stubs)
pip install 'grpcio>=1.60' 'protobuf>=4.21' 'PyYAML>=6.0'
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

Wrappers listen on host ports `15051–15053` (gRPC) and `15551–15553` (TLS). Identity PEMs are created automatically on first run (or: `bash scripts/gen_interop_certs.sh`).

```bash
PYTHONPATH=src:proto python3 src/main.py --server openssl --client openssl
python3 src/main.py --server openssl --client gnutls -v
```

Run the full 3×3 matrix:

```bash
python3 src/main.py --server ALL --client ALL
```

Matrix dimensions support comma lists, `ALL`, and `ALL\excl1,excl2` on `--server`, `--client`, and choice-backed options from the union of all `src/wrappers/*/capabilities.json` files. `ALL` on `--cipher-suite` expands to ciphers declared in the active matrix wrappers’ capabilities. Use `SERVER:CLIENT` on `cipher_suite`, `tls_version`, `supported_groups`, and `signature_schemes` for asymmetric configuration.

Parallel cells: `--jobs N` (reserved; persistent backends currently run serially).

Verbose / dry-run:

```bash
python3 src/main.py --server openssl --client nss -v
python3 src/main.py --server ALL --client ALL --dry-run
```

### Test suites (`scenarios/`)

Pre-defined YAML matrices live under `scenarios/`. With `--suite`, matrix dimensions come from the file — do not pass `--server`, `--client`, cipher/group/version flags on the command line.

```bash
python3 src/main.py --suite scenarios/smoke.yaml
python3 src/main.py --suite scenarios/pairwise-tls13.yaml -v
```

| File | Purpose |
|------|---------|
| `smoke.yaml` | Full Milestone 5 cross-product (162 cells) |
| `test.yaml` | Broad development matrix |
| `pairwise-tls12.yaml`, `pairwise-tls13.yaml` | 3×3 server×client per TLS version |
| `ciphers-tls12.yaml`, `ciphers-tls13.yaml` | Cipher suite coverage |
| `groups.yaml` | ECDH groups (`x25519`, `secp-256r1`, `secp-384r1`) |
| `alpn.yaml` | ALPN (`h2`, `http/1.1`) |
| `signature-schemes.yaml` | RSA vs ECDSA identities |
| `features-psk.yaml`, `features-resumption.yaml`, `features-0rtt.yaml`, `features-mtls.yaml`, `features-anonymous.yaml` | Optional TLS features |

Suite YAML uses **catalog ids** from `capabilities.json` (e.g. `aes-128-gcm`, `secp-256r1`), not wire-format OpenSSL cipher names.

Example:

```yaml
matrix:
  server: openssl, gnutls, nss
  client: openssl, gnutls, nss
  tls_version: 1.2, 1.3
  cipher_suite: aes-128-gcm, ecdhe-rsa-aes-128-gcm-sha256
  supported_groups: x25519, secp-256r1
```

Regenerate protobuf stubs after editing `proto/interop.proto`:

```bash
python3 -m grpc_tools.protoc -Iproto --python_out=proto --grpc_python_out=proto proto/interop.proto
# Fix gRPC stub import (protoc emits bare ``import interop_pb2``):
#   sed -i 's/^import interop_pb2/from proto import interop_pb2/' proto/interop_pb2_grpc.py
```

## NSS

| Role   | OpenSSL           | GnuTLS        | NSS        |
|--------|-------------------|---------------|------------|
| Server | `openssl s_server` | `gnutls-serv` | `selfserv` |
| Client | `openssl s_client` | `gnutls-cli`  | `tstclnt`  |

- **NSS DB:** `NSSDB` (default `src/wrappers/nss/nssdb/nss`), nickname derived from signature schemes.
- **Packages:** Fedora `nss-tools`, Debian/Ubuntu `libnss3-tools`. On Fedora 43+, `tstclnt` and `selfserv` live under `/usr/lib64/nss/unsupported-tools/` (resolved automatically; optional: `export PATH="$PATH:/usr/lib64/nss/unsupported-tools"`). The NSS server runs `selfserv` directly on the matrix TLS port (`TlsConfig.port`).

### GnuTLS server × NSS client (SNI)

`src/main.py` starts only the backends required by the matrix and runs all cells over gRPC. When both GnuTLS and NSS are needed, the NSS wrapper's `orchestration_env` hook sets `INTEROP_GNUTLS_NSS_PAIR=1`. The NSS wrapper resolves the peer hostname to an IP for `tstclnt -h` and omits DNS SNI so GnuTLS 3.8+ does not reject the handshake.

## Adding a new wrapper

Wrappers are **plugins**: the driver discovers them from the filesystem. No changes to `src/core/runner.py` or `src/core/catalog.py` are required for a standard backend.

### Discovery

A backend id is registered when **both** files exist:

```
src/wrappers/<id>/wrapper.py
src/wrappers/<id>/capabilities.json
```

`discover_wrapper_ids()` in `src/core/catalog.py` scans `src/wrappers/*/` and returns sorted directory names that satisfy this layout. After adding files, verify:

```bash
python3 src/main.py --list-wrappers
```

### Step-by-step checklist

1. **Pick an id** — lowercase alphanumeric with `_` or `-` (e.g. `mbedtls`). This becomes the wrapper directory name and `WRAPPER` env value when running standalone.

2. **Create `capabilities.json`** — declare what the backend can represent. Copy `src/wrappers/openssl/capabilities.json` or `gnutls` as a template and trim to supported options.

   Required top-level keys:

   | Key | Purpose |
   |-----|---------|
   | `runtime` | Host ports and required CLI binaries |
   | `tls_version` | Map `1.2` / `1.3` to CLI flags |
   | `tls12` / `tls13` | Per-version `cipher_suite` catalog → CLI token maps |
   | `supported_groups` | Catalog group id → CLI token |
   | `signature_schemes` | Catalog scheme id → CLI token |
   | `test_features` | Optional features (`psk`, `mtls`, `resumption`, …) with `supported` / `wired` |

   The `runtime` block (see existing wrappers):

   ```json
   {
     "runtime": {
       "grpc_addr": "127.0.0.1:15054",
       "tls_port": 15554,
       "unsupported_tls_fields": [],
       "local_cli": ["mbedtls_client", "mbedtls_server"]
     }
   }
   ```

   - `grpc_addr` / `tls_port` — **unique host ports** (openssl `15051`/`15551`, gnutls `15052`/`15552`, nss `15053`/`15553`; pick the next free pair for a fourth backend).
   - `local_cli` — executables that must be on `PATH` before running the matrix.
   - `unsupported_tls_fields` — proto field names the wrapper cannot map (cells using them are skipped).

   Catalog ids in JSON are shared across backends where possible (e.g. `aes-128-gcm`, `x25519`). Omit cipher/group entries the library does not support; the matrix driver will **SKIP** cells where either side lacks the token.

3. **Implement `wrapper.py`** — subclass `BaseTemplateWrapper` from `src/wrappers/base.py`.

   Minimum overrides:

   | Method / property | Responsibility |
   |-------------------|----------------|
   | `_component_name` | Human label for `GetMetadata` |
   | `_version_command()` | Argv to print library version |
   | `_start_server(config)` | Build argv, `Popen` server, return `(proc, log_line, message)` |
   | `_start_client(config)` | Build argv, `Popen` client, return `(proc, log_line, message)` |

   Typical pattern (see `src/wrappers/openssl/wrapper.py`):

   - Load `CAPABILITIES` from the JSON file at module level.
   - Map `TlsConfig` fields to CLI switches using catalog helpers (`tls_argv_for_config`, `test_feature_enabled_in_config`, etc.).
   - Use `popen_stdio_merged()` and `format_executed_command()` from `wrappers.utils`.
   - Optionally override `_parse_negotiated_params(stdout)` to extract protocol/cipher/group from CLI output.
   - Add a `if __name__ == "__main__": serve_insecure(MyWrapper, "Label")` block so the module can run standalone.

4. **Optional module-level hooks** in `wrapper.py` (looked up by `call_wrapper_hook()` in `catalog.py`):

   | Hook | When used |
   |------|-----------|
   | `resolve_cli_tool(name)` | Resolve non-standard binary paths (see NSS) |
   | `local_cli_requirements()` | Override `runtime.local_cli` for preflight checks |
   | `orchestration_env(active_backends)` | Extra env when multiple backends run together (e.g. NSS `INTEROP_GNUTLS_NSS_PAIR`) |
   | `local_wrapper_env(repo, backend_id, active_backends)` | Per-backend env for subprocesses (e.g. `NSSDB`) |

5. **Test**:

   ```bash
   # Standalone gRPC server (Ctrl+C to stop)
   PYTHONPATH=src:proto WRAPPER=mbedtls python3 src/wrappers/mbedtls/wrapper.py

   # Single interop cell
   python3 src/main.py --server mbedtls --client openssl -v
   python3 src/main.py --server mbedtls --client gnutls -v
   ```

6. **Extend scenarios** — add the new id to `server` / `client` lines in `scenarios/*.yaml` when you want matrix coverage.

### What you do *not* need to change

- `src/core/runner.py` — starts backends by `grpc_addr` from capabilities.
- `src/core/catalog.py` — auto-merges catalog options from all `capabilities.json` files.
- `proto/interop.proto` — unless you need new `TlsConfig` fields (then regenerate stubs and map them in your wrapper).

### Complexity notes

- **Simple case:** a backend with `s_server`/`s_client`-style CLIs and straightforward flag mapping (similar to OpenSSL).
- **Medium:** version-specific cipher tables, ALPN, session tickets, custom cert layout (GnuTLS).
- **Heavy:** persistent state (NSS database), cross-backend workarounds, native helpers (GnuTLS `gnutls_session_hook.so`).

Start by copying the closest existing wrapper and deleting unsupported catalog entries until basic `ESTABLISH` + `TRANSMIT` works.

## Known limitations

- Single driver flow: establish → transmit (echo check) → close (no multi-scenario registry).
- Many `TlsConfig` proto fields are schema-only; only catalog-backed options are translated to CLI.
- Transport is gRPC (HTTP/2), not raw TCP framing from the draft spec.

---

*Draft / PoC stage.*

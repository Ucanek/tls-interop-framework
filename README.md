# TLS Interoperability Testing Framework

Cross-test TLS 1.2/1.3 between **OpenSSL**, **GnuTLS**, and **Mozilla NSS**. The driver starts wrapper subprocesses, runs a parameter matrix, and reports **OK** / **FAIL** / **SKIP** per cell (handshake → echo `TRANSMIT` → `CLOSE`). Mismatches are never reported as OK.

## Quick start

```bash
# Fedora                          # Debian / Ubuntu
sudo dnf install openssl gnutls-bin nss-tools
sudo apt-get install openssl gnutls-bin libnss3-tools

pip install -e .

make gnutls-hook   # GnuTLS session resumption LD_PRELOAD hook (needs gcc + libgnutls dev)

tls-interop --server openssl --client gnutls
tls-interop --suite scenarios/pairwise-tls13.yaml   # 9 cells, TLS 1.3 3×3

tls-interop --list-wrappers
tls-interop --list-options     # catalog ids: aes-128-gcm, x25519, …
```

After `pip install -e .`, you can also run `python -m main` or `python3 src/main.py` from the repo root.

Protobuf/gRPC stubs live in `interop_proto/` (not `proto`, to avoid clashing with the unrelated PyPI `proto` package).

`certs/` is created on first run (`scripts/gen_interop_certs.sh`).


| Backend | gRPC  | TLS   | Server CLI         | Client CLI         |
| ------- | ----- | ----- | ------------------ | ------------------ |
| openssl | 15051 | 15551 | `openssl s_server` | `openssl s_client` |
| gnutls  | 15052 | 15552 | `gnutls-serv`      | `gnutls-cli`       |
| nss     | 15053 | 15553 | `selfserv`         | `tstclnt`          |


Wrappers live in `src/wrappers/<backend>/` (`wrapper.py` + `capabilities.json`).

## CLI matrix

```bash
tls-interop --server ALL --client ALL
tls-interop --server openssl --client nss -v
tls-interop --server openssl --client openssl --tls-port 4433
```


| Syntax           | Meaning                      |
| ---------------- | ---------------------------- |
| `openssl,gnutls` | comma list                   |
| `ALL`            | all values from capabilities |
| `ALL\nss`        | all except `nss`             |
| `openssl:gnutls` | asymmetric server:client     |


Applies to `--server`, `--client`, `--cipher-suite`, `--tls-version`, `--supported-groups`, `--signature-schemes`, `--alpn`, `--test-features`. Use **catalog ids** from `capabilities.json`, not raw OpenSSL cipher names.

## YAML suites

```bash
tls-interop --suite scenarios/pairwise-tls13.yaml
tls-interop -s scenarios/ciphers-tls13.yaml -v
```

With `--suite`, do not pass `--server` / `--client` or other matrix flags — values come from the file. See `scenarios/` (start with `pairwise-tls13.yaml`, then `pairwise-tls12.yaml`; `smoke.yaml` is the full 162-cell run).

## Results


| OK | FAIL | SKIP | TIMEOUT |
|----|------|------|---------|
| handshake + echo OK | error | unsupported / disabled feature | `--cell-timeout` exceeded |

Default cell limit: **45 s** (`--cell-timeout`). On expiry the driver sends gRPC CLOSE (kills wrapper CLI procs) and continues the matrix.

Parallel runs: `--jobs N` (default 1) starts **N isolated wrapper sets** (gRPC/TLS port stride 100 per slot). Incompatible with `--attach`, `--tls-port`, and manual gRPC port overrides.

On **FAIL** or **TIMEOUT**, logs appear under `debug_logs/run_<timestamp>/` (`fail_*.log` or `timeout_*.log`). No folder if all cells pass.

## Manual debug (`--attach`)

Use `--attach` when you want to **run wrappers yourself** and let the driver only send gRPC commands. 

**Without `--attach`:** driver starts wrapper subprocesses, waits for gRPC, runs cells, then stops wrappers.

**With `--attach`:** driver connects to wrappers already listening on localhost; it does **not** start, stop, or kill them.

```bash
# Terminal 1 — server backend (openssl example)
GRPC_PORT=15051 python3 -m wrappers.openssl.wrapper

# Terminal 2 — client backend (gnutls example)
GRPC_PORT=15052 python3 -m wrappers.gnutls.wrapper

# Terminal 3 — driver
tls-interop --server openssl --client gnutls --attach -v
```

Start both wrappers **before** the driver. `GRPC_PORT` must match the gRPC port the driver uses (defaults from `capabilities.json`: openssl `15051`, gnutls `15052`, nss `15053`). Requires `pip install -e .` so wrapper modules resolve without `PYTHONPATH`. If you use other ports:

```bash
tls-interop --server openssl --client gnutls --attach \
  --server-grpc-port 15051 --client-grpc-port 15052 -v
```

Notes:

- **Same backend on both sides** (`openssl` × `openssl`): one wrapper process is enough — driver uses a single gRPC connection for server and client roles.
- `--attach` applies to direct CLI runs (`--server` / `--client`), not only single pairs — matrix flags and `--suite` still work; you must have every backend in the matrix running on the expected gRPC ports.

## NSS

- Fedora 43+: `tstclnt` / `selfserv` in `/usr/lib64/nss/unsupported-tools/` (auto-resolved).
- `tstclnt` has no ALPN; `selfserv` serves one connection then exits (wrapper restarts it).
- GnuTLS server × NSS client: `INTEROP_GNUTLS_NSS_PAIR` is set automatically when both run in one matrix.
- Session resumption: build `gnutls_session_hook.so` once with `make gnutls-hook` (requires `gcc`, `pkg-config`, GnuTLS headers). Without it, resumption tests skip the hook (no runtime compile).

## New wrapper

Add `src/wrappers/<id>/wrapper.py` + `capabilities.json` (copy `openssl`), unique gRPC/TLS ports, then `tls-interop --list-wrappers`.
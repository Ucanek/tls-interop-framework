# TLS Interoperability Testing Framework

Cross-test TLS 1.2/1.3 between **OpenSSL**, **GnuTLS**, and **Mozilla NSS**. The driver starts wrapper subprocesses, runs a parameter matrix, and reports **PASS** / **FAIL** / **SKIP** per cell (handshake → echo `TRANSMIT` → `CLOSE`). Mismatches are never reported as PASS.

## Quick start

```bash
# Fedora                          # Debian / Ubuntu
sudo dnf install openssl gnutls-bin nss-tools
sudo apt-get install openssl gnutls-bin libnss3-tools

pip install 'grpcio>=1.60' 'protobuf>=4.21' 'PyYAML>=6.0'

python3 main.py --server openssl --client gnutls
python3 main.py --suite scenarios/pairwise-tls13.yaml   # 9 cells, TLS 1.3 3×3

python3 main.py --list-wrappers
python3 main.py --list-options     # catalog ids: aes-128-gcm, x25519, …
```

`certs/` is created on first run (`core/gen_interop_certs.sh`).


| Backend | gRPC  | TLS   | Server CLI         | Client CLI         |
| ------- | ----- | ----- | ------------------ | ------------------ |
| openssl | 15051 | 15551 | `openssl s_server` | `openssl s_client` |
| gnutls  | 15052 | 15552 | `gnutls-serv`      | `gnutls-cli`       |
| nss     | 15053 | 15553 | `selfserv`         | `tstclnt`          |


Wrappers live in `wrappers/<backend>/` (`wrapper.py` + `capabilities.json`).

## CLI matrix

```bash
python3 main.py --server ALL --client ALL
python3 main.py --server openssl --client nss -v
python3 main.py --server openssl --client openssl --tls-port 4433
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
python3 main.py --suite scenarios/pairwise-tls13.yaml
python3 main.py --suite scenarios/ciphers-tls13.yaml -v
```

With `--suite`, do not pass `--server` / `--client` or other matrix flags — values come from the file. See `scenarios/` (start with `pairwise-tls13.yaml`, then `pairwise-tls12.yaml`; `smoke.yaml` is the full 162-cell run).

## Results


| PASS | FAIL | SKIP | TIMEOUT |
|----|------|------|---------|
| handshake + echo PASS | error | unsupported / disabled feature | cell wall-clock limit exceeded |

Default cell limit: **45 s**. On expiry the driver sends gRPC CLOSE (kills wrapper CLI procs) and continues the matrix.

Parallel runs: `--jobs N` (default 1) starts **N isolated wrapper sets** (gRPC/TLS port stride 100 per slot). Incompatible with `--attach`, `--tls-port`, and manual gRPC port overrides.

On **FAIL** or **TIMEOUT**, logs appear under `debug_logs/run_<timestamp>/` (`fail_*.log` or `timeout_*.log`). No folder if all cells pass.

## Manual debug (`--attach`)

Use `--attach` when wrappers are **already** listening on localhost and the driver should only send gRPC (it will not start or stop them).

Without `--attach`, the driver starts wrapper subprocesses, runs cells, then stops them.

```bash
# Wrappers must already listen on capabilities.json gRPC ports (or overrides below).
python3 main.py --server openssl --client gnutls --attach -v

python3 main.py --server openssl --client gnutls --attach \
  --server-grpc-port 15051 --client-grpc-port 15052 -v
```

Notes:

- **Same backend on both sides** (`openssl` × `openssl`): one wrapper process is enough — driver uses a single gRPC connection for server and client roles.
- `--attach` works with matrix flags and `--suite`; every backend in the matrix must already be running on the expected gRPC ports.

## NSS

- Fedora 43+: `tstclnt` / `selfserv` in `/usr/lib64/nss/unsupported-tools/` (auto-resolved).
- `tstclnt` has no ALPN; `selfserv` serves one connection then exits (wrapper restarts it).
- GnuTLS server × NSS client: `INTEROP_GNUTLS_NSS_PAIR` is set automatically when both run in one matrix.

## New wrapper

Add `wrappers/<id>/wrapper.py` + `capabilities.json` (copy `openssl`), unique gRPC/TLS ports, then `python3 main.py --list-wrappers`.
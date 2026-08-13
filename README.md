# TLS Interoperability Testing Framework

Cross-test TLS 1.2/1.3 between **OpenSSL**, **GnuTLS**, and **Mozilla NSS**. The driver starts wrapper subprocesses, runs a parameter matrix, and reports **OK** / **FAIL** / **SKIP** per cell (handshake → echo `TRANSMIT` → `CLOSE`). Mismatches are never reported as OK.

## Quick start

```bash
# Fedora                          # Debian / Ubuntu
sudo dnf install openssl gnutls-bin nss-tools
sudo apt-get install openssl gnutls-bin libnss3-tools

pip install 'grpcio>=1.60' 'protobuf>=4.21' 'PyYAML>=6.0'

python3 src/main.py --server openssl --client gnutls
python3 src/main.py --suite scenarios/pairwise-tls13.yaml   # 9 cells, TLS 1.3 3×3

python3 src/main.py --list-wrappers
python3 src/main.py --list-options     # catalog ids: aes-128-gcm, x25519, …
```

`certs/` is created on first run (`scripts/gen_interop_certs.sh`).


| Backend | gRPC  | TLS   | Server CLI         | Client CLI         |
| ------- | ----- | ----- | ------------------ | ------------------ |
| openssl | 15051 | 15551 | `openssl s_server` | `openssl s_client` |
| gnutls  | 15052 | 15552 | `gnutls-serv`      | `gnutls-cli`       |
| nss     | 15053 | 15553 | `selfserv`         | `tstclnt`          |


Wrappers live in `src/wrappers/<backend>/` (`wrapper.py` + `capabilities.json`).

## CLI matrix

```bash
python3 src/main.py --server ALL --client ALL
python3 src/main.py --server openssl --client nss -v
python3 src/main.py --server openssl --client openssl --tls-port 4433
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
python3 src/main.py --suite scenarios/pairwise-tls13.yaml
python3 src/main.py -s scenarios/ciphers-tls13.yaml -v
```

With `--suite`, do not pass `--server` / `--client` or other matrix flags — values come from the file. See `scenarios/` (start with `pairwise-tls13.yaml`, then `pairwise-tls12.yaml`; `smoke.yaml` is the full 162-cell run).

## Results


| OK                  | FAIL            | SKIP                                   |
| ------------------- | --------------- | -------------------------------------- |
| handshake + echo OK | error / timeout | unsupported option or disabled feature |


On **FAIL**, logs appear under `debug_logs/run_<timestamp>/fail_<server>_x_<client>_….log` (CLI cmd, stdout, `TlsConfig`). No folder if all cells pass.

## Manual debug (`--attach`)

Use `--attach` when you want to **run wrappers yourself** and let the driver only send gRPC commands. 

**Without `--attach`:** driver starts wrapper subprocesses, waits for gRPC, runs cells, then stops wrappers.

**With `--attach`:** driver connects to wrappers already listening on localhost; it does **not** start, stop, or kill them.

```bash
# Terminal 1 — server backend (openssl example)
GRPC_PORT=15051 PYTHONPATH=src:proto python3 -m wrappers.openssl.wrapper

# Terminal 2 — client backend (gnutls example)
GRPC_PORT=15052 PYTHONPATH=src:proto python3 -m wrappers.gnutls.wrapper

# Terminal 3 — driver
python3 src/main.py --server openssl --client gnutls --attach -v
```

Start both wrappers **before** the driver. `GRPC_PORT` must match the gRPC port the driver uses (defaults from `capabilities.json`: openssl `15051`, gnutls `15052`, nss `15053`). If you use other ports:

```bash
python3 src/main.py --server openssl --client gnutls --attach \
  --server-grpc-port 15051 --client-grpc-port 15052 -v
```

Notes:

- **Same backend on both sides** (`openssl` × `openssl`): one wrapper process is enough — driver uses a single gRPC connection for server and client roles.
- `--attach` applies to direct CLI runs (`--server` / `--client`), not only single pairs — matrix flags and `--suite` still work; you must have every backend in the matrix running on the expected gRPC ports.

## NSS

- Fedora 43+: `tstclnt` / `selfserv` in `/usr/lib64/nss/unsupported-tools/` (auto-resolved).
- `tstclnt` has no ALPN; `selfserv` serves one connection then exits (wrapper restarts it).
- GnuTLS server × NSS client: `INTEROP_GNUTLS_NSS_PAIR` is set automatically when both run in one matrix.

## New wrapper

Add `src/wrappers/<id>/wrapper.py` + `capabilities.json` (copy `openssl`), unique gRPC/TLS ports, then `python3 src/main.py --list-wrappers`.
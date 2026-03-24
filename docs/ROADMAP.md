# Roadmap – How we proceed

Recommended order of work, aligned with the draft spec and current codebase.

**Target components:** OpenSSL, GnuTLS, **NSS**. The framework must work with all three; the driver and proto stay library-agnostic. See [NSS_SUPPORT.md](NSS_SUPPORT.md) for how NSS fits in.

---

## Phase 1: Capabilities (spec alignment)

**Goal:** Driver can ask wrappers what they support; optional use in test selection.

| Step | What | Outcome |
|------|------|--------|
| 1.1 | Implement **GetMetadata** in OpenSSL wrapper | Return `LibraryMetadata`: component_name, version (from `openssl version`), roles [CLIENT, SERVER], supported_versions / cipher_suites / groups (e.g. from CLI or fixed TLS 1.3 list) with ModifyFlags. |
| 1.2 | Implement **GetMetadata** in GnuTLS wrapper | Same shape; version from `gnutls-cli --version`, capabilities from GnuTLS priority or fixed set. |
| 1.3 | Driver calls GetMetadata before test (optional) | Log or display metadata; later use it to skip incompatible tests (capability filter). |

**Definition of done:** OpenSSL and GnuTLS wrappers respond to GetMetadata; driver can call it and print or use the result. No breaking change to current test. (NSS wrapper will implement GetMetadata when added.)

---

## Phase 2: More tests and driver structure

**Goal:** Not everything in one script; easy to add scenarios.

| Step | What | Outcome |
|------|------|--------|
| 2.1 | Extract test into **scenario functions** (e.g. `run_establish_transmit_close()`) | Driver has a small list of scenarios; main() runs one or all. |
| 2.2 | Add **one more scenario** | e.g. “wrong hostname” or “TLS 1.2 only” (if CLI allows), or simple KEY_UPDATE test when wrappers support it. |
| 2.3 | (Optional) **Capability filter** | Before running a scenario, driver checks metadata and skips if e.g. TLS version not supported. |

**Definition of done:** At least two runnable scenarios; driver code is easier to extend.

---

## Phase 3: CI and robustness

**Goal:** Every change is automatically tested.

| Step | What | Outcome |
|------|------|--------|
| 3.1 | **CI workflow** (e.g. GitHub Actions) | On push/PR: run `./scripts/run_local.sh` (or equivalent), then `docker compose -f deploy/docker-compose.yaml run driver` (and optionally reversed). |
| 3.2 | **Error handling** | Driver checks `OperationResponse.status` for each call; report FAILURE/ERROR clearly and exit non‑zero on failure. |

**Definition of done:** CI runs local + Docker tests; failed response from wrapper fails the run.

---

## Phase 4: NSS wrapper (full support for three libraries)

**Goal:** Framework works with NSS the same way as with OpenSSL and GnuTLS.

| Step | What | Outcome |
|------|------|--------|
| 4.1 | **NSS wrapper** `src/wrappers/wrapper_nss.py` | Same gRPC service as OpenSSL/GnuTLS; ESTABLISH → `selfserv` / `tstclnt`, TRANSMIT (stdin/stdout), CLOSE. Cert handling: NSS DB (e.g. create DB + import cert in container or from TlsConfig). |
| 4.2 | **GetMetadata for NSS** | component_name `"NSS"`, version from NSS, roles, capabilities (versions/ciphers/groups) with ModifyFlags. |
| 4.3 | **Docker and Compose** | Image (or variant) with `nss-tools`, NSS DB setup; compose profile or file for NSS as server and/or client. |
| 4.4 | **CI** | At least one job with NSS in the mix (e.g. NSS client vs OpenSSL server). |

**Definition of done:** Same scenarios run with NSS as one of the two nodes; no driver changes. See [NSS_SUPPORT.md](NSS_SUPPORT.md).

---

## Phase 5: Later (when needed)

- **RequestSender / HTTP API:** If tests should be written as scripts that call the driver via HTTP (per spec).
- **tmt / fmf:** Integrate with tmt plans and fmf metadata so tests are discoverable and runnable as a “test plan”.
- **Control parameters:** Config file or CLI for “which component pairs to test” (e.g. ALL-S × GnuTLS-C, including NSS).
- **Session/test/epoch model:** If we need session-level setup and multiple tests per session.

---

## Suggested next action

**Done:** Phase 1, 2.1–2.2, 3 (CI + error handling), 4 (NSS wrapper), `run_docker.sh`, `setup_nssdb.sh` (find certutil/pk12util).

**Next (when useful):**

- **Phase 2.3 (optional) – Capability filter**  
  Driver uses GetMetadata to skip scenarios a wrapper can’t support (e.g. TLS 1.2 when only 1.3 is reported).

- **Phase 5 – Later**  
  RequestSender/HTTP API, tmt/fmf, control parameters (which pairs to test), session/test epochs. Start when the spec or usage requires it.

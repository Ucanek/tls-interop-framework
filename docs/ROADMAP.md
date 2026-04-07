# Roadmap – How we proceed

Recommended order of work, aligned with the draft spec and current codebase.

**Target components:** OpenSSL, GnuTLS, **NSS**. The framework runs all three; the driver and proto stay library-agnostic. NSS tooling, DB layout, and the GnuTLS×NSS workaround are documented in [README.md](../README.md) (sections *NSS* and *Known limitations*).

---

## Current status (snapshot)

| Phase | Theme | Largely done |
|-------|--------|----------------|
| 1 | `GetMetadata` in wrappers | Yes (OpenSSL, GnuTLS, NSS) |
| 2 | Scenarios + capability filter | Yes (`scenario_skip_reason`, `./scripts/run.sh capability-test`) |
| 3 | CI + response handling | Yes (GitHub Actions, `run.sh ci`) |
| 4 | NSS wrapper + matrix | Yes (`wrapper_nss.py`, `matrix.yaml`, `setup_nssdb.sh`) |
| 5 | Spec extras | Optional / when needed |

---

## Phase 1: Capabilities (spec alignment)

**Goal:** Driver can ask wrappers what they support; use in test selection.

| Step | What | Outcome |
|------|------|--------|
| 1.1 | **GetMetadata** in OpenSSL wrapper | `LibraryMetadata`: name, version, roles, supported_versions / cipher_suites / groups |
| 1.2 | **GetMetadata** in GnuTLS wrapper | Same shape |
| 1.3 | Driver uses GetMetadata | Log metadata; **skip** scenarios when capabilities insufficient |

**Definition of done:** ✅ All three wrappers implement GetMetadata; driver calls it and applies the capability filter.

---

## Phase 2: More tests and driver structure

**Goal:** Not everything in one blob; easy to add scenarios.

| Step | What | Outcome |
|------|------|--------|
| 2.1 | **Scenario functions** | Driver runs a list of scenarios |
| 2.2 | **Additional scenarios** | Wrong hostname, wrong port, TLS 1.2 happy path; KEY_UPDATE still future |
| 2.3 | **Capability filter** | Skip with success + `SKIP` log when metadata rules out a scenario |

**Definition of done:** ✅ Multiple scenarios; filter covered by `capability-test`.

---

## Phase 3: CI and robustness

**Goal:** Every change is automatically tested.

| Step | What | Outcome |
|------|------|--------|
| 3.1 | **CI workflow** | `./scripts/run.sh` (`protoc`, `certs`, `local`, `docker`, …) |
| 3.2 | **Error handling** | Non-zero exit on failed `OperationResponse` |

**Definition of done:** ✅ CI runs local + Docker matrix; failures fail the job.

---

## Phase 4: NSS wrapper (full support for three libraries)

**Goal:** NSS on par with OpenSSL/GnuTLS in the matrix.

| Step | What | Outcome |
|------|------|--------|
| 4.1 | **NSS wrapper** | `wrapper_nss.py`, `selfserv` / `tstclnt`, NSS DB |
| 4.2 | **GetMetadata for NSS** | Same metadata shape as other wrappers |
| 4.3 | **Docker / Compose** | Image with `nss-tools`, `matrix.yaml` rows for NSS |
| 4.4 | **CI** | NSS included in matrix runs |

**Definition of done:** ✅ Same scenarios across NSS combinations; GnuTLS×NSS env documented in README.

---

## Phase 5: Later (when needed)

- **RequestSender / HTTP API:** If tests should be scripts that call the driver via HTTP (per spec).
- **tmt / fmf:** Discoverable “test plans” and metadata.
- **Control parameters:** Driver-level config for pairs (beyond compose / `run.sh` args).
- **Session / test / epoch model:** Session-level setup and multiple tests per session.

---

## Suggested next action

**Next (when useful):** Phase 5 items above, or extend scenarios (e.g. KEY_UPDATE, stricter TLS version cases) and metadata fields if the spec or downstream tests need them.

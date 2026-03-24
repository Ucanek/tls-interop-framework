# Compliance with Draft Specification "TLS interoperability testing"

This document compares the current implementation to the draft spec (Name: TLS interoperability testing, State: Draft, Version: 0.1).

---

## Summary

| Area | Status | Notes |
|------|--------|--------|
| Abstract / goal | ✅ Aligned | Single test across implementations, driver + wrappers, Protocol Buffers |
| Common test driver | ✅ Partial | Orchestrates tests, syncs server/client; not yet configurable by capabilities |
| Wrappers | ✅ Aligned | Intermediary, interpret requests, common format (proto) |
| Metadata / capabilities | ⚠️ Proto only | `GetMetadata` + `LibraryMetadata` in proto; **not implemented** in wrappers or driver |
| Communication | ⚠️ Different | gRPC (not raw sockets + custom message types); no Dispatcher/Coordinator split as in spec |
| RequestSender | ❌ Not present | Spec: test scripts → HTTP → driver. Current: driver is the only caller of wrappers |
| Tests / tmt / fmf | ❌ Not present | No tmt plans, no fmf metadata, no “test plan” abstraction |
| Control parameters | ❌ Not present | No “list of pairs”, no ALL/component selection, no capability filter usage |
| Pipeline / epochs | ❌ Not present | No session vs test vs TLS epoch model; single hardcoded test |
| Topology | ✅ Conceptually same | Driver + two wrapper endpoints (server + client) |

**Overall:** The project implements a **minimal viable slice** of the spec: one common driver, two wrappers (OpenSSL, GnuTLS), Protocol Buffers over gRPC, and one test (establish → transmit → close). **NSS** is a required third component; the design (driver-agnostic, one wrapper per library) is intended to support NSS without driver changes—see [NSS_SUPPORT.md](NSS_SUPPORT.md). The project does **not** yet implement capability-based filtering, tmt/fmf, RequestSender, or the full message/API layout from the spec.

---

## What Matches or Is Close

### Abstract and goal
- Standardized framework for TLS library interoperability: **yes**.
- Single test across multiple implementations: **yes** (one test, two implementations).
- Common test driver: **yes**.
- Wrapper as intermediary: **yes**.
- Protocol Buffers for communication: **yes** (gRPC + protobuf).

### Common test driver (spec)
- Controls initialization, execution, evaluation: **yes** (for one test).
- Synchronization between client and server: **yes** (ordered ESTABLISH → TRANSMIT → CLOSE).
- Configurable to run specific tests against specific components: **no** – single fixed test, components fixed by Docker/compose.

### Wrappers (spec)
- Intermediary between driver and component utility: **yes**.
- Correct interpretation of requests: **yes** (ESTABLISH, TRANSMIT, CLOSE).
- Result in common format: **yes** (`OperationResponse`).

### Proto vs spec concepts
- **Roles:** CLIENT / SERVER – **yes** (`Role`).
- **ModifyFlag:** Unsupported, Read, Set, Negotiate – **yes** (same semantics in proto).
- **Capabilities:** supported_versions, cipher_suites, groups – **yes** in `LibraryMetadata` (names slightly different; spec also has signatureAlgorithms, ecPointFormats, etc.).
- **Operations:** establish, transmit, close – **yes**; key_update – **yes** in proto (not used in driver yet).
- **Ack-like response:** status (ok/bad/error) – **yes** (`OperationResponse.Status`).
- **Config:** hostname, port, certificate, key – **yes** (`TlsConfig`).

### Topology
- Driver talks to server wrapper and client wrapper; TLS is between the two component utilities. **Matches** the intended topology (aside from optional OCSP/RequestSender).

---

## What Differs or Is Missing

### Communication
- **Spec:** Sockets, TCP, custom message framing (type, sequence_number, opcode), optional TLS.
- **Current:** gRPC (HTTP/2), single service `TlsInteropWrapper` with `GetMetadata` and `ExecuteOperation`. No explicit Dispatcher vs Coordinator transport split; both are conceptually in one service.

### RequestSender
- **Spec:** Component that turns test scripts into requests to the driver (e.g. HTTP). Tests written in scripts; RequestSender talks to driver.
- **Current:** No RequestSender. The driver is the only active part; it runs one built-in test. No HTTP API for “test scripts”.

### Metadata and capability filter
- **Spec:** Wrappers send metadata (capabilities); driver uses it to decide which tests run (capability filter).
- **Current:** Proto has `GetMetadata` and `LibraryMetadata`, but wrappers do **not** implement `GetMetadata`. Driver does **not** call it and does **not** filter tests by capabilities.

### Control parameters
- **Spec:** Test combination from list of pairs (e.g. `{ GnuTLS-C, ALL-S }`), common args (files), TLS args, capability filter.
- **Current:** No such configuration. Which library is server/client is fixed by Docker Compose (and reversed compose), not by driver config.

### Pipeline and epochs
- **Spec:** Session (tmt plan) → test → TLS (single session). Initial setup, test execution, cleanup at session/test level.
- **Current:** Single test, single TLS session, no session/test/epoch model, no tmt/fmf.

### Tests and tmt/fmf
- **Spec:** Tests follow common interface; run with tmt and fmf; multiple TLS connections per test.
- **Current:** One test in driver code; no tmt, no fmf, no test repository.

### Dispatcher operations (spec)
- getLibraries, setLibraries, getAvailableLibraries, getServerHostname, setEndpointRole, getStatus.
- **Current:** None of these as separate RPCs. Hostname/port/role are inside `ExecuteOperation` (TlsConfig, Role). No “list of libraries” or “set endpoint role” API.

### Coordinator operations (spec)
- set_common_params, set_tls_params, tls_operation, fetch logs, cleanup(scope).
- **Current:** Single “execute operation” (establish/transmit/close). No separate set_params; config is passed per request. Logs are in `OperationResponse.logs` but not a dedicated “fetch logs” RPC. Cleanup is one operation, no scope.

### Capability details
- **Spec:** Many capability types (signatureAlgorithms, ecPointFormats, psKeyExchangeMode, extensions, certificate, certificateAuth, etc.).
- **Current:** Proto has a generic `Capability` (name + flags) and `LibraryMetadata` with supported_versions, cipher_suites, groups. Enough for a minimal capability filter later, but not the full list from the spec.

### Other services
- **Spec:** OCSP alongside driver.
- **Current:** No OCSP.

---

## Conclusion

**Does the current project “odpovídá” (comply with) the spec?**  
**Partially.** It implements the core idea (common driver, wrappers, one test across two implementations, protobuf-based communication) and the proto already reflects parts of the spec (roles, modify flags, metadata shape, operations). It does **not** yet implement:

- Metadata/capability flow (GetMetadata in wrappers + driver using it).
- RequestSender, tmt/fmf, test plans, or configurable test combinations.
- The exact communication layer (sockets + custom framing) or the full Dispatcher/Coordinator API from the spec.

So: **yes, it corresponds as a minimal first step**; the rest of the spec is the target for future iterations (GetMetadata + capability filter next, then control parameters and tmt/fmf if desired).

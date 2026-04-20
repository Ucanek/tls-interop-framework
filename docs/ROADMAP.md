# Roadmap

This roadmap is aligned with:

- **Upstream interoperability architecture** — fmf metadata, tmt-based discovery/execution, generic test runner, subject metadata, separate test-case repository.
- **Crypto Team epic (automated / “second approach”)** — one logical test per scenario across all client×server pairs, common interface, wrappers, success criteria for upstream CI and shared maintenance.

NSS tooling, the GnuTLS×NSS workaround, and how to run the matrix are documented in [README.md](../README.md).

---

## Current baseline (done)

The repository already delivers the **core of the second (universal) approach**: a **common test driver**, **gRPC/Protobuf contract**, **per-library wrappers** (OpenSSL, GnuTLS, NSS), a **full Docker matrix** of pairs, **`GetMetadata` / capability-based skips**, and **CI** (`protoc`, certs, capability self-check, matrix).

| Area | Status |
|------|--------|
| Wrappers + `GetMetadata` | Done for all three stacks |
| Driver scenarios + capability filter | Done (`scenario_skip_reason`, `capability-test`) |
| Docker image + `matrix.yaml` + `run.sh` | Done (including NSS DB / image layout) |
| CI on this repo | Done (GitHub Actions) |

**Note:** The **first subproject** (manual, library-specific tests for hard corner cases) remains complementary; this codebase does not replace it.

---

## Unified gap analysis

The sections below merge what still differs from **both** the upstream architecture doc and the epic’s **success criteria / design**.

### 1. Test discovery and packaging

| Gap | Source |
|-----|--------|
| No **fmf** metadata or **tmt** execution (discover/filter/run tests from the tree) | Upstream architecture |
| Tests are **methods in the driver**, not standalone scripts + metadata in a **tests-only** layout | Both |
| No published pattern for a **central “interop tests” repo** separate from runner/wrappers | Epic |

### 2. Generic runner and upstream integration

| Gap | Source |
|-----|--------|
| Runner is tuned to **this** wrapper set and Docker Compose, not a documented **plug-in** model for arbitrary future components | Epic |
| **Upstream projects** cannot yet “drop in” interop on **every PR** without custom work; missing **reusable CI recipe** (container, action, minimal steps) | Epic success criteria |
| **Documentation** focuses on cloning this repo; weak on **integrating into another project’s CI** | Epic |

### 3. Common interface and metadata depth

| Gap | Source |
|-----|--------|
| Interface is **Protobuf** (good) but narrow; no separate **capability catalog** / versioned interface doc beside `.proto` | Upstream architecture |
| **Subject-side metadata files** (deps, how to build/run driver, protocol version) are not used — only runtime `GetMetadata` | Upstream architecture |
| **RequestSender / HTTP** entrypoint for external test scripts not present | Draft spec (README table) |

### 4. Wrapper observability and spec detail

| Gap | Source |
|-----|--------|
| Wrappers do not reliably **log executed commands** for manual reproduction (epic explicitly asks for this) | Epic design |
| **KEY_UPDATE**, richer TLS cases, new extensions / future protocol versions | Roadmap + epic maintenance note |
| **Transport** is gRPC, not raw TCP + custom framing (documented difference vs some spec sketches) | README |

### 5. Deployment and ownership

| Gap | Source |
|-----|--------|
| **Optimistic epic scenario** (each upstream maintains its wrapper + CI) vs **current** “all wrappers live here” | Epic deployment |

### 6. Selectable capabilities, combinations, and user-chosen tests

**Goal (vision):** Wrappers expose capabilities (cipher suites, signature algorithms, groups, …); the framework tests **non–mutually-exclusive** combinations where sensible; users **pick** which tests run and can **add** new ones easily.

| Topic | Current state | Gap |
|--------|----------------|-----|
| **Advertised capabilities** | `GetMetadata` already lists `cipher_suites` and `groups` (same `Capability` model as TLS versions). | Driver **only** uses `supported_versions` (+ roles) for skip logic; cipher/group lists are unused for filtering. |
| **`TlsConfig`** | `cipher_suite` exists in `.proto`. | Wrappers **do not** read it when building CLI commands; ESTABLISH is driven mainly by TLS version, host, port. |
| **Signature algorithms** | — | Not in metadata or `TlsConfig`; would need schema + wrapper support. |
| **Combinatorics** | Fixed scenarios in code. | No generator for compatible cipher × group × version tuples; no explicit **compatibility rules** (avoid blind Cartesian product — TLS has many invalid combos). |
| **User selection** | `--scenario` + Docker matrix of **library pairs**. | No plan file / tags for “which capability axes to run”; scenarios are not **data-driven** yet. |

**Direction:** (1) End-to-end for **one axis** first — wire `cipher_suite` (and add `group` to `TlsConfig` if needed), map to OpenSSL/GnuTLS/NSS CLIs, extend driver skip checks like for TLS 1.2/1.3. (2) **Parametric scenarios** + declarative **test registry** (see near/medium term below). (3) Add **compatibility rules** or curated grids before scaling combinations. (4) Extend proto + metadata for **sig algs** when required.

### 7. Generic driver vs “only three libraries” *(architecture clarification)*

The **driver is already generic at the protocol layer:** it only depends on **gRPC + Protobuf** (`TlsInteropWrapper`); it does **not** import OpenSSL, GnuTLS, or NSS. Any process that implements the same service can be a peer.

**Where the stack is still specific to three backends:**

| Layer | What is hard-coded |
|--------|-------------------|
| `deploy/wrapper_launch.sh` | Delegates to **`wrapper_entry.py`** + **`wrappers.json`** (no per-name `case` in shell). |
| `scripts/run.sh` | Matrix pairs and valid names from **`deploy/wrappers.json`** via **`matrix_config.py`**. |
| `deploy/matrix.yaml` + image | One image recipe with Fedora packages for those three stacks. |
| Docs / CI | Examples assume the 3×3 matrix. |

**Direction:** Treat wrappers as **plug-ins**: e.g. **registry** (YAML/JSON) mapping `WRAPPER` name → launch command or module; **generate matrix pairs** from that list or from a plan file; document **“how to implement a wrapper”** (contract only, no library names). Optionally run server/client endpoints from **pure config** (`TLS_SERVER_GRPC` / `TLS_CLIENT_GRPC`) so the driver does not need to know wrapper *names* at all — only addresses. Heavier images vs **per-wrapper sidecars** / external processes remain a deployment choice.

---

## What to do next (recommended order)

Work is ordered so early items unblock documentation and ergonomics; later items align with architecture/epic without requiring everything at once.

### Near term (high value, smaller scope)

1. **Command logging in wrappers** — ✅ *Done (baseline):* `wrapper_common.format_executed_command()`; on **ESTABLISH**, wrappers set `OperationResponse.logs` to `cwd=…` plus `shlex`-quoted argv (NSS server: socat + selfserv on two lines). The driver already surfaces `resp.logs` on failures in verbose mode (`message` or `logs` in `_check_response`). *Optional later:* log on more op types or behind a dedicated env flag only.
2. **Upstream / CI integration guide** — Short doc (e.g. `docs/INTEGRATION.md`): prerequisites, image or compose usage, env vars, how to run a **subset** of the matrix, how to add a **new wrapper** stub. Ties directly to epic success criteria.
3. **Extract scenario registry** — ✅ `src/driver/scenarios.py`: `SCENARIO_REGISTRY` (id, TLS requirement, driver method name), `SCENARIO_TLS_REQUIREMENT`, `ORDERED_SCENARIO_IDS`, `ARGPARSE_SCENARIO_CHOICES`. `driver.py` prepends repo root on `sys.path` then appends `src/driver` for `import scenarios`. Docker: both files copied to `/app/`.
4. **Wrapper registry + configurable matrix** — ✅ `deploy/wrappers.json` (`wrappers`, `launch`, `matrix_pairs`); `scripts/matrix_config.py` (`pairs` / `valid`); `deploy/wrapper_entry.py` + `wrapper_launch.sh`; Dockerfile copies JSON + entry; **`matrix_pairs` omitted** ⇒ Cartesian product of `wrappers`. Env **`WRAPPERS_CONFIG`** overrides JSON path for `run.sh`.

### Medium term (architecture + epic)

5. **Wire capability axes end-to-end** — Use `TlsConfig.cipher_suite` in all wrappers; add **group** (and later **sig algs**) to `.proto` + `GetMetadata` where needed; extend driver **skip** logic to require NEGOTIATE (or equivalent) on both sides for chosen cipher/group.
6. **Parametric runs + compatibility rules** — Same scenario code, parameters from data; curated or rule-based grids for **valid** combinations (not full Cartesian product unless bounded).
7. **External test scripts (optional HTTP or Python API)** — Let a script drive the same operations the driver uses, or add a thin HTTP **RequestSender** as in the draft spec, so tests are not only embedded in the driver.
8. **Declarative test plans** — File-based list of scenarios, tags, and/or capability tuples (YAML/TOML) read by `run.sh` or the driver, as a bridge before full fmf/tmt.
9. **tmt + fmf proof of concept** — Minimal tree: `plans/`, `tests/`, `tmt run` in CI (Fedora container), even if it initially only wraps existing `run.sh` or the driver. Validates the upstream architecture baseline (see libssh-style POC).

### Longer term

10. **Capability / interface specification** — Versioned document (or generated from schema) describing operations, parameters, and capability IDs; keep `.proto` in sync.
11. **Subject metadata** — Optional fmf/yaml next to a wrapper or consumed by a future runner describing build deps and supported interface version.
12. **More scenarios and protocol depth** — e.g. KEY_UPDATE, stricter cipher/SNI cases; keep **first-subproject**-style tests in mind where automation is insufficient.
13. **Split repository layout** — When mature: **tests + plans** (and possibly runner packaging) vs **reference wrappers**, to match the “central tests repository” epic wording.

---

## How to use this file

- **Done vs next:** The baseline table marks what already matches the epic’s *direction*; the gap analysis is the single checklist derived from **both** comparison documents, **team meeting notes** (§6), and the **generic-driver** note (§7).
- **README** stays the operational entrypoint; this file tracks **product/architecture** follow-up.

When a line item is completed, update the baseline or remove/shrink the corresponding gap to avoid drift.

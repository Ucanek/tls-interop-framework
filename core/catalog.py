"""CLI option catalog, validation, and matrix expansion."""

from __future__ import annotations

import importlib
import json
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal, Sequence

TlsMode = Literal["1.2", "1.3"]

# Static CLI options (choices for crypto dims come from capabilities union).
STATIC_CLI_OPTIONS: tuple[dict[str, Any], ...] = (
    {"id": "cipher_suite", "description": "Cipher suite catalog id (per-backend mapping in capabilities.json)."},
    {"id": "tls_version", "description": "TLS protocol version for the endpoint (TlsConfig.version)."},
    {"id": "tls_port", "description": "TLS data-plane port override (default scenario value is 5555)."},
    {"id": "supported_groups", "description": "Advertised/allowed key exchange groups (supported_groups extension)."},
    {"id": "signature_schemes", "description": "Advertised TLS signature algorithms."},
    {"id": "alpn", "description": "ALPN protocol identifiers offered by the endpoint (e.g. h2, http/1.1)."},
    {"id": "test_features", "description": (
        "Credentials for special ciphers (psk, anonymous). "
        "cipher_suite ALL includes PSK/anon suites; without enabling a feature here, "
        "those cells are pre-SKIP (Feature disabled). "
        "Set test_features: psk,anonymous (or YAML map with true values) to run them.")})

NON_TLS_OPTION_IDS: frozenset[str] = frozenset({"server_wrapper", "client_wrapper"})
# Applied once per run (suite/CLI), not Cartesian-expanded with cipher_suite.
NON_MATRIX_OPTION_IDS: frozenset[str] = frozenset({"test_features"})

CAPABILITY_DIMENSIONS: frozenset[str] = frozenset({"cipher_suite", "supported_groups", "signature_schemes", "tls_version", "alpn"})
TLS13_ORTHOGONAL_DIMS: frozenset[str] = frozenset({"supported_groups", "signature_schemes"})

# Matrix default when ``cipher_suite`` is omitted but ``tls_version`` pins TLS 1.2 or 1.3.
DEFAULT_CIPHER_BY_TLS_MODE: dict[TlsMode, str] = {"1.3": "aes-128-gcm", "1.2": "ecdhe-rsa-aes-128-gcm-sha256"}


def repository_root() -> Path:
    cur = Path(__file__).resolve().parent
    while True:
        if (cur / "interop_proto" / "interop_pb2.py").is_file():
            return cur
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
    p = Path(__file__).resolve()
    for candidate in (p.parents[1], p.parents[2] if len(p.parents) > 2 else None):
        if candidate is None:
            continue
        if (candidate / "interop_proto" / "interop_pb2.py").is_file():
            return candidate
    raise FileNotFoundError("Could not locate repository root containing interop_proto directory")


@dataclass(frozen=True)
class TranslationResult:
    argv: tuple[str, ...]
    unsupported: tuple[str, ...]


def load_local_capabilities(wrapper_file: str) -> dict[str, Any]:
    path = Path(wrapper_file).resolve().parent / "capabilities.json"
    if not path.is_file():
        raise FileNotFoundError(f"capabilities.json not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"capabilities.json must be a JSON object: {path}")
    return data


def tls_argv_for_config(config: Any, backend: str, capabilities: dict[str, Any], *, role: Any | None = None) -> TranslationResult:
    name = (backend or "").strip().lower()
    mod = importlib.import_module(f"wrappers.{name}.wrapper")
    fn = getattr(mod, "tls_argv_for_config", None)
    if fn is None:
        return TranslationResult((), (f"(backend {name!r} has no tls_argv_for_config)",))
    return fn(config, role=role, capabilities=capabilities)


def build_cli_options_catalog(repo: Path | None = None) -> list[dict[str, Any]]:
    root = repo or repository_root()
    union = aggregate_union(root, discover_wrapper_ids(root))
    out: list[dict[str, Any]] = []
    for template in STATIC_CLI_OPTIONS:
        item = dict(template)
        oid = item["id"]
        if oid in union:
            item["choices"] = list(union[oid])
        out.append(item)
    return out


def discover_wrapper_ids(repo: Path) -> tuple[str, ...]:
    plugin_dir = repo / "wrappers"
    if not plugin_dir.is_dir():
        return ()
    found: list[str] = []
    for path in sorted(plugin_dir.iterdir()):
        if not path.is_dir():
            continue
        if (path / "wrapper.py").is_file() and (path / "capabilities.json").is_file():
            found.append(path.name)
    return tuple(found)


RUNTIME_DEFAULTS: dict[str, Any] = {
    "grpc_addr": None, "tls_host": "127.0.0.1", "tls_port": 15551,
    "unsupported_tls_fields": (), "local_cli": ()}


def _capability_token_supported(block: dict[str, Any], token: str) -> bool:
    if block.get("supported") is False:
        return False
    key = norm_catalog_token(token)
    entry = block.get(key) if key in block else block.get(token)
    if isinstance(entry, dict) and entry.get("supported") is False:
        return False
    return key in block or token in block


@dataclass(frozen=True)
class BackendCapabilities:
    raw: dict[str, Any]

    def runtime(self) -> dict[str, Any]:
        raw = self.raw.get("runtime")
        if not isinstance(raw, dict):
            raw = {}
        out = dict(RUNTIME_DEFAULTS)
        for key in RUNTIME_DEFAULTS:
            if key in raw and raw[key] is not None:
                out[key] = raw[key]
        return out

    def cipher_maps(self) -> tuple[dict[str, str], dict[str, str]]:
        t13 = self.raw.get("tls13") if isinstance(self.raw.get("tls13"), dict) else {}
        t12 = self.raw.get("tls12") if isinstance(self.raw.get("tls12"), dict) else {}
        m13 = dict(t13.get("cipher_suite") or {}) if isinstance(t13.get("cipher_suite"), dict) else {}
        m12 = dict(t12.get("cipher_suite") or {}) if isinstance(t12.get("cipher_suite"), dict) else {}
        return ({str(k): str(v) for k, v in m13.items() if v},
                {str(k): str(v) for k, v in m12.items() if v})

    def cipher_ids(self, mode: TlsMode | None = None) -> list[str]:
        m13, m12 = self.cipher_maps()
        if mode is None:
            return sorted(set(m13) | set(m12))
        mp = m13 if mode == "1.3" else m12
        return sorted(str(k) for k in mp.keys() if k)

    def cipher_modes(self, catalog_id: str) -> set[TlsMode]:
        m13, m12 = self.cipher_maps()
        key = norm_catalog_token(catalog_id)
        modes: set[TlsMode] = set()
        if key in m13 or catalog_id in m13:
            modes.add("1.3")
        if key in m12 or catalog_id in m12:
            modes.add("1.2")
        return modes

    def supports_cipher(self, catalog_id: str, mode: TlsMode) -> bool:
        m13, m12 = self.cipher_maps()
        key = norm_catalog_token(catalog_id)
        mp = m13 if mode == "1.3" else m12
        return key in mp or catalog_id in mp

    def supports_token(self, dimension: str, token: str, *, tls_mode: TlsMode | None = None) -> bool:
        if dimension == "cipher_suite":
            if tls_mode is None:
                return bool(self.cipher_modes(token))
            return self.supports_cipher(token, tls_mode)
        block = self.raw.get(dimension)
        if not isinstance(block, dict):
            return False
        return _capability_token_supported(block, token)

    def dimension_keys(self, dimension: str, *, tls_mode: TlsMode | None = None) -> list[str]:
        if dimension == "cipher_suite":
            return self.cipher_ids(tls_mode)
        block = self.raw.get(dimension)
        if not isinstance(block, dict):
            return []
        if block.get("supported") is False:
            return []
        meta = frozenset({"supported", "wired", "description"})
        out: list[str] = []
        for key, entry in block.items():
            if key in meta:
                continue
            if isinstance(entry, dict) and entry.get("supported") is False:
                continue
            out.append(str(key))
        return sorted(out)

    def feature_block(self) -> dict[str, Any]:
        block = self.raw.get("test_features")
        return block if isinstance(block, dict) else {}

    def feature_entry(self, name: str) -> dict[str, Any]:
        entry = self.feature_block().get(name)
        return entry if isinstance(entry, dict) else {}

    def feature_ids(self) -> frozenset[str]:
        out: set[str] = set()
        for key, entry in self.feature_block().items():
            if isinstance(entry, dict) and entry.get("supported", False):
                out.add(str(key).strip().lower())
        return frozenset(x for x in out if x)

    def psk_secret_hex(self, cipher_id: str) -> str | None:
        entry = self.feature_entry("psk")
        bits = psk_key_bits_for_cipher(cipher_id)
        field = "secret_hex_256" if bits >= 256 else "secret_hex_128"
        secret_hex = str(entry.get(field) or entry.get("secret_hex") or "").strip()
        if not secret_hex:
            return None
        if len(secret_hex) != bits // 4:
            return None
        return secret_hex

    def psk_material(self, cipher_id: str) -> tuple[str, str] | None:
        entry = self.feature_entry("psk")
        identity = str(entry.get("identity") or "interop").strip()
        secret_hex = self.psk_secret_hex(cipher_id)
        if not secret_hex:
            return None
        return identity, secret_hex


@cache
def load_backend_capabilities(name: str) -> BackendCapabilities:
    key = (name or "").strip().lower()
    path = repository_root() / "wrappers" / key / "capabilities.json"
    if not path.is_file():
        raise FileNotFoundError(f"capabilities.json not found for backend {key!r}: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"capabilities.json must be a JSON object: {path}")
    return BackendCapabilities(data)


def load_wrapper_module(backend_name: str) -> Any:
    name = (backend_name or "").strip().lower()
    return importlib.import_module(f"wrappers.{name}.wrapper")


def call_wrapper_hook(backend_name: str, hook: str, /, *args: Any, **kwargs: Any) -> Any:
    mod = load_wrapper_module(backend_name)
    fn = getattr(mod, hook, None)
    if fn is None:
        return None
    return fn(*args, **kwargs)


def local_cli_requirements(backend_name: str, capabilities: dict[str, Any]) -> tuple[str, ...]:
    req = call_wrapper_hook(backend_name, "local_cli_requirements")
    if req is not None:
        return tuple(str(x) for x in req)
    cli = BackendCapabilities(capabilities).runtime().get("local_cli") or ()
    return tuple(str(x) for x in cli)


def resolve_wrapper_cli_tool(backend_name: str, exe: str) -> str | None:
    resolved = call_wrapper_hook(backend_name, "resolve_cli_tool", exe)
    if resolved:
        return str(resolved)
    import shutil

    return shutil.which(exe)


def wrapper_orchestration_env(backend_name: str, active_backends: frozenset[str] | set[str]) -> dict[str, str]:
    out = call_wrapper_hook(backend_name, "orchestration_env", active_backends)
    return dict(out) if isinstance(out, dict) else {}


def wrapper_local_env(backend_name: str, repo: Path, active_backends: frozenset[str] | set[str],
                      *, slot_id: int | None = None) -> dict[str, str]:
    out = call_wrapper_hook(
        backend_name, "local_wrapper_env", repo, backend_name, active_backends, slot_id=slot_id)
    return dict(out) if isinstance(out, dict) else {}


def merged_orchestration_env(active_backends: Iterable[str]) -> dict[str, str]:
    active = frozenset((b or "").strip().lower() for b in active_backends if (b or "").strip())
    merged: dict[str, str] = {}
    for backend in sorted(active):
        merged.update(wrapper_orchestration_env(backend, active))
    return merged


def session_wrapper_env(backend_name: str, repo: Path, active_backends: Iterable[str],
                        *, slot_id: int | None = None) -> dict[str, str]:
    active = frozenset((b or "").strip().lower() for b in active_backends if (b or "").strip())
    merged = dict(merged_orchestration_env(active))
    merged.update(wrapper_local_env(backend_name, repo, active, slot_id=slot_id))
    return merged


def backend_grpc_addr(backend_name: str, repo: Path | None = None, *, port_override: int | None = None) -> str:
    rt = load_backend_capabilities(backend_name).runtime()
    addr = rt.get("grpc_addr")
    if not isinstance(addr, str) or not addr.strip():
        raise ValueError(f"capabilities.runtime.grpc_addr missing for backend {backend_name!r}")
    addr = addr.strip()
    if port_override:
        host, _, _ = addr.rpartition(":")
        return f"{host or '127.0.0.1'}:{int(port_override)}"
    return addr


def grpc_port_overrides_from_args(args: Any) -> dict[str, int]:
    out: dict[str, int] = {}

    def _maybe_add(role: str, port: int) -> None:
        if not port:
            return
        wid = (getattr(args, role, None) or "").strip().lower()
        if not wid or wid == "all" or "," in wid or "\\" in wid:
            return
        out[wid] = port

    _maybe_add("server", int(getattr(args, "server_grpc_port", 0) or 0))
    _maybe_add("client", int(getattr(args, "client_grpc_port", 0) or 0))
    return out


def backend_tls_endpoint(backend_name: str, repo: Path | None = None) -> tuple[str, int]:
    rt = load_backend_capabilities(backend_name).runtime()
    host = str(rt.get("tls_host") or "127.0.0.1")
    port = int(rt.get("tls_port") or 15551)
    return host, port


def check_local_cli_tools(backends: Iterable[str], repo: Path | None = None) -> list[str]:
    missing: list[str] = []
    for backend in backends:
        key = (backend or "").strip().lower()
        caps = load_backend_capabilities(key)
        for exe in local_cli_requirements(key, caps.raw):
            if resolve_wrapper_cli_tool(key, exe) is None:
                missing.append(f"{key}: {exe} not found")
    return missing


def union_cipher_suite_ids_for_wrappers(caps_by_wrapper: dict[str, dict[str, Any]], wrapper_ids: Sequence[str], *, mode: TlsMode | None = None) -> list[str]:
    keys: set[str] = set()
    for wid in wrapper_ids:
        bc = BackendCapabilities(caps_by_wrapper.get(wid, {}))
        keys.update(bc.cipher_ids(mode))
    return sorted(keys)


def default_cipher_for_tls_mode(mode: TlsMode, *, allowed: set[str] | frozenset[str]) -> str:
    preferred = DEFAULT_CIPHER_BY_TLS_MODE.get(mode, "")
    if preferred and preferred in allowed:
        return preferred
    return sorted(allowed)[0] if allowed else ""


def tls_mode_filter_from_args(args: Any) -> TlsMode | None:
    raw = str(getattr(args, "tls_version", "") or "").strip()
    if not raw:
        return None
    if ":" in raw:
        left, right = parse_asymmetric(raw)
        if left and right and tls_mode_from_version(left) == tls_mode_from_version(right):
            return tls_mode_from_version(left)
        return None
    return tls_mode_from_version(raw)


def capability_dimension_name(option_id: str) -> str:
    if (option_id or "").strip() == "alpn":
        return "alpn_protocols"
    return (option_id or "").strip()


def aggregate_union(repo: Path, wrapper_ids: tuple[str, ...] | frozenset[str]) -> dict[str, list[str]]:
    cipher: set[str] = set()
    groups: set[str] = set()
    sigs: set[str] = set()
    alpn: set[str] = set()
    test_feats: set[str] = set()
    for wid in wrapper_ids:
        bc = load_backend_capabilities(wid)
        cipher.update(bc.cipher_ids())
        groups.update(bc.dimension_keys("supported_groups"))
        sigs.update(bc.dimension_keys("signature_schemes"))
        alpn.update(bc.dimension_keys("alpn_protocols"))
        test_feats.update(bc.feature_ids())
    return {
        "cipher_suite": sorted(cipher), "supported_groups": sorted(groups),
        "signature_schemes": sorted(sigs), "alpn": sorted(alpn),
        "test_features": sorted(test_feats), "tls_version": ["1.2", "1.3"]}


def parse_asymmetric(val: str | None) -> tuple[str, str]:
    v = (val or "").strip()
    if ":" in v:
        left, right = v.split(":", 1)
        return left.strip(), right.strip()
    return v, v


def asymmetric_role_part(val: str | None, *, server: bool) -> str:
    left, right = parse_asymmetric(val)
    return left if server else right


def split_csv_tokens(part: str) -> list[str]:
    return [p.strip() for p in (part or "").split(",") if p.strip()]


def norm_token(s: str) -> str:
    return (s or "").strip().lower().replace("-", "").replace("_", "")


def norm_catalog_token(raw: str) -> str:
    return (raw or "").strip().lower().replace(" ", "")


def tls_mode_from_version(version: str | None) -> TlsMode:
    if not (version or "").strip():
        return "1.3"
    folded = norm_token((version or "").replace(".", ""))
    if "13" in folded:
        return "1.3"
    if "12" in folded:
        return "1.2"
    return "1.3"


def option_choice_tokens(item: dict[str, Any]) -> list[str]:
    ch = item.get("choices") or []
    return [str(c).strip() for c in ch if str(c).strip()]


def _coerce_cipher_tls13_only(cipher_side: str, ver_side: str, caps: dict[str, Any]) -> str | None:
    if tls_mode_from_version(ver_side) != "1.2":
        return None
    cid = (cipher_side or "").strip()
    if not cid:
        return None
    if BackendCapabilities(caps).cipher_modes(cid) == {"1.3"}:
        return "1.3"
    return None


def coerce_tls_version_for_cipher_capabilities(args: Any, repo: Path | None = None) -> None:
    cs_raw = getattr(args, "cipher_suite", None)
    tv_raw = getattr(args, "tls_version", None)
    if cs_raw in (None, "", 0) or tv_raw in (None, "", 0):
        return
    cs_s = str(cs_raw).strip()
    tv_s = str(tv_raw).strip()
    if not cs_s or not tv_s:
        return

    server = (getattr(args, "server", None) or "").strip().lower()
    client = (getattr(args, "client", None) or "").strip().lower()
    try:
        srv_caps = load_backend_capabilities(server).raw if server else {}
        cli_caps = load_backend_capabilities(client).raw if client else {}
    except (FileNotFoundError, ValueError):
        return

    def _pair(cipher_side: str, ver_side: str, caps: dict[str, Any]) -> str | None:
        return _coerce_cipher_tls13_only(cipher_side, ver_side, caps)

    warn = (
        "[catalog] TLS 1.3-only cipher with --tls-version 1.2: "
        "adjusting protocol version to 1.3 to avoid handshake mismatch.")

    if ":" in cs_s and ":" in tv_s:
        lc, rc = cs_s.split(":", 1)
        lv, rv = tv_s.split(":", 1)
        nl = _pair(lc.strip(), lv.strip(), srv_caps)
        nr = _pair(rc.strip(), rv.strip(), cli_caps)
        if nl or nr:
            print(warn, file=sys.stderr)
            setattr(args, "tls_version", f"{nl or lv.strip()}:{nr or rv.strip()}")
        return
    if ":" in tv_s:
        lv, rv = tv_s.split(":", 1)
        nl = _pair(cs_s, lv.strip(), srv_caps)
        nr = _pair(cs_s, rv.strip(), cli_caps)
        if nl or nr:
            print(warn, file=sys.stderr)
            setattr(args, "tls_version", f"{nl or lv.strip()}:{nr or rv.strip()}")
        return
    if ":" in cs_s:
        lc, rc = cs_s.split(":", 1)
        n1 = _pair(lc.strip(), tv_s, srv_caps)
        n2 = _pair(rc.strip(), tv_s, cli_caps)
        if n1 or n2:
            print(warn, file=sys.stderr)
            setattr(args, "tls_version", f"{n1 or tv_s}:{n2 or tv_s}")
        return
    caps = srv_caps if server and not client else cli_caps
    if server and client:
        modes = BackendCapabilities(srv_caps).cipher_modes(cs_s) | BackendCapabilities(cli_caps).cipher_modes(cs_s)
        if "1.3" in modes and "1.2" not in modes:
            caps = srv_caps
        else:
            caps = srv_caps
    n = _pair(cs_s, tv_s, caps)
    if n:
        print(warn, file=sys.stderr)
        setattr(args, "tls_version", n)


def expand_dimension(value: str, choices: Sequence[str]) -> list[str]:
    base = [str(c).strip() for c in choices if c and str(c).strip()]
    v = (value or "").strip()

    if not base:
        return [v] if v else [""]

    if not v:
        return [""]

    if re.match(r"(?is)^ALL\s*$", v):
        return list(base)

    sub = re.match(r"(?is)^ALL\s*[\\-]\s*(.+)$", v)
    if sub:
        excl = {x.strip() for x in sub.group(1).split(",") if x.strip()}
        out = [x for x in base if x not in excl]
        if not out:
            raise ValueError(f"ALL minus exclusions leaves empty set: {value!r}")
        return out

    if ":" in v:
        return [v]

    parts = [x.strip() for x in v.split(",") if x.strip()]
    if not parts:
        raise ValueError(f"Empty dimension value: {value!r}")
    bad = [p for p in parts if p not in base]
    if bad:
        raise ValueError(f"Unknown value(s) {bad!r}; known: {', '.join(sorted(set(base)))}")
    return parts


def expand_alpn_matrix_axis(value: str, *, wrapper_ids: Sequence[str], caps_by_wrapper: dict[str, dict[str, Any]],
                            catalog_choices: Sequence[str]) -> list[str]:
    v = (value or "").strip()
    if not v:
        return [""]
    if ":" in v:
        return expand_capability_dimension(
            v, "alpn_protocols", wrapper_ids=wrapper_ids, caps_by_wrapper=caps_by_wrapper,
            catalog_choices=catalog_choices)
    tokens = expand_capability_dimension(
        v, "alpn_protocols", wrapper_ids=wrapper_ids, caps_by_wrapper=caps_by_wrapper,
        catalog_choices=catalog_choices)
    if not tokens or tokens == [""]:
        return [""]
    return [f"{srv}:{cli}" for srv in tokens for cli in tokens]


def expand_capability_dimension(value: str, dimension: str, *, wrapper_ids: Sequence[str],
                                caps_by_wrapper: dict[str, dict[str, Any]], catalog_choices: Sequence[str],
                                tls_mode: TlsMode | None = None) -> list[str]:
    v = (value or "").strip()
    catalog_tokens = [str(c).strip() for c in catalog_choices if c and str(c).strip()]
    cipher_mode = tls_mode if dimension == "cipher_suite" else None

    if re.match(r"(?is)^ALL\s*$", v):
        keys: set[str] = set()
        if dimension == "cipher_suite" and cipher_mode is not None:
            keys.update(union_cipher_suite_ids_for_wrappers(caps_by_wrapper, wrapper_ids, mode=cipher_mode))
        else:
            for wid in wrapper_ids:
                keys.update(BackendCapabilities(caps_by_wrapper.get(wid, {})).dimension_keys(dimension, tls_mode=cipher_mode))
        if keys:
            return sorted(keys)
        return list(catalog_tokens)

    sub = re.match(r"(?is)^ALL\s*[\\-]\s*(.+)$", v)
    if sub:
        excl = {x.strip() for x in sub.group(1).split(",") if x.strip()}
        keys: set[str] = set()
        if dimension == "cipher_suite" and cipher_mode is not None:
            keys.update(union_cipher_suite_ids_for_wrappers(caps_by_wrapper, wrapper_ids, mode=cipher_mode))
        else:
            for wid in wrapper_ids:
                keys.update(BackendCapabilities(caps_by_wrapper.get(wid, {})).dimension_keys(dimension, tls_mode=cipher_mode))
        if not keys:
            keys = set(catalog_tokens)
        out = sorted(k for k in keys if k not in excl)
        if not out:
            raise ValueError(f"ALL minus exclusions leaves empty set: {value!r}")
        return out

    if ":" in v:
        return [v]

    expanded = expand_dimension(v, catalog_tokens)
    if dimension != "cipher_suite" or cipher_mode is None:
        return expanded
    allowed = set(union_cipher_suite_ids_for_wrappers(caps_by_wrapper, wrapper_ids, mode=cipher_mode))
    filtered = [x for x in expanded if x in allowed]
    # Unset cipher_suite with explicit tls_version → one default cipher for that protocol version.
    if not filtered and not v.strip():
        default = default_cipher_for_tls_mode(cipher_mode, allowed=allowed)
        return [default] if default else [""]
    # Explicit cipher requests stay in the matrix (SKIP at run time) instead of 0 tests.
    if not filtered and v.strip() and not re.match(r"(?is)^ALL", v.strip()):
        return expanded if expanded else [v.strip()]
    return filtered


def _cell_cipher_id(cell: dict[str, str], *, server: bool) -> str:
    cs = (cell.get("cipher_suite") or "").strip()
    if not cs:
        return ""
    if ":" in cs:
        left, right = cs.split(":", 1)
        return (left if server else right).strip()
    return cs


def effective_cell_tls_mode(cell: dict[str, str], srv_caps: dict[str, Any], cli_caps: dict[str, Any]) -> TlsMode:
    tv = (cell.get("tls_version") or "").strip()
    if tv and ":" not in tv:
        return tls_mode_from_version(tv)
    if tv and ":" in tv:
        left, _ = parse_asymmetric(tv)
        if left:
            return tls_mode_from_version(left)

    srv_c = _cell_cipher_id(cell, server=True)
    cli_c = _cell_cipher_id(cell, server=False)
    modes: set[TlsMode] = set()
    for cid, caps in ((srv_c, srv_caps), (cli_c, cli_caps)):
        if cid:
            modes |= BackendCapabilities(caps).cipher_modes(cid)
    if modes == {"1.2"}:
        return "1.2"
    if modes == {"1.3"} or not modes:
        return "1.3"
    return "1.3"


def _implicit_tls_version_for_side(cell: dict[str, str], *, server: bool, caps: dict[str, Any]) -> str:
    cid = _cell_cipher_id(cell, server=server)
    if not cid:
        return ""
    modes = BackendCapabilities(caps).cipher_modes(cid)
    if modes == {"1.3"}:
        return "1.3"
    if modes == {"1.2"}:
        return "1.2"
    return ""


def normalize_cell_tls_micro_params(cell: dict[str, str], args_template: Any, repo: Path) -> dict[str, str]:
    out = dict(cell)
    port = int(getattr(args_template, "tls_port", 0) or 0)
    if port:
        out["tls_port"] = str(port)
    server = (cell.get("server") or "").strip().lower()
    client = (cell.get("client") or "").strip().lower()
    try:
        srv_caps = load_backend_capabilities(server).raw
        cli_caps = load_backend_capabilities(client).raw
    except (FileNotFoundError, ValueError):
        return out

    if not (out.get("tls_version") or "").strip():
        sv = _implicit_tls_version_for_side(out, server=True, caps=srv_caps)
        cv = _implicit_tls_version_for_side(out, server=False, caps=cli_caps)
        if sv or cv:
            if sv and cv and sv != cv:
                out["tls_version"] = f"{sv}:{cv}"
            else:
                out["tls_version"] = sv or cv

    if effective_cell_tls_mode(out, srv_caps, cli_caps) != "1.2":
        out["test_features"] = str(
            getattr(args_template, "test_features", "") or ""
        ).strip()
    else:
        for dim in TLS13_ORTHOGONAL_DIMS:
            user_raw = str(getattr(args_template, dim, "") or "").strip()
            if not user_raw:
                out[dim] = ""
        out["test_features"] = str(
            getattr(args_template, "test_features", "") or ""
        ).strip()

    # Explicit TLS 1.2 + TLS 1.3-only cipher → bump version (avoids handshake mismatch).
    coerce_ns = SimpleNamespace(server=server, client=client, cipher_suite=out.get("cipher_suite", ""), tls_version=out.get("tls_version", ""))
    coerce_tls_version_for_cipher_capabilities(coerce_ns, repo)
    bumped = str(getattr(coerce_ns, "tls_version", "") or "").strip()
    if bumped:
        out["tls_version"] = bumped
    return out


def _check_cipher_side(cell: dict[str, str], *, server: bool, wrapper: str, caps: dict[str, Any], mode: TlsMode) -> str | None:
    cid = _cell_cipher_id(cell, server=server)
    if not cid:
        return None
    bc = BackendCapabilities(caps)
    if bc.supports_cipher(cid, mode):
        return None
    modes = bc.cipher_modes(cid)
    if not modes:
        return f"{wrapper} lacks cipher_suite={cid!r}"
    return (f"{wrapper} lacks cipher_suite={cid!r} for TLS {mode} "
            f"(supported modes: {', '.join(sorted(modes))})")


def _check_list_dim(cell: dict[str, str], dim: str, *, server: bool, wrapper: str,
                    caps: dict[str, Any], mode: TlsMode) -> str | None:
    if mode == "1.2" and dim in TLS13_ORTHOGONAL_DIMS:
        raw = (cell.get(dim) or "").strip()
        if not raw:
            return None
    tokens = _split_cell_list_tokens(cell, dim, server=server)
    if not tokens:
        return None
    cap_dim = capability_dimension_name(dim)
    for tok in tokens:
        if not BackendCapabilities(caps).supports_token(cap_dim, tok, tls_mode=mode):
            return f"{wrapper} lacks {dim}={tok!r}"
    return None


@dataclass(frozen=True)
class Tls12CipherMetadata:
    kx: Literal["ecdhe", "dhe", "static-rsa", "unknown"]
    au: Literal["rsa", "ecdsa", "dsa", "unknown"]


def _split_cell_list_tokens(cell: dict[str, str], field: str, *, server: bool) -> list[str]:
    return split_csv_tokens(asymmetric_role_part(cell.get(field), server=server))


def tls12_cipher_metadata_from_name(cipher_name: str) -> Tls12CipherMetadata:
    raw = (cipher_name or "").strip().lower()
    tok = raw.replace("_", "-").replace(" ", "")
    if not tok or tok.startswith("tls-"):
        return Tls12CipherMetadata(kx="unknown", au="unknown")
    if "ecdhe" in tok:
        kx: Literal["ecdhe", "dhe", "static-rsa", "unknown"] = "ecdhe"
    elif re.search(r"(^|-)dhe(-|$)", tok):
        kx = "dhe"
    elif "rsa" in tok or tok.startswith("aes"):
        kx = "static-rsa"
    else:
        kx = "unknown"

    if re.search(r"(^|-)dss(-|$)", tok):
        au: Literal["rsa", "ecdsa", "dsa", "unknown"] = "dsa"
    elif "ecdsa" in tok:
        au = "ecdsa"
    elif "rsa" in tok or tok.startswith("aes"):
        au = "rsa"
    else:
        au = "unknown"
    return Tls12CipherMetadata(kx=kx, au=au)


def cipher_catalog_id_requires_psk(cipher_id: str) -> bool:
    c = norm_catalog_token(cipher_id)
    return bool(re.search(r"(^|-)psk(-|$)", c))


def cipher_catalog_id_requires_anon(cipher_id: str) -> bool:
    c = norm_catalog_token(cipher_id)
    return "anon" in c.split("-") or c.startswith("adh-")


def cipher_required_test_feature(cipher_id: str) -> str | None:
    if cipher_catalog_id_requires_psk(cipher_id):
        return "psk"
    if cipher_catalog_id_requires_anon(cipher_id):
        return "anonymous"
    return None


def cipher_catalog_id_requires_identity_pem(cipher_id: str) -> bool:
    c = norm_catalog_token(cipher_id)
    if not c:
        return False
    if cipher_catalog_id_requires_anon(c):
        return False
    if cipher_catalog_id_requires_psk(c):
        return bool(re.search(r"(^|-)(rsa|dhe|ecdhe)-psk", c))
    from core.identity import cipher_catalog_id_uses_dsa_auth

    if cipher_catalog_id_uses_dsa_auth(c):
        return True
    if "ecdsa" in c or "ed25519" in c or "ed448" in c:
        return True
    if re.search(r"(^|-)rsa", c):
        return True
    return False


def _required_server_identity_prefix(cell: dict[str, str]) -> str | None:
    from core.identity import get_cert_prefix_for_cipher_suite, get_cert_prefix_for_schemes

    schemes = _split_cell_list_tokens(cell, "signature_schemes", server=True)
    if schemes:
        return get_cert_prefix_for_schemes(schemes)
    cipher = _cell_cipher_id(cell, server=True)
    if not cipher or not cipher_catalog_id_requires_identity_pem(cipher):
        return None
    return get_cert_prefix_for_cipher_suite(cipher)


def _cell_identity_pem_skip_reason(cell: dict[str, str], repo: Path) -> str | None:
    from core.identity import identity_pem_present

    prefix = _required_server_identity_prefix(cell)
    if not prefix:
        return None
    if identity_pem_present(prefix, repo=repo):
        return None
    return f"Missing identity PEM: certs/{prefix}.crt and certs/{prefix}.key"


def parse_test_features_enabled(raw: str) -> frozenset[str]:
    if not (raw or "").strip():
        return frozenset()
    return frozenset(p.strip().lower() for p in str(raw).split(",") if p.strip())


def psk_key_bits_for_cipher(cipher_id: str) -> int:
    c = norm_catalog_token(cipher_id)
    if "chacha20" in c:
        return 256
    aes256 = r"(?:aes|aria|camellia)(?:-)?256|[-/]256[-/](?:gcm|ccm|cbc)|[-]256[-](?:gcm|ccm|cbc)"
    if re.search(aes256, c):
        return 256
    return 128


def _cell_enabled_test_features_skip_reason(cell: dict[str, str], *, server: str, client: str,
                                            srv_caps: dict[str, Any], cli_caps: dict[str, Any]) -> str | None:
    for feat in sorted(parse_test_features_enabled(str(cell.get("test_features") or ""))):
        for role_label, caps in ((f"server ({server})", srv_caps), (f"client ({client})", cli_caps)):
            entry = BackendCapabilities(caps).feature_entry(feat)
            if not entry.get("wired", False):
                return f"Feature {feat} is not wired in {role_label} wrapper"
            if not entry.get("supported", False):
                return f"Feature {feat} is not supported in {role_label} wrapper"
    return None


def _cell_test_feature_skip_reason(cell: dict[str, str], *, server: str, client: str,
                                   srv_caps: dict[str, Any], cli_caps: dict[str, Any]) -> str | None:
    cid = _cell_cipher_id(cell, server=True) or _cell_cipher_id(cell, server=False)
    if not cid:
        return None
    feat = cipher_required_test_feature(cid)
    if not feat:
        return None
    if feat not in parse_test_features_enabled(str(cell.get("test_features") or "")):
        return "Feature disabled"
    for role_label, caps in ((f"server ({server})", srv_caps), (f"client ({client})", cli_caps)):
        entry = BackendCapabilities(caps).feature_entry(feat)
        if not entry.get("wired", False):
            return "Not wired"
        if not entry.get("supported", False):
            return f"Feature {feat} is not supported in {role_label} wrapper"
    return None


def _signature_scheme_auth_kind(token: str) -> Literal["rsa", "ecdsa", "dsa", "eddsa", "unknown"]:
    t = (token or "").strip().lower().replace("_", "").replace("-", "")
    if not t:
        return "unknown"
    if t.startswith("dsa") or t == "dsa":
        return "dsa"
    if t.startswith("rsa") or "rsa" in t:
        return "rsa"
    if t.startswith("ecdsa") or "ecdsa" in t:
        return "ecdsa"
    if t.startswith("ed25519") or t.startswith("ed448") or t.startswith("eddsa"):
        return "eddsa"
    return "unknown"


def _group_family(token: str) -> Literal["ec", "ffdhe", "other"]:
    t = (token or "").strip().lower().replace("_", "-")
    if not t:
        return "other"
    if t.startswith("ffdhe"):
        return "ffdhe"
    if (t.startswith("secp") or t.startswith("x25519") or t.startswith("x448")
            or t.startswith("brainpool") or t.startswith("xyber")
            or t.startswith("mlkem") or "mlkem" in t):
        return "ec"
    return "other"


def _tls12_semantic_skip_reason_side(cell: dict[str, str], *, server: bool, mode: TlsMode) -> str | None:
    if mode != "1.2":
        return None
    cipher_id = _cell_cipher_id(cell, server=server)
    if not cipher_id:
        return None
    meta = tls12_cipher_metadata_from_name(cipher_id)
    grp_tokens = _split_cell_list_tokens(cell, "supported_groups", server=server)
    if grp_tokens and meta.kx == "static-rsa":
        return "TLS 1.2 static RSA cipher does not support groups"
    if grp_tokens and meta.kx == "ecdhe":
        for grp in grp_tokens:
            fam = _group_family(grp)
            if fam != "ec":
                return "TLS 1.2 ECDHE cipher requires EC groups (secp*/x25519/x448)"
    if grp_tokens and meta.kx == "dhe":
        for grp in grp_tokens:
            fam = _group_family(grp)
            if fam != "ffdhe":
                return "TLS 1.2 DHE cipher requires FFDHE groups"

    sig_tokens = _split_cell_list_tokens(cell, "signature_schemes", server=server)
    if not sig_tokens or meta.au == "unknown":
        return None
    for sig in sig_tokens:
        sk = _signature_scheme_auth_kind(sig)
        if sk == "unknown":
            continue
        if meta.au == "rsa" and sk != "rsa":
            return "Signature scheme type conflicts with TLS 1.2 cipher authentication"
        if meta.au == "ecdsa" and sk != "ecdsa":
            return "Signature scheme type conflicts with TLS 1.2 cipher authentication"
        if meta.au == "dsa" and sk != "dsa":
            return "Signature scheme type conflicts with TLS 1.2 cipher authentication"
    return None


def cell_capability_skip_reason(cell: dict[str, str], repo: Path) -> str | None:
    server = (cell.get("server") or "").strip().lower()
    client = (cell.get("client") or "").strip().lower()
    if not server or not client:
        return None
    try:
        srv_bc = load_backend_capabilities(server)
        cli_bc = load_backend_capabilities(client)
    except (FileNotFoundError, ValueError) as e:
        return str(e)
    srv_caps = srv_bc.raw
    cli_caps = cli_bc.raw

    mode_srv = effective_cell_tls_mode(cell, srv_caps, cli_caps)
    mode_cli = mode_srv
    tv = (cell.get("tls_version") or "").strip()
    if tv and ":" in tv:
        lv, rv = parse_asymmetric(tv)
        if lv:
            mode_srv = tls_mode_from_version(lv)
        if rv:
            mode_cli = tls_mode_from_version(rv)

    sem_srv = _tls12_semantic_skip_reason_side(cell, server=True, mode=mode_srv)
    if sem_srv:
        return sem_srv
    sem_cli = _tls12_semantic_skip_reason_side(cell, server=False, mode=mode_cli)
    if sem_cli:
        return sem_cli

    feat_skip = _cell_enabled_test_features_skip_reason(cell, server=server, client=client, srv_caps=srv_caps, cli_caps=cli_caps)
    if feat_skip:
        return feat_skip

    feat_skip = _cell_test_feature_skip_reason(cell, server=server, client=client, srv_caps=srv_caps, cli_caps=cli_caps)
    if feat_skip:
        return feat_skip

    id_skip = _cell_identity_pem_skip_reason(cell, repo)
    if id_skip:
        return id_skip

    if (cell.get("expect_hrr") or "").strip().lower() in ("true", "1", "yes"):
        blocked = frozenset(
            str(x).strip() for x in (cli_bc.runtime().get("unsupported_tls_fields") or ()))
        if "expect_hrr" in blocked:
            return f"client ({client}) does not support expect_hrr"

    for check in (
        _check_cipher_side(cell, server=True, wrapper=f"server ({server})", caps=srv_caps, mode=mode_srv),
        _check_cipher_side(cell, server=False, wrapper=f"client ({client})", caps=cli_caps, mode=mode_cli)):
        if check:
            return check

    for dim in ("supported_groups", "signature_schemes", "alpn"):
        for check in (
            _check_list_dim(cell, dim, server=True, wrapper=f"server ({server})", caps=srv_caps, mode=mode_srv),
            _check_list_dim(cell, dim, server=False, wrapper=f"client ({client})", caps=cli_caps, mode=mode_cli)):
            if check:
                return check

    tv_single = (cell.get("tls_version") or "").strip()
    if tv_single and ":" not in tv_single:
        for wrapper, caps, mode in ((f"server ({server})", srv_caps, mode_srv),
                                    (f"client ({client})", cli_caps, mode_cli)):
            block = caps.get("tls_version")
            if isinstance(block, dict) and block:
                key = "1.2" if mode == "1.2" else "1.3"
                if key not in block:
                    return f"{wrapper} lacks tls_version={key!r}"

    return None


def print_catalog_options(repo: Path | None = None) -> None:
    for item in build_cli_options_catalog(repo):
        choices = item.get("choices") or []
        ctext = f" choices={choices}" if choices else ""
        print(f"{item.get('id')}{ctext}")


def _config_has_value(config: Any, field: str) -> bool:
    raw = getattr(config, field, None)
    if raw is None:
        return False
    if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes, bytearray)):
        return any(str(x).strip() for x in raw)
    if isinstance(raw, Iterable) and not isinstance(raw, (str, bytes, bytearray, dict)):
        return any(str(x).strip() for x in raw)
    if isinstance(raw, bytes):
        return bool(raw.strip())
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return raw != 0
    return bool(str(raw).strip())


def unsupported_cli_params(config: Any, backend: str, repo: Path | None = None) -> list[str]:
    key = (backend or "").strip().lower()
    rt = load_backend_capabilities(key).runtime()
    extra = rt.get("unsupported_tls_fields") or ()
    if not isinstance(extra, (list, tuple)):
        return []
    bad: list[str] = []
    for field in extra:
        name = str(field).strip()
        if name and _config_has_value(config, name):
            bad.append(name)
    return bad


def catalog_parameter_conflicts(config: Any, backend: str, *, role: Any | None = None,
                                capabilities: dict[str, Any] | None = None, repo: Path | None = None) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in unsupported_cli_params(config, backend, repo):
        if item not in seen:
            seen.add(item)
            out.append(item)
    if capabilities:
        for item in tls_argv_for_config(config, backend, capabilities, role=role).unsupported:
            if item not in seen:
                seen.add(item)
                out.append(item)
    return out


def validate_run_args(args: Any, *, known_wrappers: frozenset[str] | None = None, repo: Path | None = None) -> None:
    _ = (known_wrappers, repo)
    if not (0 <= int(args.tls_port) <= 65535):
        raise ValueError("--tls-port must be in range 0..65535")
    for attr in ("server_grpc_port", "client_grpc_port"):
        if not (0 <= int(getattr(args, attr, 0) or 0) <= 65535):
            raise ValueError(f"--{attr.replace('_', '-')} must be in range 0..65535")


def matrix_axis_plan(args: Any, *, known_wrappers: frozenset[str], repo: Path | None = None) -> tuple[list[str], list[list[Any]]]:
    root = repo or repository_root()
    wr = sorted(known_wrappers)
    caps_cache = {wid: load_backend_capabilities(wid).raw for wid in known_wrappers}
    catalog = build_cli_options_catalog(root)

    keys = ["server", "client"]
    server_vals = expand_dimension(str(args.server), wr)
    client_vals = expand_dimension(str(args.client), wr)
    vals: list[list[Any]] = [server_vals, client_vals]
    matrix_wrappers = set(server_vals) | set(client_vals)
    cipher_tls_mode = tls_mode_filter_from_args(args)

    for item in sorted(catalog, key=lambda x: str(x.get("id", ""))):
        oid = item["id"]
        if oid in NON_TLS_OPTION_IDS or oid == "tls_port" or oid in NON_MATRIX_OPTION_IDS:
            continue
        ch = item.get("choices") or []
        keys.append(oid)
        tokens = option_choice_tokens(item) if ch else []
        raw = str(getattr(args, oid, "") or "")
        if oid in CAPABILITY_DIMENSIONS and tokens:
            if oid == "alpn":
                vals.append(expand_alpn_matrix_axis(
                    raw, wrapper_ids=sorted(matrix_wrappers), caps_by_wrapper=caps_cache,
                    catalog_choices=tokens))
            else:
                vals.append(expand_capability_dimension(
                    raw, capability_dimension_name(oid), wrapper_ids=sorted(matrix_wrappers),
                    caps_by_wrapper=caps_cache, catalog_choices=tokens,
                    tls_mode=cipher_tls_mode if oid == "cipher_suite" else None))
        elif tokens:
            vals.append(expand_dimension(raw, tokens))
        else:
            if raw in (None, "", 0):
                vals.append([""])
            else:
                vals.append([str(raw)])
    return keys, vals

"""CLI option catalog (capabilities union), validation, and matrix expansion."""

from __future__ import annotations

import importlib
import json
import os
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal, Sequence

TlsMode = Literal["1.2", "1.3"]

TLS12_TOKENS = frozenset({"1.2", "1.2.0", "tls1.2", "tls1_2"})
TLS13_TOKENS = frozenset({"1.3", "1.3.0", "tls1.3", "tls1_3"})

# Driver metadata fallback when env cipher id is not in GetMetadata lists.
FALLBACK_CIPHER_ID_TO_IANA: dict[str, str] = {
    "aes-256-gcm": "TLS_AES_256_GCM_SHA384",
    "aes-128-gcm": "TLS_AES_128_GCM_SHA256",
    "chacha20-poly1305": "TLS_CHACHA20_POLY1305_SHA256",
}

# Static CLI options (choices for crypto dims come from capabilities union).
STATIC_CLI_OPTIONS: tuple[dict[str, Any], ...] = (
    {
        "id": "cipher_suite",
        "description": "Cipher suite catalog id (per-backend mapping in capabilities.json).",
    },
    {
        "id": "tls_version",
        "choices": ["1.2", "1.3"],
        "description": "TLS protocol version for the endpoint (TlsConfig.version).",
    },
    {
        "id": "tls_port",
        "description": "TLS data-plane port override (default scenario value is 5555).",
    },
    {
        "id": "certificate_pem",
        "description": "PEM certificate bytes provided to endpoint identity config.",
    },
    {
        "id": "private_key_pem",
        "description": "PEM private key bytes paired with certificate_pem.",
    },
    {
        "id": "supported_groups",
        "description": "Advertised/allowed key exchange groups (supported_groups extension).",
    },
    {
        "id": "signature_schemes",
        "description": "Advertised TLS signature algorithms.",
    },
    {
        "id": "alpn_protocols",
        "description": "Application protocols for ALPN negotiation (e.g. h2, http/1.1).",
    },
    {
        "id": "test_features",
        "description": (
            "Credentials for special ciphers (psk, anonymous). "
            "cipher_suite ALL lists every cipher; without this, PSK/anon cells run and FAIL. "
            "Set test_features: psk,anonymous (or YAML map with true values) to enable wiring."
        ),
    },
    {
        "id": "ca_file",
        "description": "Path/identifier for trusted CA bundle file.",
    },
    {
        "id": "keylog_file",
        "description": "NSS/SSLKEYLOGFILE-compatible key log output path.",
    },
)

OPTION_GROUPS: dict[str, str] = {
    "tls_port": "basic",
    "cipher_suite": "crypto",
    "tls_version": "protocol",
    "supported_groups": "crypto",
    "signature_schemes": "crypto",
    "ca_file": "security",
    "certificate_pem": "security",
    "private_key_pem": "security",
    "keylog_file": "debug",
    "alpn_protocols": "debug",
    "test_features": "crypto",
}

NON_TLS_OPTION_IDS: frozenset[str] = frozenset({"server_wrapper", "client_wrapper"})
# Applied once per run (suite/CLI), not Cartesian-expanded with cipher_suite.
NON_MATRIX_OPTION_IDS: frozenset[str] = frozenset({"test_features"})
MULTI_VALUE_OPTION_IDS: frozenset[str] = frozenset(
    {"supported_groups", "signature_schemes", "alpn_protocols", "test_features"}
)
ASYMMETRIC_SCALAR_OPTION_IDS: frozenset[str] = frozenset({"cipher_suite", "tls_version"})
ASYMMETRIC_HELP_OPTION_IDS: frozenset[str] = frozenset(
    {"cipher_suite", "signature_schemes", "supported_groups", "tls_version"}
)

CAPABILITY_DIMENSIONS: frozenset[str] = frozenset(
    {"cipher_suite", "supported_groups", "signature_schemes", "tls_version"}
)
TLS13_ORTHOGONAL_DIMS: frozenset[str] = frozenset(
    {"supported_groups", "signature_schemes"}
)


def repository_root() -> Path:
    """Repo root (``deploy/compose.yaml``) or container ``/app`` (``proto/interop_pb2.py``)."""
    cur = Path(__file__).resolve().parent
    while True:
        if (cur / "deploy" / "compose.yaml").is_file():
            return cur
        if (cur / "proto" / "interop_pb2.py").is_file():
            return cur
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
    p = Path(__file__).resolve()
    for candidate in (p.parents[2], p.parents[1]):
        if (candidate / "deploy" / "compose.yaml").is_file():
            return candidate
        if (candidate / "proto" / "interop_pb2.py").is_file():
            return candidate
    return p.parents[2]


_purged_foreign_proto = False


def _purge_foreign_proto_module() -> None:
    """Drop unrelated PyPI ``proto`` (proto-plus) so ``import proto`` hits this repo."""
    global _purged_foreign_proto
    if _purged_foreign_proto:
        return
    mod = sys.modules.get("proto")
    if mod is not None and not hasattr(mod, "interop_pb2"):
        for key in list(sys.modules):
            if key == "proto" or key.startswith("proto."):
                del sys.modules[key]
    _purged_foreign_proto = True


def ensure_import_paths() -> Path:
    """
    Put repo root on ``sys.path[0]`` and ``src/`` on ``[1]`` before ``import proto``.

    Call once at process entry (``main``, ``driver``) or rely on ``proto/__init__.py``.
    """
    root = repository_root()
    if not (root / "proto" / "interop_pb2.py").is_file():
        raise ImportError(f"project proto/ not found under {root}")
    rs = str(root)
    while rs in sys.path:
        sys.path.remove(rs)
    sys.path.insert(0, rs)
    src = root / "src"
    if src.is_dir():
        ss = str(src)
        if ss in sys.path:
            sys.path.remove(ss)
        sys.path.insert(1, ss)
    _purge_foreign_proto_module()
    return root


@dataclass(frozen=True)
class TranslationResult:
    """Backend CLI argv fragments and unsupported catalog tokens."""

    argv: tuple[str, ...]
    unsupported: tuple[str, ...]


def load_local_capabilities(wrapper_file: str) -> dict[str, Any]:
    """Load ``capabilities.json`` next to a ``wrapper.py`` file."""
    path = Path(wrapper_file).resolve().parent / "capabilities.json"
    if not path.is_file():
        raise FileNotFoundError(f"capabilities.json not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"capabilities.json must be a JSON object: {path}")
    return data


def metadata_from_capabilities(
    capabilities: dict[str, Any],
    *,
    component_name: str | None = None,
) -> tuple[list[tuple[str, bool]], list[str], list[str]]:
    """
    Build GetMetadata lists using **catalog token ids** (JSON keys).

    Driver compares env values to capability names (e.g. ``aes-128-gcm``), not CLI literals.
    """
    del component_name
    versions = [("TLS1.2", False), ("TLS1.3", True)]
    cap13, cap12 = cipher_maps_from_capabilities(capabilities)
    cipher_ids = sorted(set(cap13) | set(cap12))
    groups_block = capabilities.get("supported_groups") or {}
    groups = sorted(str(k) for k in groups_block.keys() if k)
    return versions, cipher_ids, groups


def tls_argv_for_config(
    config: Any,
    backend: str,
    capabilities: dict[str, Any],
    *,
    role: Any | None = None,
) -> TranslationResult:
    """Delegate argv translation to ``wrappers.<backend>.wrapper.tls_argv_for_config``."""
    name = (backend or "").strip().lower()
    _ensure_src_importable()
    mod = importlib.import_module(f"wrappers.{name}.wrapper")
    fn = getattr(mod, "tls_argv_for_config", None)
    if fn is None:
        return TranslationResult((), (f"(backend {name!r} has no tls_argv_for_config)",))
    return fn(config, role=role, capabilities=capabilities)


def build_cli_options_catalog(repo: Path | None = None) -> list[dict[str, Any]]:
    """Merge static CLI options with union of keys from all ``capabilities.json`` files."""
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


def load_options_catalog(repo: Path | None = None) -> list[dict[str, Any]]:
    """CLI/matrix option descriptors (dynamic choices from wrapper capabilities)."""
    return build_cli_options_catalog(repo)


def union_cipher_suite_ids(repo: Path | None = None) -> frozenset[str]:
    root = repo or repository_root()
    return frozenset(aggregate_union(root, discover_wrapper_ids(root))["cipher_suite"])


def wrappers_plugin_dir(repo: Path) -> Path:
    """``src/wrappers`` in dev checkout; ``wrappers/`` in the container image."""
    if (repo / "wrappers").is_dir():
        return repo / "wrappers"
    return repo / "src" / "wrappers"


def discover_wrapper_ids(repo: Path) -> tuple[str, ...]:
    """Ids from ``src/wrappers/<id>/wrapper.py`` + ``capabilities.json``."""
    plugin_dir = wrappers_plugin_dir(repo)
    if not plugin_dir.is_dir():
        return ()
    found: list[str] = []
    for path in sorted(plugin_dir.iterdir()):
        if not path.is_dir():
            continue
        if (path / "wrapper.py").is_file() and (path / "capabilities.json").is_file():
            found.append(path.name)
    return tuple(found)


def _ensure_src_importable(repo: Path | None = None) -> Path:
    src = (repo or repository_root()) / "src"
    src_s = str(src)
    if src_s not in sys.path:
        sys.path.insert(0, src_s)
    return src


def load_capabilities(backend_name: str, repo: Path | None = None) -> dict[str, Any]:
    name = (backend_name or "").strip().lower()
    path = wrappers_plugin_dir(repo or repository_root()) / name / "capabilities.json"
    if not path.is_file():
        raise FileNotFoundError(f"capabilities.json not found for backend {name!r}: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"capabilities.json must be a JSON object: {path}")
    return data


_RUNTIME_DEFAULTS: dict[str, Any] = {
    "grpc_addr": None,
    "tls_host": "127.0.0.1",
    "tls_port": 15551,
    "compose_service": None,
    "unsupported_tls_fields": (),
    "local_cli": (),
}


def wrapper_runtime(capabilities: dict[str, Any]) -> dict[str, Any]:
    """Merged ``capabilities.json`` → ``runtime`` block with defaults."""
    raw = capabilities.get("runtime")
    if not isinstance(raw, dict):
        raw = {}
    out = dict(_RUNTIME_DEFAULTS)
    for key in _RUNTIME_DEFAULTS:
        if key in raw and raw[key] is not None:
            out[key] = raw[key]
    return out


def wrapper_runtime_config(
    backend_name: str, repo: Path | None = None
) -> dict[str, Any]:
    """Per-wrapper ``runtime`` section from ``capabilities.json``."""
    return wrapper_runtime(load_capabilities(backend_name, repo))


def load_wrapper_module(backend_name: str) -> Any:
    """Import ``wrappers.<backend>.wrapper`` (optional plugin hooks live there)."""
    name = (backend_name or "").strip().lower()
    _ensure_src_importable()
    return importlib.import_module(f"wrappers.{name}.wrapper")


def call_wrapper_hook(
    backend_name: str,
    hook: str,
    /,
    *args: Any,
    **kwargs: Any,
) -> Any:
    mod = load_wrapper_module(backend_name)
    fn = getattr(mod, hook, None)
    if fn is None:
        return None
    return fn(*args, **kwargs)


def local_cli_requirements(
    backend_name: str, capabilities: dict[str, Any]
) -> tuple[str, ...]:
    req = call_wrapper_hook(backend_name, "local_cli_requirements")
    if req is not None:
        return tuple(str(x) for x in req)
    cli = wrapper_runtime(capabilities).get("local_cli") or ()
    return tuple(str(x) for x in cli)


def resolve_wrapper_cli_tool(backend_name: str, exe: str) -> str | None:
    resolved = call_wrapper_hook(backend_name, "resolve_cli_tool", exe)
    if resolved:
        return str(resolved)
    import shutil

    return shutil.which(exe)


def wrapper_orchestration_env(
    backend_name: str, active_backends: frozenset[str] | set[str]
) -> dict[str, str]:
    out = call_wrapper_hook(backend_name, "orchestration_env", active_backends)
    return dict(out) if isinstance(out, dict) else {}


def wrapper_local_env(
    backend_name: str,
    repo: Path,
    active_backends: frozenset[str] | set[str],
) -> dict[str, str]:
    out = call_wrapper_hook(
        backend_name, "local_wrapper_env", repo, backend_name, active_backends
    )
    return dict(out) if isinstance(out, dict) else {}


def merged_orchestration_env(active_backends: Iterable[str]) -> dict[str, str]:
    """Union env fragments from every active wrapper's ``orchestration_env`` hook."""
    active = frozenset(
        (b or "").strip().lower() for b in active_backends if (b or "").strip()
    )
    merged: dict[str, str] = {}
    for backend in sorted(active):
        merged.update(wrapper_orchestration_env(backend, active))
    return merged


def session_wrapper_env(
    backend_name: str,
    repo: Path,
    active_backends: Iterable[str],
) -> dict[str, str]:
    """Orchestration + per-wrapper env for one wrapper subprocess."""
    active = frozenset(
        (b or "").strip().lower() for b in active_backends if (b or "").strip()
    )
    merged = dict(merged_orchestration_env(active))
    merged.update(wrapper_local_env(backend_name, repo, active))
    return merged


def backend_grpc_addr(backend_name: str, repo: Path | None = None) -> str:
    rt = wrapper_runtime_config(backend_name, repo)
    addr = rt.get("grpc_addr")
    if not isinstance(addr, str) or not addr.strip():
        raise ValueError(
            f"capabilities.runtime.grpc_addr missing for backend {backend_name!r}"
        )
    return addr.strip()


def backend_tls_endpoint(
    backend_name: str, repo: Path | None = None
) -> tuple[str, int]:
    rt = wrapper_runtime_config(backend_name, repo)
    host = str(rt.get("tls_host") or "127.0.0.1")
    port = int(rt.get("tls_port") or 15551)
    return host, port


def compose_service_name(backend_name: str, repo: Path | None = None) -> str:
    rt = wrapper_runtime_config(backend_name, repo)
    svc = rt.get("compose_service")
    if isinstance(svc, str) and svc.strip():
        return svc.strip()
    return (backend_name or "").strip().lower()


def discover_compose_backends(repo: Path | None = None) -> frozenset[str]:
    """Wrapper ids that declare ``runtime.compose_service`` (Docker Compose services)."""
    root = repo or repository_root()
    out: set[str] = set()
    for wid in discover_wrapper_ids(root):
        rt = wrapper_runtime_config(wid, root)
        if rt.get("compose_service"):
            out.add(wid)
    return frozenset(out)


def check_local_cli_tools(
    backends: Iterable[str], repo: Path | None = None
) -> list[str]:
    """Return human-readable missing-tool messages (delegates to each wrapper)."""
    missing: list[str] = []
    root = repo or repository_root()
    for backend in backends:
        key = (backend or "").strip().lower()
        caps = load_capabilities(key, root)
        for exe in local_cli_requirements(key, caps):
            if resolve_wrapper_cli_tool(key, exe) is None:
                missing.append(f"{key}: {exe} not found")
    return missing


def load_backend_component(
    backend_name: str,
    repo: Path | None = None,
) -> tuple[Any, dict[str, Any]]:
    """
    Import ``wrappers.<backend>.wrapper`` and load ``capabilities.json``.

    Returns ``(wrapper_module, capabilities)``.
    """
    name = (backend_name or "").strip().lower()
    _ensure_src_importable(repo)
    capabilities = load_capabilities(name, repo)
    module = importlib.import_module(f"wrappers.{name}.wrapper")
    return module, capabilities


def load_backend(
    backend_name: str,
    repo: Path | None = None,
) -> tuple[Any, dict[str, Any]]:
    """Alias for :func:`load_backend_component`."""
    return load_backend_component(backend_name, repo)


def load_capabilities_cache(
    wrapper_ids: frozenset[str] | set[str],
    repo: Path | None = None,
) -> dict[str, dict[str, Any]]:
    return {wid: load_capabilities(wid, repo) for wid in wrapper_ids}


def _merge_legacy_cipher_maps(caps: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    """Support deprecated top-level ``cipher_suite`` with nested tls13/tls12 values."""
    m13: dict[str, str] = {}
    m12: dict[str, str] = {}
    legacy = caps.get("cipher_suite")
    if not isinstance(legacy, dict):
        return m13, m12
    for key, val in legacy.items():
        if isinstance(val, dict):
            if val.get("tls13"):
                m13[str(key)] = str(val["tls13"])
            if val.get("tls12"):
                m12[str(key)] = str(val["tls12"])
        elif isinstance(val, str) and val.strip():
            m13[str(key)] = val
    return m13, m12


def cipher_maps_from_capabilities(
    capabilities: dict[str, Any],
) -> tuple[dict[str, str], dict[str, str]]:
    """Return (tls13_map, tls12_map) catalog_id → raw CLI string."""
    t13 = capabilities.get("tls13") if isinstance(capabilities.get("tls13"), dict) else {}
    t12 = capabilities.get("tls12") if isinstance(capabilities.get("tls12"), dict) else {}
    m13 = dict(t13.get("cipher_suite") or {}) if isinstance(t13.get("cipher_suite"), dict) else {}
    m12 = dict(t12.get("cipher_suite") or {}) if isinstance(t12.get("cipher_suite"), dict) else {}
    leg13, leg12 = _merge_legacy_cipher_maps(capabilities)
    for k, v in leg13.items():
        m13.setdefault(k, v)
    for k, v in leg12.items():
        m12.setdefault(k, v)
    return (
        {str(k): str(v) for k, v in m13.items() if v},
        {str(k): str(v) for k, v in m12.items() if v},
    )


def all_cipher_suite_ids(capabilities: dict[str, Any]) -> list[str]:
    m13, m12 = cipher_maps_from_capabilities(capabilities)
    return sorted(set(m13) | set(m12))


def cipher_suite_ids_for_mode(
    capabilities: dict[str, Any], mode: TlsMode
) -> list[str]:
    """Catalog cipher ids declared under ``tls13`` or ``tls12`` for ``mode``."""
    m13, m12 = cipher_maps_from_capabilities(capabilities)
    mp = m13 if mode == "1.3" else m12
    return sorted(str(k) for k in mp.keys() if k)


def union_cipher_suite_ids_for_wrappers(
    caps_by_wrapper: dict[str, dict[str, Any]],
    wrapper_ids: Sequence[str],
    *,
    mode: TlsMode | None = None,
) -> list[str]:
    """Union of cipher catalog ids across wrappers, optionally restricted to one TLS mode."""
    keys: set[str] = set()
    for wid in wrapper_ids:
        caps = caps_by_wrapper.get(wid, {})
        if mode is None:
            keys.update(all_cipher_suite_ids(caps))
        else:
            keys.update(cipher_suite_ids_for_mode(caps, mode))
    return sorted(keys)


def tls_mode_filter_from_args(args: Any) -> TlsMode | None:
    """
    When ``args.tls_version`` is a single protocol version, return ``1.2`` or ``1.3``.

    Returns ``None`` if unset or asymmetric (``1.3:1.2``) so cipher expansion stays broad
    and per-cell skip/normalize handles mismatches.
    """
    raw = str(getattr(args, "tls_version", "") or "").strip()
    if not raw:
        return None
    if ":" in raw:
        left, right = parse_asymmetric(raw)
        if left and right and tls_mode_from_version(left) == tls_mode_from_version(right):
            return tls_mode_from_version(left)
        return None
    return tls_mode_from_version(raw)


def backend_cipher_modes(
    capabilities: dict[str, Any], catalog_id: str
) -> set[TlsMode]:
    m13, m12 = cipher_maps_from_capabilities(capabilities)
    key = norm_catalog_token(catalog_id)
    modes: set[TlsMode] = set()
    if key in m13 or catalog_id in m13:
        modes.add("1.3")
    if key in m12 or catalog_id in m12:
        modes.add("1.2")
    return modes


def backend_supports_cipher(
    capabilities: dict[str, Any], catalog_id: str, mode: TlsMode
) -> bool:
    m13, m12 = cipher_maps_from_capabilities(capabilities)
    key = norm_catalog_token(catalog_id)
    mp = m13 if mode == "1.3" else m12
    return key in mp or catalog_id in mp


def dimension_keys(
    capabilities: dict[str, Any],
    dimension: str,
    *,
    tls_mode: TlsMode | None = None,
) -> list[str]:
    if dimension == "cipher_suite":
        if tls_mode is not None:
            return cipher_suite_ids_for_mode(capabilities, tls_mode)
        return all_cipher_suite_ids(capabilities)
    block = capabilities.get(dimension)
    if not isinstance(block, dict):
        return []
    return sorted(str(k) for k in block.keys() if k)


def backend_supports_token(
    capabilities: dict[str, Any],
    dimension: str,
    token: str,
    *,
    mode: TlsMode | None = None,
) -> bool:
    if dimension == "cipher_suite":
        if mode is None:
            return bool(backend_cipher_modes(capabilities, token))
        return backend_supports_cipher(capabilities, token, mode)
    block = capabilities.get(dimension)
    if not isinstance(block, dict):
        return False
    key = norm_catalog_token(token)
    return key in block or token in block


def aggregate_union(repo: Path, wrapper_ids: tuple[str, ...] | frozenset[str]) -> dict[str, list[str]]:
    """Union of catalog token ids across backends (for CLI choices)."""
    cipher: set[str] = set()
    groups: set[str] = set()
    sigs: set[str] = set()
    for wid in wrapper_ids:
        caps = load_capabilities(wid, repo)
        cipher.update(all_cipher_suite_ids(caps))
        groups.update(dimension_keys(caps, "supported_groups"))
        sigs.update(dimension_keys(caps, "signature_schemes"))
    test_feats: set[str] = set()
    for wid in wrapper_ids:
        test_feats.update(test_feature_ids(load_capabilities(wid, repo)))
    return {
        "cipher_suite": sorted(cipher),
        "supported_groups": sorted(groups),
        "signature_schemes": sorted(sigs),
        "test_features": sorted(test_feats),
        "tls_version": ["1.2", "1.3"],
    }


def is_cipher_tls13_only(capabilities: dict[str, Any], catalog_id: str) -> bool:
    return backend_cipher_modes(capabilities, catalog_id) == {"1.3"}


def is_cipher_tls12_only(capabilities: dict[str, Any], catalog_id: str) -> bool:
    return backend_cipher_modes(capabilities, catalog_id) == {"1.2"}


def parse_asymmetric(val: str | None) -> tuple[str, str]:
    v = (val or "").strip()
    if ":" in v:
        left, right = v.split(":", 1)
        return left.strip(), right.strip()
    return v, v


def norm_token(s: str) -> str:
    return (s or "").strip().lower().replace("-", "").replace("_", "")


def norm_catalog_token(raw: str) -> str:
    return (raw or "").strip().lower().replace(" ", "")


def tls_mode_from_version(version: str | None) -> TlsMode:
    if not (version or "").strip():
        return "1.3"
    v = version.strip().lower()
    if v in TLS12_TOKENS:
        return "1.2"
    if v in TLS13_TOKENS:
        return "1.3"
    upper = version.strip().upper().replace(" ", "")
    if upper == "TLS1.2":
        return "1.2"
    if upper == "TLS1.3":
        return "1.3"
    return "1.3"


def tls_version_forces_12(tok: str) -> bool:
    t = (tok or "").strip().lower().replace(" ", "").replace("_", "")
    return t in ("1.2", "1.2.0", "tls1.2") or (tok or "").strip().upper() == "TLS1.2"


def tls_version_to_capability_name(version_str: str | None) -> str:
    if version_str is None or str(version_str).strip() == "":
        return "TLS1.3"
    if tls_mode_from_version(str(version_str)) == "1.2":
        return "TLS1.2"
    return "TLS1.3"


def option_choice_tokens(item: dict[str, Any]) -> list[str]:
    """CLI/matrix tokens for a catalog option."""
    ch = item.get("choices") or []
    return [str(c).strip() for c in ch if str(c).strip()]


def _coerce_cipher_tls13_only(
    cipher_side: str,
    ver_side: str,
    caps: dict[str, Any],
) -> str | None:
    if not tls_version_forces_12(ver_side):
        return None
    cid = (cipher_side or "").strip()
    if not cid:
        return None
    if is_cipher_tls13_only(caps, cid):
        return "1.3"
    return None


def coerce_tls_version_for_cipher_capabilities(
    args: Any,
    repo: Path | None = None,
) -> None:
    """
    If ``--tls-version`` pins TLS 1.2 but the cipher exists only under ``tls13`` in
    the active server/client capabilities, bump version to 1.3 for that side.
    """
    cs_raw = getattr(args, "cipher_suite", None)
    tv_raw = getattr(args, "tls_version", None)
    if cs_raw in (None, "", 0) or tv_raw in (None, "", 0):
        return
    cs_s = str(cs_raw).strip()
    tv_s = str(tv_raw).strip()
    if not cs_s or not tv_s:
        return

    root = repo or repository_root()
    server = (getattr(args, "server", None) or "").strip().lower()
    client = (getattr(args, "client", None) or "").strip().lower()
    try:
        srv_caps = load_capabilities(server, root) if server else {}
        cli_caps = load_capabilities(client, root) if client else {}
    except (FileNotFoundError, ValueError):
        return

    def _pair(cipher_side: str, ver_side: str, caps: dict[str, Any]) -> str | None:
        return _coerce_cipher_tls13_only(cipher_side, ver_side, caps)

    warn = (
        "[catalog] TLS 1.3-only cipher with --tls-version 1.2: "
        "adjusting protocol version to 1.3 to avoid handshake mismatch."
    )

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
        modes = backend_cipher_modes(srv_caps, cs_s) | backend_cipher_modes(cli_caps, cs_s)
        if "1.3" in modes and "1.2" not in modes:
            caps = srv_caps
        else:
            caps = srv_caps
    n = _pair(cs_s, tv_s, caps)
    if n:
        print(warn, file=sys.stderr)
        setattr(args, "tls_version", n)


def expand_dimension(value: str, choices: Sequence[str]) -> list[str]:
    """
    Expand a CLI dimension into concrete values.

    * Comma list: ``openssl,gnutls`` → listed tokens (each must be in ``choices``).
    * ``ALL`` (case-insensitive): full ``choices`` order.
    * ``ALL \\ a,b`` or ``ALL - a,b``: all choices except listed exclusions.
    * No ``choices``: one row — ``value`` or ``""``.
    * ``SERVER:CLIENT`` asymmetric (contains ``:`` but not ``ALL``-based): one row, unchanged.
    """
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
        raise ValueError(
            f"Unknown value(s) {bad!r}; known: {', '.join(sorted(set(base)))}"
        )
    return parts


def expand_capability_dimension(
    value: str,
    dimension: str,
    *,
    wrapper_ids: Sequence[str],
    caps_by_wrapper: dict[str, dict[str, Any]],
    catalog_choices: Sequence[str],
    tls_mode: TlsMode | None = None,
) -> list[str]:
    """Expand ALL / lists using per-backend ``capabilities.json`` keys."""
    v = (value or "").strip()
    catalog_tokens = [str(c).strip() for c in catalog_choices if c and str(c).strip()]
    cipher_mode = tls_mode if dimension == "cipher_suite" else None

    if re.match(r"(?is)^ALL\s*$", v):
        keys: set[str] = set()
        if dimension == "cipher_suite" and cipher_mode is not None:
            keys.update(
                union_cipher_suite_ids_for_wrappers(
                    caps_by_wrapper, wrapper_ids, mode=cipher_mode
                )
            )
        else:
            for wid in wrapper_ids:
                keys.update(
                    dimension_keys(
                        caps_by_wrapper.get(wid, {}),
                        dimension,
                        tls_mode=cipher_mode,
                    )
                )
        if keys:
            return sorted(keys)
        return list(catalog_tokens)

    sub = re.match(r"(?is)^ALL\s*[\\-]\s*(.+)$", v)
    if sub:
        excl = {x.strip() for x in sub.group(1).split(",") if x.strip()}
        keys: set[str] = set()
        if dimension == "cipher_suite" and cipher_mode is not None:
            keys.update(
                union_cipher_suite_ids_for_wrappers(
                    caps_by_wrapper, wrapper_ids, mode=cipher_mode
                )
            )
        else:
            for wid in wrapper_ids:
                keys.update(
                    dimension_keys(
                        caps_by_wrapper.get(wid, {}),
                        dimension,
                        tls_mode=cipher_mode,
                    )
                )
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
    allowed = set(
        union_cipher_suite_ids_for_wrappers(
            caps_by_wrapper, wrapper_ids, mode=cipher_mode
        )
    )
    filtered = [x for x in expanded if x in allowed]
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


def effective_cell_tls_mode(
    cell: dict[str, str],
    srv_caps: dict[str, Any],
    cli_caps: dict[str, Any],
) -> TlsMode:
    """Infer TLS 1.2 vs 1.3 from explicit version or cipher capabilities sections."""
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
            modes |= backend_cipher_modes(caps, cid)
    if modes == {"1.2"}:
        return "1.2"
    if modes == {"1.3"} or not modes:
        return "1.3"
    return "1.3"


def _implicit_tls_version_for_side(
    cell: dict[str, str], *, server: bool, caps: dict[str, Any]
) -> str:
    cid = _cell_cipher_id(cell, server=server)
    if not cid:
        return ""
    modes = backend_cipher_modes(caps, cid)
    if modes == {"1.3"}:
        return "1.3"
    if modes == {"1.2"}:
        return "1.2"
    return ""


def normalize_cell_tls_micro_params(
    cell: dict[str, str],
    args_template: Any,
    repo: Path,
) -> dict[str, str]:
    """
    Infer ``tls_version`` from cipher ``tls13``/``tls12`` sections; for TLS 1.2 ciphers
    drop orthogonal dims unless the user set them on the CLI.
    """
    out = dict(cell)
    server = (cell.get("server") or "").strip().lower()
    client = (cell.get("client") or "").strip().lower()
    try:
        srv_caps = load_capabilities(server, repo)
        cli_caps = load_capabilities(client, repo)
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
        out["test_features"] = str(getattr(args_template, "test_features", "") or "").strip()
        return out
    for dim in TLS13_ORTHOGONAL_DIMS:
        user_raw = str(getattr(args_template, dim, "") or "").strip()
        if not user_raw:
            out[dim] = ""
    out["test_features"] = str(getattr(args_template, "test_features", "") or "").strip()
    return out


def _check_cipher_side(
    cell: dict[str, str],
    *,
    server: bool,
    wrapper: str,
    caps: dict[str, Any],
    mode: TlsMode,
) -> str | None:
    cid = _cell_cipher_id(cell, server=server)
    if not cid:
        return None
    if backend_supports_cipher(caps, cid, mode):
        return None
    modes = backend_cipher_modes(caps, cid)
    if not modes:
        return f"{wrapper} lacks cipher_suite={cid!r}"
    return (
        f"{wrapper} lacks cipher_suite={cid!r} for TLS {mode} "
        f"(supported modes: {', '.join(sorted(modes))})"
    )


def _check_list_dim(
    cell: dict[str, str],
    dim: str,
    *,
    server: bool,
    wrapper: str,
    caps: dict[str, Any],
    mode: TlsMode,
) -> str | None:
    if mode == "1.2" and dim in TLS13_ORTHOGONAL_DIMS:
        raw = (cell.get(dim) or "").strip()
        if not raw:
            return None
    raw = (cell.get(dim) or "").strip()
    if not raw:
        return None
    if ":" in raw:
        part = raw.split(":", 1)[0 if server else 1].strip()
        tokens = [p.strip() for p in part.split(",") if p.strip()]
    else:
        tokens = [p.strip() for p in raw.split(",") if p.strip()]
    for tok in tokens:
        if not backend_supports_token(caps, dim, tok, mode=mode):
            return f"{wrapper} lacks {dim}={tok!r}"
    return None


@dataclass(frozen=True)
class Tls12CipherMetadata:
    """Metadata extracted from a TLS 1.2 cipher token/name."""

    kx: Literal["ecdhe", "dhe", "static-rsa", "unknown"]
    au: Literal["rsa", "ecdsa", "unknown"]


def _split_cell_list_tokens(cell: dict[str, str], field: str, *, server: bool) -> list[str]:
    raw = (cell.get(field) or "").strip()
    if not raw:
        return []
    if ":" in raw:
        left, right = parse_asymmetric(raw)
        part = left if server else right
        return [p.strip() for p in part.split(",") if p.strip()]
    return [p.strip() for p in raw.split(",") if p.strip()]


def tls12_cipher_metadata_from_name(cipher_name: str) -> Tls12CipherMetadata:
    """
    Extract TLS 1.2 semantics from cipher token/name (catalog id or backend literal).

    This parser is intentionally TLS1.2-oriented and must not be used for TLS 1.3 ciphers.
    """
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

    if "ecdsa" in tok:
        au: Literal["rsa", "ecdsa", "unknown"] = "ecdsa"
    elif "rsa" in tok or tok.startswith("aes"):
        au = "rsa"
    else:
        au = "unknown"
    return Tls12CipherMetadata(kx=kx, au=au)


def cipher_catalog_id_requires_psk(cipher_id: str) -> bool:
    """True for catalog ids such as ``psk-aes-128-gcm``, ``rsa-psk-*``, ``dhe-psk-*``."""
    c = norm_catalog_token(cipher_id)
    return bool(re.search(r"(^|-)psk(-|$)", c))


def cipher_catalog_id_requires_anon(cipher_id: str) -> bool:
    """True for DH/ECDH anonymous catalog ids (``dh-anon-*``, ``ecdh-anon-*``, …)."""
    c = norm_catalog_token(cipher_id)
    return "anon" in c.split("-") or c.startswith("adh-")


def cipher_required_test_feature(cipher_id: str) -> str | None:
    if cipher_catalog_id_requires_psk(cipher_id):
        return "psk"
    if cipher_catalog_id_requires_anon(cipher_id):
        return "anonymous"
    return None


def test_features_block(capabilities: dict[str, Any]) -> dict[str, Any]:
    block = capabilities.get("test_features")
    return block if isinstance(block, dict) else {}


def test_feature_entry(capabilities: dict[str, Any], name: str) -> dict[str, Any]:
    entry = test_features_block(capabilities).get(name)
    return entry if isinstance(entry, dict) else {}


def test_feature_ids(capabilities: dict[str, Any]) -> frozenset[str]:
    out: set[str] = set()
    for key, entry in test_features_block(capabilities).items():
        if isinstance(entry, dict) and entry.get("supported", False):
            out.add(str(key).strip().lower())
    return frozenset(x for x in out if x)


def test_feature_supported(capabilities: dict[str, Any], name: str) -> bool:
    entry = test_feature_entry(capabilities, name)
    return bool(entry.get("supported", False))


def test_feature_wired(capabilities: dict[str, Any], name: str) -> bool:
    entry = test_feature_entry(capabilities, name)
    return bool(entry.get("wired", False))


def parse_test_features_enabled(raw: str) -> frozenset[str]:
    """Parse suite/CLI ``test_features`` into enabled feature names (default: none)."""
    if not (raw or "").strip():
        return frozenset()
    return frozenset(
        p.strip().lower()
        for p in str(raw).split(",")
        if p.strip()
    )


def enabled_test_features_from_cell(cell: dict[str, str]) -> frozenset[str]:
    return parse_test_features_enabled(str(cell.get("test_features") or ""))


def psk_key_bits_for_cipher(cipher_id: str) -> int:
    """PSK key length implied by catalog cipher id (128-bit vs 256-bit suites)."""
    c = norm_catalog_token(cipher_id)
    if "chacha20" in c:
        return 256
    if re.search(
        r"(?:aes|aria|camellia)(?:-)?256|[-/]256[-/](?:gcm|ccm|cbc)|[-]256[-](?:gcm|ccm|cbc)",
        c,
    ):
        return 256
    return 128


def psk_secret_hex_for_cipher(
    capabilities: dict[str, Any], cipher_id: str
) -> str | None:
    entry = test_feature_entry(capabilities, "psk")
    bits = psk_key_bits_for_cipher(cipher_id)
    field = "secret_hex_256" if bits >= 256 else "secret_hex_128"
    secret_hex = str(entry.get(field) or entry.get("secret_hex") or "").strip()
    if not secret_hex:
        return None
    expected = bits // 4
    if len(secret_hex) != expected:
        return None
    return secret_hex


def psk_material_from_capabilities(
    capabilities: dict[str, Any], cipher_id: str
) -> tuple[str, str] | None:
    entry = test_feature_entry(capabilities, "psk")
    identity = str(entry.get("identity") or "interop").strip()
    secret_hex = psk_secret_hex_for_cipher(capabilities, cipher_id)
    if not secret_hex:
        return None
    return identity, secret_hex


def _cell_test_feature_skip_reason(
    cell: dict[str, str],
    *,
    server: str,
    client: str,
    srv_caps: dict[str, Any],
    cli_caps: dict[str, Any],
) -> str | None:
    """
    Pre-run SKIP for PSK/anon suites when a backend cannot wire the feature.

    Missing ``test_features`` in the cell does not SKIP (handshake may FAIL at runtime).
    """
    cid = _cell_cipher_id(cell, server=True) or _cell_cipher_id(cell, server=False)
    if not cid:
        return None
    feat = cipher_required_test_feature(cid)
    if not feat:
        return None
    for role_label, caps in (
        (f"server ({server})", srv_caps),
        (f"client ({client})", cli_caps),
    ):
        if not test_feature_supported(caps, feat):
            return f"Feature {feat} is not supported in {role_label} wrapper"
        if not test_feature_wired(caps, feat):
            return f"Feature {feat} is not wired in {role_label} wrapper"
    return None


def _signature_scheme_auth_kind(token: str) -> Literal["rsa", "ecdsa", "eddsa", "unknown"]:
    t = (token or "").strip().lower().replace("_", "").replace("-", "")
    if not t:
        return "unknown"
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
    if (
        t.startswith("secp")
        or t.startswith("x25519")
        or t.startswith("x448")
        or t.startswith("brainpool")
        or t.startswith("xyber")
        or t.startswith("mlkem")
        or "mlkem" in t
    ):
        return "ec"
    return "other"


def _tls12_semantic_skip_reason_side(
    cell: dict[str, str], *, server: bool, mode: TlsMode
) -> str | None:
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
    return None


def cell_capability_skip_reason(
    cell: dict[str, str],
    repo: Path,
) -> str | None:
    """SKIP when server/client lack a declared token in capabilities.json."""
    server = (cell.get("server") or "").strip().lower()
    client = (cell.get("client") or "").strip().lower()
    if not server or not client:
        return None
    try:
        srv_caps = load_capabilities(server, repo)
        cli_caps = load_capabilities(client, repo)
    except (FileNotFoundError, ValueError) as e:
        return str(e)

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

    feat_skip = _cell_test_feature_skip_reason(
        cell, server=server, client=client, srv_caps=srv_caps, cli_caps=cli_caps
    )
    if feat_skip:
        return feat_skip

    for check in (
        _check_cipher_side(
            cell, server=True, wrapper=f"server ({server})", caps=srv_caps, mode=mode_srv
        ),
        _check_cipher_side(
            cell, server=False, wrapper=f"client ({client})", caps=cli_caps, mode=mode_cli
        ),
    ):
        if check:
            return check

    for dim in ("supported_groups", "signature_schemes"):
        for check in (
            _check_list_dim(
                cell, dim, server=True, wrapper=f"server ({server})", caps=srv_caps, mode=mode_srv
            ),
            _check_list_dim(
                cell, dim, server=False, wrapper=f"client ({client})", caps=cli_caps, mode=mode_cli
            ),
        ):
            if check:
                return check

    tv_single = (cell.get("tls_version") or "").strip()
    if tv_single and ":" not in tv_single:
        for wrapper, caps, mode in (
            (f"server ({server})", srv_caps, mode_srv),
            (f"client ({client})", cli_caps, mode_cli),
        ):
            block = caps.get("tls_version")
            if isinstance(block, dict) and block:
                key = "1.2" if mode == "1.2" else "1.3"
                if key not in block:
                    return f"{wrapper} lacks tls_version={key!r}"

    return None


def print_catalog_options(repo: Path | None = None) -> None:
    for item in load_options_catalog(repo):
        choices = item.get("choices") or []
        ctext = f" choices={choices}" if choices else ""
        print(f"{item.get('id')}{ctext}")


def parse_csv_values(raw: str, arg_name: str) -> list[str]:
    if not raw:
        return []
    values = [part.strip() for part in raw.split(",")]
    if any(not v for v in values):
        raise ValueError(
            f"{arg_name} must be a comma-separated list of non-empty values"
        )
    return values


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


def unsupported_cli_params(
    config: Any, backend: str, repo: Path | None = None
) -> list[str]:
    """
    Return unsupported non-empty ``TlsConfig`` fields for a backend CLI.

    Declared per wrapper in ``capabilities.json`` → ``runtime.unsupported_tls_fields``.
    """
    key = (backend or "").strip().lower()
    rt = wrapper_runtime_config(key, repo)
    extra = rt.get("unsupported_tls_fields") or ()
    if not isinstance(extra, (list, tuple)):
        return []
    bad: list[str] = []
    for field in extra:
        name = str(field).strip()
        if name and _config_has_value(config, name):
            bad.append(name)
    return bad


def catalog_parameter_conflicts(
    config: Any,
    backend: str,
    *,
    role: Any | None = None,
    capabilities: dict[str, Any] | None = None,
    repo: Path | None = None,
) -> list[str]:
    """
    Union of ``unsupported_cli_params`` and capability-translator unsupported
    entries (deduplicated, stable order).
    """
    seen: set[str] = set()
    out: list[str] = []
    for item in unsupported_cli_params(config, backend, repo):
        if item not in seen:
            seen.add(item)
            out.append(item)
    if capabilities:
        for item in tls_argv_for_config(
            config, backend, capabilities, role=role
        ).unsupported:
            if item not in seen:
                seen.add(item)
                out.append(item)
    return out


def run_args_tls_config_view(
    args: Any,
    *,
    server: bool,
) -> SimpleNamespace:
    """Build a TlsConfig-like view from host CLI ``args`` for one matrix role."""

    def pick_scalar(field: str) -> str:
        raw = getattr(args, field, None)
        if raw in (None, "", 0):
            return ""
        s = str(raw).strip()
        if ":" in s and field in ASYMMETRIC_SCALAR_OPTION_IDS:
            left, right = parse_asymmetric(s)
            return left if server else right
        return s

    def pick_list(field: str) -> list[str]:
        raw = getattr(args, field, None)
        if raw in (None, "", 0):
            return []
        s = str(raw).strip()
        if ":" in s:
            left, right = s.split(":", 1)
            part = left if server else right
        else:
            part = s
        return [p.strip() for p in part.split(",") if p.strip()]

    version = pick_scalar("tls_version") or "1.3"
    return SimpleNamespace(
        version=version,
        cipher_suite=pick_scalar("cipher_suite"),
        supported_groups=pick_list("supported_groups"),
        signature_schemes=pick_list("signature_schemes"),
        alpn_protocols=pick_list("alpn_protocols"),
        psk_modes=sorted(
            parse_test_features_enabled(",".join(pick_list("test_features")))
        ),
        ca_file=(getattr(args, "ca_file", None) or "") or "",
        certificate=getattr(args, "certificate_pem", None),
        private_key=getattr(args, "private_key_pem", None),
    )


def _validate_wrapper_config_conflicts(
    args: Any,
    *,
    known_wrappers: frozenset[str],
) -> None:
    from proto import interop_pb2

    for attr, role in (("server", interop_pb2.SERVER), ("client", interop_pb2.CLIENT)):
        wid = (getattr(args, attr, None) or "").strip().lower()
        if not wid or wid not in known_wrappers:
            continue
        caps = load_capabilities(wid)
        view = run_args_tls_config_view(args, server=(role == interop_pb2.SERVER))
        conflicts = catalog_parameter_conflicts(
            view, wid, role=role, capabilities=caps
        )
        if conflicts:
            raise ValueError(
                f"{attr} wrapper {wid!r} cannot apply requested parameter(s): "
                f"{', '.join(conflicts)}"
            )


def validate_run_args(
    args: Any,
    *,
    known_wrappers: frozenset[str],
    repo: Path | None = None,
) -> None:
    if args.server not in known_wrappers:
        raise ValueError(
            f"Unknown --server '{args.server}'. Known: {sorted(known_wrappers)}"
        )
    if args.client not in known_wrappers:
        raise ValueError(
            f"Unknown --client '{args.client}'. Known: {sorted(known_wrappers)}"
        )
    if not (0 <= int(args.tls_port) <= 65535):
        raise ValueError("--tls-port must be in range 0..65535")

    for item in load_options_catalog(repo):
        option_id = item["id"]
        if option_id in NON_TLS_OPTION_IDS:
            continue
        value = getattr(args, option_id, None)
        if value in (None, "", 0):
            continue
        if option_id == "tls_port" and int(value) == 0:
            continue

        arg_name = f"--{option_id.replace('_', '-')}"
        choices = item.get("choices") or []

        if option_id in MULTI_VALUE_OPTION_IDS:
            raw = str(value).strip()
            if ":" in raw:
                left_s, right_s = raw.split(":", 1)
                values = parse_csv_values(left_s, arg_name) + parse_csv_values(
                    right_s, arg_name
                )
            else:
                values = parse_csv_values(raw, arg_name)
            if choices:
                tokens = option_choice_tokens(item)
                unknown = sorted(x for x in values if x not in tokens)
                if unknown:
                    raise ValueError(
                        f"{arg_name} unknown value(s): {', '.join(unknown)}. "
                        f"Known: {', '.join(tokens)}"
                    )
            if option_id == "alpn_protocols":
                alpn_re = re.compile(r"^[A-Za-z0-9._/+:-]{1,255}$")
                invalid_alpn = sorted(x for x in values if not alpn_re.fullmatch(x))
                if invalid_alpn:
                    raise ValueError(
                        "--alpn-protocols contains invalid token(s): "
                        f"{', '.join(invalid_alpn)}"
                    )
            continue

        if not choices:
            continue

        if option_id in ASYMMETRIC_SCALAR_OPTION_IDS:
            tokens = option_choice_tokens(item)
            for part in parse_asymmetric(str(value)):
                if part and part not in tokens:
                    raise ValueError(
                        f"{arg_name} must use catalog values; unknown: {part!r}. "
                        f"Known: {', '.join(tokens)}"
                    )
        elif str(value).strip() not in option_choice_tokens(item):
            raise ValueError(
                f"{arg_name} must be one of: {', '.join(option_choice_tokens(item))}"
            )

    coerce_tls_version_for_cipher_capabilities(args, repo)
    _validate_cipher_suite_for_tls_version(args, known_wrappers=known_wrappers, repo=repo)
    _validate_wrapper_config_conflicts(args, known_wrappers=known_wrappers)


def _validate_cipher_suite_for_tls_version(
    args: Any,
    *,
    known_wrappers: frozenset[str],
    repo: Path | None = None,
) -> None:
    """Reject explicit ``--cipher-suite`` tokens that exist only for another TLS version."""
    mode = tls_mode_filter_from_args(args)
    if mode is None:
        return
    raw = str(getattr(args, "cipher_suite", "") or "").strip()
    if not raw or re.match(r"(?is)^ALL", raw):
        return

    root = repo or repository_root()
    wr = sorted(known_wrappers)
    active: set[str] = set()
    for token in (str(args.server or ""), str(args.client or "")):
        t = token.strip()
        if not t:
            continue
        if re.match(r"(?is)^ALL", t):
            active |= set(wr)
        else:
            for part in expand_dimension(t, wr):
                if part in known_wrappers:
                    active.add(part)
    if not active:
        active = set(wr)

    caps_cache = load_capabilities_cache(active, root)
    allowed = set(
        union_cipher_suite_ids_for_wrappers(caps_cache, sorted(active), mode=mode)
    )

    def _check_part(part: str) -> None:
        p = (part or "").strip()
        if not p or p in allowed:
            return
        raise ValueError(
            f"--cipher-suite {p!r} is not available for TLS {mode} "
            f"(see tls{mode.replace('.', '')} in capabilities.json)"
        )

    if ":" in raw:
        left, right = raw.split(":", 1)
        for part in parse_csv_values(left, "--cipher-suite"):
            _check_part(part)
        for part in parse_csv_values(right, "--cipher-suite"):
            _check_part(part)
    else:
        for part in expand_dimension(raw, sorted(allowed)):
            _check_part(part)


def matrix_axis_plan(
    args: Any,
    *,
    known_wrappers: frozenset[str],
    repo: Path | None = None,
) -> tuple[list[str], list[list[Any]]]:
    """Capability-driven matrix axes (ALL/SKIP, TLS 1.2/1.3)."""
    root = repo or repository_root()
    wr = sorted(known_wrappers)
    caps_cache = load_capabilities_cache(known_wrappers, root)
    catalog = load_options_catalog(root)

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
            vals.append(
                expand_capability_dimension(
                    raw,
                    oid,
                    wrapper_ids=sorted(matrix_wrappers),
                    caps_by_wrapper=caps_cache,
                    catalog_choices=tokens,
                    tls_mode=(
                        cipher_tls_mode if oid == "cipher_suite" else None
                    ),
                )
            )
        elif tokens:
            vals.append(expand_dimension(raw, tokens))
        else:
            if raw in (None, "", 0):
                vals.append([""])
            else:
                vals.append([str(raw)])
    return keys, vals

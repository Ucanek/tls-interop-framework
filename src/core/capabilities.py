"""Backend registry, ``capabilities.json`` loading, and catalog token helpers."""

from __future__ import annotations

import importlib
import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Sequence

from core.matrix_cell import MatrixCell
from core.tls_config_view import RoleLike, TlsConfigLike
from core.utils import norm_catalog_token

TlsMode = Literal["1.2", "1.3"]

DEFAULT_CIPHER_BY_TLS_MODE: dict[TlsMode, str] = {"1.3": "aes-128-gcm", "1.2": "ecdhe-rsa-aes-128-gcm-sha256"}

STATIC_CLI_OPTIONS: tuple[dict[str, Any], ...] = (
    {"id": "cipher_suite", "description": "Cipher suite catalog id (per-backend mapping in capabilities.json)."},
    {"id": "tls_version", "description": "TLS protocol version for the endpoint (TlsConfig.version)."},
    {"id": "tls_port", "description": "TLS data-plane port override (default scenario value is 5555)."},
    {"id": "supported_groups", "description": "Advertised/allowed key exchange groups (supported_groups extension)."},
    {"id": "signature_schemes", "description": "Advertised TLS signature algorithms."},
    {"id": "alpn", "description": "ALPN protocol identifiers offered by the endpoint (e.g. h2, http/1.1)."},
    {"id": "test_features", "description": ("Credentials for special ciphers (psk, anonymous). "
        "cipher_suite ALL includes PSK/anon suites; without enabling a feature here, "
        "those cells are pre-SKIP (Feature disabled). "
        "Set test_features: psk,anonymous (or YAML map with true values) to run them.")})

OPTION_GROUPS: dict[str, str] = {
    "tls_port": "basic", "cipher_suite": "crypto", "tls_version": "protocol", "supported_groups": "crypto",
    "signature_schemes": "crypto", "alpn": "protocol", "test_features": "crypto"}

NON_TLS_OPTION_IDS: frozenset[str] = frozenset({"server_wrapper", "client_wrapper"})
NON_MATRIX_OPTION_IDS: frozenset[str] = frozenset({"test_features"})
MULTI_VALUE_OPTION_IDS: frozenset[str] = frozenset({"supported_groups", "signature_schemes", "alpn", "test_features"})
ASYMMETRIC_SCALAR_OPTION_IDS: frozenset[str] = frozenset({"cipher_suite", "tls_version"})
ASYMMETRIC_HELP_OPTION_IDS: frozenset[str] = frozenset({"cipher_suite", "signature_schemes", "supported_groups",
    "tls_version", "alpn"})
CAPABILITY_DIMENSIONS: frozenset[str] = frozenset({"cipher_suite", "supported_groups", "signature_schemes",
    "tls_version", "alpn"})
TLS13_ORTHOGONAL_DIMS: frozenset[str] = frozenset({"supported_groups", "signature_schemes"})


def repository_root() -> Path:
    """Repository root (directory containing ``interop_proto/interop_pb2.py``)."""
    cur = Path(__file__).resolve().parent
    while True:
        if (cur / "interop_proto" / "interop_pb2.py").is_file():
            return cur
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
    p = Path(__file__).resolve()
    for candidate in (p.parents[2], p.parents[1]):
        if (candidate / "interop_proto" / "interop_pb2.py").is_file():
            return candidate
    return p.parents[2]


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


def load_capabilities(backend_name: str, repo: Path | None = None) -> dict[str, Any]:
    name = (backend_name or "").strip().lower()
    path = wrappers_plugin_dir(repo or repository_root()) / name / "capabilities.json"
    if not path.is_file():
        raise FileNotFoundError(f"capabilities.json not found for backend {name!r}: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"capabilities.json must be a JSON object: {path}")
    return data


_RUNTIME_DEFAULTS: dict[str, Any] = {"grpc_addr": None, "tls_host": "127.0.0.1", "tls_port": 15551,
    "unsupported_tls_fields": (), "local_cli": ()}


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


def wrapper_runtime_config(backend_name: str, repo: Path | None = None) -> dict[str, Any]:
    """Per-wrapper ``runtime`` section from ``capabilities.json``."""
    return wrapper_runtime(load_capabilities(backend_name, repo))


def load_wrapper_module(backend_name: str) -> Any:
    """Import ``wrappers.<backend>.wrapper`` (optional plugin hooks live there)."""
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
    cli = wrapper_runtime(capabilities).get("local_cli") or ()
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


def wrapper_local_env(backend_name: str, repo: Path, active_backends: frozenset[str] | set[str]) -> dict[str, str]:
    out = call_wrapper_hook(backend_name, "local_wrapper_env", repo, backend_name, active_backends)
    return dict(out) if isinstance(out, dict) else {}


def merged_orchestration_env(active_backends: Iterable[str]) -> dict[str, str]:
    """Union env fragments from every active wrapper's ``orchestration_env`` hook."""
    active = frozenset((b or "").strip().lower() for b in active_backends if (b or "").strip())
    merged: dict[str, str] = {}
    for backend in sorted(active):
        merged.update(wrapper_orchestration_env(backend, active))
    return merged


def session_wrapper_env(backend_name: str, repo: Path, active_backends: Iterable[str]) -> dict[str, str]:
    """Orchestration + per-wrapper env for one wrapper subprocess."""
    active = frozenset((b or "").strip().lower() for b in active_backends if (b or "").strip())
    merged = dict(merged_orchestration_env(active))
    merged.update(wrapper_local_env(backend_name, repo, active))
    return merged


def backend_grpc_addr(backend_name: str, repo: Path | None = None, *, port_override: int | None = None) -> str:
    rt = wrapper_runtime_config(backend_name, repo)
    addr = rt.get("grpc_addr")
    if not isinstance(addr, str) or not addr.strip():
        raise ValueError(f"capabilities.runtime.grpc_addr missing for backend {backend_name!r}")
    addr = addr.strip()
    if port_override:
        host, _, _ = addr.rpartition(":")
        return f"{host or '127.0.0.1'}:{int(port_override)}"
    return addr


def grpc_port_overrides_from_args(args: Any) -> dict[str, int]:
    """Per-backend gRPC port overrides from ``--server-grpc-port`` / ``--client-grpc-port``."""
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
    rt = wrapper_runtime_config(backend_name, repo)
    host = str(rt.get("tls_host") or "127.0.0.1")
    port = int(rt.get("tls_port") or 15551)
    return host, port


def check_local_cli_tools(backends: Iterable[str], repo: Path | None = None) -> list[str]:
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


def load_backend_component(backend_name: str, repo: Path | None = None) -> tuple[Any, dict[str, Any]]:
    """
    Import ``wrappers.<backend>.wrapper`` and load ``capabilities.json``.

    Returns ``(wrapper_module, capabilities)``.
    """
    name = (backend_name or "").strip().lower()
    capabilities = load_capabilities(name, repo)
    module = importlib.import_module(f"wrappers.{name}.wrapper")
    return module, capabilities


def load_backend(backend_name: str, repo: Path | None = None) -> tuple[Any, dict[str, Any]]:
    """Alias for :func:`load_backend_component`."""
    return load_backend_component(backend_name, repo)


def load_capabilities_cache(wrapper_ids: frozenset[str] | set[str],
    repo: Path | None = None) -> dict[str, dict[str, Any]]:
    return {wid: load_capabilities(wid, repo) for wid in wrapper_ids}


def cipher_maps_from_capabilities(capabilities: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    """Return (tls13_map, tls12_map) catalog_id → raw CLI string."""
    t13 = capabilities.get("tls13") if isinstance(capabilities.get("tls13"), dict) else {}
    t12 = capabilities.get("tls12") if isinstance(capabilities.get("tls12"), dict) else {}
    m13 = dict(t13.get("cipher_suite") or {}) if isinstance(t13.get("cipher_suite"), dict) else {}
    m12 = dict(t12.get("cipher_suite") or {}) if isinstance(t12.get("cipher_suite"), dict) else {}
    return ({str(k): str(v) for k, v in m13.items() if v},
        {str(k): str(v) for k, v in m12.items() if v})


def all_cipher_suite_ids(capabilities: dict[str, Any]) -> list[str]:
    m13, m12 = cipher_maps_from_capabilities(capabilities)
    return sorted(set(m13) | set(m12))


def cipher_suite_ids_for_mode(capabilities: dict[str, Any], mode: TlsMode) -> list[str]:
    """Catalog cipher ids declared under ``tls13`` or ``tls12`` for ``mode``."""
    m13, m12 = cipher_maps_from_capabilities(capabilities)
    mp = m13 if mode == "1.3" else m12
    return sorted(str(k) for k in mp.keys() if k)


def union_cipher_suite_ids_for_wrappers(caps_by_wrapper: dict[str, dict[str, Any]],
    wrapper_ids: Sequence[str], *, mode: TlsMode | None = None) -> list[str]:
    """Union of cipher catalog ids across wrappers, optionally restricted to one TLS mode."""
    keys: set[str] = set()
    for wid in wrapper_ids:
        caps = caps_by_wrapper.get(wid, {})
        if mode is None:
            keys.update(all_cipher_suite_ids(caps))
        else:
            keys.update(cipher_suite_ids_for_mode(caps, mode))
    return sorted(keys)


def default_cipher_for_tls_mode(mode: TlsMode, *, allowed: set[str] | frozenset[str]) -> str:
    """One catalog cipher when ``cipher_suite`` is omitted; prefer scenario defaults."""
    preferred = DEFAULT_CIPHER_BY_TLS_MODE.get(mode, "")
    if preferred and preferred in allowed:
        return preferred
    return sorted(allowed)[0] if allowed else ""


def backend_cipher_modes(capabilities: dict[str, Any], catalog_id: str) -> set[TlsMode]:
    m13, m12 = cipher_maps_from_capabilities(capabilities)
    key = norm_catalog_token(catalog_id)
    modes: set[TlsMode] = set()
    if key in m13 or catalog_id in m13:
        modes.add("1.3")
    if key in m12 or catalog_id in m12:
        modes.add("1.2")
    return modes


def backend_supports_cipher(capabilities: dict[str, Any], catalog_id: str, mode: TlsMode) -> bool:
    m13, m12 = cipher_maps_from_capabilities(capabilities)
    key = norm_catalog_token(catalog_id)
    mp = m13 if mode == "1.3" else m12
    return key in mp or catalog_id in mp


def capability_dimension_name(option_id: str) -> str:
    """Map CLI/matrix option id to the matching ``capabilities.json`` block key."""
    if (option_id or "").strip() == "alpn":
        return "alpn_protocols"
    return (option_id or "").strip()


def _capability_block_meta_keys() -> frozenset[str]:
    return frozenset({"supported", "wired", "description"})


def _capability_token_supported(block: dict[str, Any], token: str) -> bool:
    if block.get("supported") is False:
        return False
    key = norm_catalog_token(token)
    entry = block.get(key) if key in block else block.get(token)
    if isinstance(entry, dict) and entry.get("supported") is False:
        return False
    return key in block or token in block


def dimension_keys(capabilities: dict[str, Any], dimension: str, *, tls_mode: TlsMode | None = None) -> list[str]:
    if dimension == "cipher_suite":
        if tls_mode is not None:
            return cipher_suite_ids_for_mode(capabilities, tls_mode)
        return all_cipher_suite_ids(capabilities)
    block = capabilities.get(dimension)
    if not isinstance(block, dict):
        return []
    if block.get("supported") is False:
        return []
    meta = _capability_block_meta_keys()
    out: list[str] = []
    for key, entry in block.items():
        if key in meta:
            continue
        if isinstance(entry, dict) and entry.get("supported") is False:
            continue
        out.append(str(key))
    return sorted(out)


def backend_supports_token(capabilities: dict[str, Any], dimension: str,
    token: str, *, mode: TlsMode | None = None) -> bool:
    if dimension == "cipher_suite":
        if mode is None:
            return bool(backend_cipher_modes(capabilities, token))
        return backend_supports_cipher(capabilities, token, mode)
    block = capabilities.get(dimension)
    if not isinstance(block, dict):
        return False
    return _capability_token_supported(block, token)


def aggregate_union(repo: Path, wrapper_ids: tuple[str, ...] | frozenset[str]) -> dict[str, list[str]]:
    """Union of catalog token ids across backends (for CLI choices)."""
    cipher: set[str] = set()
    groups: set[str] = set()
    sigs: set[str] = set()
    alpn: set[str] = set()
    for wid in wrapper_ids:
        caps = load_capabilities(wid, repo)
        cipher.update(all_cipher_suite_ids(caps))
        groups.update(dimension_keys(caps, "supported_groups"))
        sigs.update(dimension_keys(caps, "signature_schemes"))
        alpn.update(dimension_keys(caps, "alpn_protocols"))
    test_feats: set[str] = set()
    for wid in wrapper_ids:
        test_feats.update(test_feature_ids(load_capabilities(wid, repo)))
    return {"cipher_suite": sorted(cipher), "supported_groups": sorted(groups), "signature_schemes": sorted(sigs),
        "alpn": sorted(alpn), "test_features": sorted(test_feats), "tls_version": ["1.2", "1.3"]}


def is_cipher_tls13_only(capabilities: dict[str, Any], catalog_id: str) -> bool:
    return backend_cipher_modes(capabilities, catalog_id) == {"1.3"}


def is_cipher_tls12_only(capabilities: dict[str, Any], catalog_id: str) -> bool:
    return backend_cipher_modes(capabilities, catalog_id) == {"1.2"}


def metadata_from_capabilities(capabilities: dict[str, Any], *,
    component_name: str | None = None) -> tuple[list[tuple[str, bool]], list[str], list[str]]:
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


def tls_argv_for_config(config: TlsConfigLike, backend: str, capabilities: dict[str, Any],
    *, role: RoleLike | None = None) -> TranslationResult:
    """Delegate argv translation to ``wrappers.<backend>.wrapper.tls_argv_for_config``."""
    name = (backend or "").strip().lower()
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


def option_choice_tokens(item: dict[str, Any]) -> list[str]:
    """CLI/matrix tokens for a catalog option."""
    ch = item.get("choices") or []
    return [str(c).strip() for c in ch if str(c).strip()]


def print_catalog_options(repo: Path | None = None) -> None:
    log = logging.getLogger(__name__)
    for item in load_options_catalog(repo):
        choices = item.get("choices") or []
        ctext = f" choices={choices}" if choices else ""
        log.info("%s%s", item.get("id"), ctext)


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
    return frozenset(p.strip().lower() for p in str(raw).split(",") if p.strip())


def enabled_test_features_from_cell(cell: MatrixCell) -> frozenset[str]:
    return parse_test_features_enabled(cell.test_features)


def psk_key_bits_for_cipher(cipher_id: str) -> int:
    """PSK key length implied by catalog cipher id (128-bit vs 256-bit suites)."""
    c = norm_catalog_token(cipher_id)
    if "chacha20" in c:
        return 256
    if re.search(r"(?:aes|aria|camellia)(?:-)?256|[-/]256[-/](?:gcm|ccm|cbc)|[-]256[-](?:gcm|ccm|cbc)", c):
        return 256
    return 128


def psk_secret_hex_for_cipher(capabilities: dict[str, Any], cipher_id: str) -> str | None:
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


def psk_material_from_capabilities(capabilities: dict[str, Any], cipher_id: str) -> tuple[str, str] | None:
    entry = test_feature_entry(capabilities, "psk")
    identity = str(entry.get("identity") or "interop").strip()
    secret_hex = psk_secret_hex_for_cipher(capabilities, cipher_id)
    if not secret_hex:
        return None
    return identity, secret_hex


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


def cipher_catalog_id_requires_identity_pem(cipher_id: str) -> bool:
    """
    True when the server must present a leaf certificate matching the cipher auth.

    Excludes anonymous suites and static PSK (``psk-aes-*``); includes RSA/ECDSA/EdDSA
    ciphers and hybrid ``*-psk`` suites that combine certificates with PSK.
    """
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

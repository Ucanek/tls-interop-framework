"""CLI option catalog, validation, and matrix expansion."""

from __future__ import annotations

import importlib
import json
import re
import shutil
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Literal, Optional, Sequence, Set, Tuple

TlsMode = Literal["1.2", "1.3"]

STATIC_CLI_OPTIONS: Tuple[Dict[str, Any], ...] = (
    {
        "id": "cipher_suite",
        "description": "Cipher suite catalog id (per-backend mapping in capabilities.json).",
    },
    {
        "id": "tls_version",
        "description": "TLS protocol version for the endpoint (TlsConfig.version).",
    },
    {
        "id": "tls_port",
        "description": "TLS data-plane port override (default scenario value is 5555).",
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
        "id": "alpn",
        "description": "ALPN protocol identifiers offered by the endpoint (e.g. h2, http/1.1).",
    },
    {
        "id": "test_features",
        "description": (
            "Credentials for special ciphers (psk, anonymous). "
            "cipher_suite ALL includes PSK/anon suites; without enabling a feature here, "
            "those cells are pre-SKIP (Feature disabled). "
            "Set test_features: psk,anonymous (or YAML map with true values) to run them."
        ),
    },
)

NON_TLS_OPTION_IDS: frozenset[str] = frozenset({"server_wrapper", "client_wrapper"})
NON_MATRIX_OPTION_IDS: frozenset[str] = frozenset({"test_features"})

CAPABILITY_DIMENSIONS: frozenset[str] = frozenset(
    {"cipher_suite", "supported_groups", "signature_schemes", "tls_version", "alpn"}
)
TLS13_ORTHOGONAL_DIMS: frozenset[str] = frozenset(
    {"supported_groups", "signature_schemes"}
)

DEFAULT_CIPHER_BY_TLS_MODE: Dict[TlsMode, str] = {
    "1.3": "aes-128-gcm",
    "1.2": "ecdhe-rsa-aes-128-gcm-sha256",
}

RUNTIME_DEFAULTS: Dict[str, Any] = {
    "grpc_addr": None,
    "tls_host": "127.0.0.1",
    "tls_port": 15551,
    "unsupported_tls_fields": (),
    "local_cli": (),
}


def repository_root() -> Path:
    """Walk from this file up until ``interop_proto/interop_pb2.py`` is found."""
    cur = Path(__file__).resolve().parent
    while True:
        if (cur / "interop_proto" / "interop_pb2.py").is_file():
            return cur
        if cur.parent == cur:
            raise FileNotFoundError(
                "Could not locate repository root containing interop_proto directory")
        cur = cur.parent


@dataclass(frozen=True)
class TranslationResult:
    argv: Tuple[str, ...]
    unsupported: Tuple[str, ...]


def load_local_capabilities(wrapper_file: str) -> Dict[str, Any]:
    path = Path(wrapper_file).resolve().parent / "capabilities.json"
    if not path.is_file():
        raise FileNotFoundError(f"capabilities.json not found: {path}")

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"capabilities.json must be a JSON object: {path}")

    return data


def tls_argv_for_config(
    config: Any,
    backend: str,
    capabilities: Dict[str, Any],
    role: Optional[Any] = None
) -> TranslationResult:
    name = (backend or "").strip().lower()
    mod = importlib.import_module(f"wrappers.{name}.wrapper")
    fn = getattr(mod, "tls_argv_for_config", None)
    if fn is None:
        return TranslationResult((), (f"(backend {name!r} has no tls_argv_for_config)",))

    return fn(config, role=role, capabilities=capabilities)


def build_cli_options_catalog(repo: Optional[Path] = None) -> List[Dict[str, Any]]:
    root = repo or repository_root()
    union = aggregate_union(root, discover_wrapper_ids(root))
    output: List[Dict[str, Any]] = []

    for template in STATIC_CLI_OPTIONS:
        item = dict(template)
        option_id = item["id"]
        if option_id in union:
            item["choices"] = list(union[option_id])
        output.append(item)

    return output


def discover_wrapper_ids(repo: Path) -> Tuple[str, ...]:
    plugin_dir = repo / "wrappers"
    if not plugin_dir.is_dir():
        return ()

    found: List[str] = []
    for path in sorted(plugin_dir.iterdir()):
        if not path.is_dir():
            continue
        if (path / "wrapper.py").is_file() and (path / "capabilities.json").is_file():
            found.append(path.name)

    return tuple(found)


def _capability_token_supported(block: Dict[str, Any], token: str) -> bool:
    if block.get("supported") is False:
        return False

    key = norm_catalog_token(token)
    entry = block.get(key) if key in block else block.get(token)
    if isinstance(entry, dict) and entry.get("supported") is False:
        return False

    return key in block or token in block


def _cipher_suite_map_from_tls_block(tls_block: Any) -> Dict[str, str]:
    if not isinstance(tls_block, dict):
        return {}
    raw = tls_block.get("cipher_suite")
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items() if v}


@dataclass(frozen=True)
class BackendCapabilities:
    raw: Dict[str, Any]

    def runtime(self) -> Dict[str, Any]:
        raw_runtime = self.raw.get("runtime")
        if not isinstance(raw_runtime, dict):
            raw_runtime = {}

        output = dict(RUNTIME_DEFAULTS)
        for key in RUNTIME_DEFAULTS:
            if key in raw_runtime and raw_runtime[key] is not None:
                output[key] = raw_runtime[key]

        return output

    def cipher_maps(self) -> Tuple[Dict[str, str], Dict[str, str]]:
        return (
            _cipher_suite_map_from_tls_block(self.raw.get("tls13")),
            _cipher_suite_map_from_tls_block(self.raw.get("tls12")))

    def cipher_ids(self, mode: Optional[TlsMode] = None) -> List[str]:
        m13, m12 = self.cipher_maps()
        if mode is None:
            return sorted(set(m13) | set(m12))

        selected_map = m13 if mode == "1.3" else m12
        return sorted(str(k) for k in selected_map.keys() if k)

    def cipher_modes(self, catalog_id: str) -> Set[TlsMode]:
        m13, m12 = self.cipher_maps()
        key = norm_catalog_token(catalog_id)
        modes: Set[TlsMode] = set()

        if key in m13 or catalog_id in m13:
            modes.add("1.3")
        if key in m12 or catalog_id in m12:
            modes.add("1.2")

        return modes

    def supports_cipher(self, catalog_id: str, mode: TlsMode) -> bool:
        m13, m12 = self.cipher_maps()
        key = norm_catalog_token(catalog_id)
        selected_map = m13 if mode == "1.3" else m12

        return key in selected_map or catalog_id in selected_map

    def supports_token(self, dimension: str, token: str, tls_mode: Optional[TlsMode] = None) -> bool:
        if dimension == "cipher_suite":
            if tls_mode is None:
                return bool(self.cipher_modes(token))
            return self.supports_cipher(token, tls_mode)

        block = self.raw.get(dimension)
        if not isinstance(block, dict):
            return False

        return _capability_token_supported(block, token)

    def dimension_keys(self, dimension: str, tls_mode: Optional[TlsMode] = None) -> List[str]:
        if dimension == "cipher_suite":
            return self.cipher_ids(tls_mode)

        block = self.raw.get(dimension)
        if not isinstance(block, dict) or block.get("supported") is False:
            return []

        meta_keys = frozenset({"supported", "wired", "description"})
        output: List[str] = []
        for key, entry in block.items():
            if key in meta_keys:
                continue
            if isinstance(entry, dict) and entry.get("supported") is False:
                continue
            output.append(str(key))

        return sorted(output)

    def feature_block(self) -> Dict[str, Any]:
        block = self.raw.get("test_features")
        return block if isinstance(block, dict) else {}

    def feature_entry(self, name: str) -> Dict[str, Any]:
        entry = self.feature_block().get(name)
        return entry if isinstance(entry, dict) else {}

    def feature_ids(self) -> frozenset[str]:
        output: Set[str] = set()
        for key, entry in self.feature_block().items():
            if isinstance(entry, dict) and entry.get("supported", False):
                output.add(str(key).strip().lower())

        return frozenset(x for x in output if x)

    def psk_secret_hex(self, cipher_id: str) -> Optional[str]:
        entry = self.feature_entry("psk")
        bits = psk_key_bits_for_cipher(cipher_id)
        field = "secret_hex_256" if bits >= 256 else "secret_hex_128"

        secret_hex = str(entry.get(field) or entry.get("secret_hex") or "").strip()
        if not secret_hex or len(secret_hex) != bits // 4:
            return None

        return secret_hex

    def psk_material(self, cipher_id: str) -> Optional[Tuple[str, str]]:
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


def local_cli_requirements(backend_name: str, capabilities: Dict[str, Any]) -> Tuple[str, ...]:
    req = call_wrapper_hook(backend_name, "local_cli_requirements")
    if req is not None:
        return tuple(str(x) for x in req)

    cli = BackendCapabilities(capabilities).runtime().get("local_cli") or ()
    return tuple(str(x) for x in cli)


def resolve_wrapper_cli_tool(backend_name: str, exe: str) -> Optional[str]:
    resolved = call_wrapper_hook(backend_name, "resolve_cli_tool", exe)
    if resolved:
        return str(resolved)

    return shutil.which(exe)


def wrapper_orchestration_env(
    backend_name: str,
    active_backends: frozenset[str] | Set[str]
) -> Dict[str, str]:
    output = call_wrapper_hook(backend_name, "orchestration_env", active_backends)
    return dict(output) if isinstance(output, dict) else {}


def wrapper_local_env(
    backend_name: str,
    repo: Path,
    active_backends: frozenset[str] | Set[str],
    slot_id: Optional[int] = None
) -> Dict[str, str]:
    output = call_wrapper_hook(
        backend_name,
        "local_wrapper_env",
        repo,
        backend_name,
        active_backends,
        slot_id=slot_id
    )
    return dict(output) if isinstance(output, dict) else {}


def merged_orchestration_env(active_backends: Iterable[str]) -> Dict[str, str]:
    active = frozenset((b or "").strip().lower() for b in active_backends if (b or "").strip())
    merged: Dict[str, str] = {}
    for backend in sorted(active):
        merged.update(wrapper_orchestration_env(backend, active))

    return merged


def session_wrapper_env(
    backend_name: str,
    repo: Path,
    active_backends: Iterable[str],
    slot_id: Optional[int] = None
) -> Dict[str, str]:
    active = frozenset((b or "").strip().lower() for b in active_backends if (b or "").strip())
    merged = dict(merged_orchestration_env(active))
    merged.update(wrapper_local_env(backend_name, repo, active, slot_id=slot_id))

    return merged


def backend_grpc_addr(
    backend_name: str,
    repo: Optional[Path] = None,
    port_override: Optional[int] = None
) -> str:
    runtime_info = load_backend_capabilities(backend_name).runtime()
    addr = runtime_info.get("grpc_addr")
    if not isinstance(addr, str) or not addr.strip():
        raise ValueError(f"capabilities.runtime.grpc_addr missing for backend {backend_name!r}")

    addr = addr.strip()
    if port_override:
        host, _, _ = addr.rpartition(":")
        return f"{host or '127.0.0.1'}:{int(port_override)}"

    return addr


def grpc_port_overrides_from_args(args: Any) -> Dict[str, int]:
    output: Dict[str, int] = {}

    def maybe_add_override(role: str, port: int) -> None:
        if not port:
            return
        wrapper_id = (getattr(args, role, None) or "").strip().lower()
        if not wrapper_id or wrapper_id == "all" or "," in wrapper_id or "\\" in wrapper_id:
            return
        output[wrapper_id] = port

    maybe_add_override("server", int(getattr(args, "server_grpc_port", 0) or 0))
    maybe_add_override("client", int(getattr(args, "client_grpc_port", 0) or 0))
    return output


def backend_tls_endpoint(backend_name: str, repo: Optional[Path] = None) -> Tuple[str, int]:
    runtime_info = load_backend_capabilities(backend_name).runtime()
    host = str(runtime_info.get("tls_host") or "127.0.0.1")
    port = int(runtime_info.get("tls_port") or 15551)

    return host, port


def check_local_cli_tools(backends: Iterable[str], repo: Optional[Path] = None) -> List[str]:
    missing: List[str] = []
    for backend in backends:
        key = (backend or "").strip().lower()
        caps = load_backend_capabilities(key)
        for exe in local_cli_requirements(key, caps.raw):
            if resolve_wrapper_cli_tool(key, exe) is None:
                missing.append(f"{key}: {exe} not found")

    return missing


def union_cipher_suite_ids_for_wrappers(
    caps_by_wrapper: Dict[str, Dict[str, Any]],
    wrapper_ids: Sequence[str],
    mode: Optional[TlsMode] = None
) -> List[str]:
    keys: Set[str] = set()
    for wrapper_id in wrapper_ids:
        capabilities = BackendCapabilities(caps_by_wrapper.get(wrapper_id, {}))
        keys.update(capabilities.cipher_ids(mode))

    return sorted(keys)


def default_cipher_for_tls_mode(mode: TlsMode, allowed: set[str] | frozenset[str]) -> str:
    preferred = DEFAULT_CIPHER_BY_TLS_MODE.get(mode, "")
    if preferred and preferred in allowed:
        return preferred

    return sorted(allowed)[0] if allowed else ""


def tls_mode_filter_from_args(args: Any) -> Optional[TlsMode]:
    raw_version = str(getattr(args, "tls_version", "") or "").strip()
    if not raw_version:
        return None

    if ":" in raw_version:
        left, right = parse_asymmetric(raw_version)
        if left and right and tls_mode_from_version(left) == tls_mode_from_version(right):
            return tls_mode_from_version(left)
        return None

    return tls_mode_from_version(raw_version)


def capability_dimension_name(option_id: str) -> str:
    if (option_id or "").strip() == "alpn":
        return "alpn_protocols"

    return (option_id or "").strip()


def aggregate_union(repo: Path, wrapper_ids: Tuple[str, ...] | frozenset[str]) -> Dict[str, List[str]]:
    cipher_set: Set[str] = set()
    groups_set: Set[str] = set()
    sigs_set: Set[str] = set()
    alpn_set: Set[str] = set()
    test_feats_set: Set[str] = set()

    for wrapper_id in wrapper_ids:
        capabilities = load_backend_capabilities(wrapper_id)
        cipher_set.update(capabilities.cipher_ids())
        groups_set.update(capabilities.dimension_keys("supported_groups"))
        sigs_set.update(capabilities.dimension_keys("signature_schemes"))
        alpn_set.update(capabilities.dimension_keys("alpn_protocols"))
        test_feats_set.update(capabilities.feature_ids())

    return {
        "cipher_suite": sorted(cipher_set),
        "supported_groups": sorted(groups_set),
        "signature_schemes": sorted(sigs_set),
        "alpn": sorted(alpn_set),
        "test_features": sorted(test_feats_set),
        "tls_version": ["1.2", "1.3"],
    }


def parse_asymmetric(val: Optional[str]) -> Tuple[str, str]:
    value = (val or "").strip()
    if ":" in value:
        left, right = value.split(":", 1)
        return left.strip(), right.strip()

    return value, value


def asymmetric_role_part(val: Optional[str], server: bool) -> str:
    left, right = parse_asymmetric(val)
    return left if server else right


def split_csv_tokens(part: str) -> List[str]:
    return [p.strip() for p in (part or "").split(",") if p.strip()]


def norm_catalog_token(raw: str) -> str:
    return (raw or "").strip().lower().replace(" ", "")


def tls_mode_from_version(version: Optional[str]) -> TlsMode:
    if not (version or "").strip():
        return "1.3"

    folded = norm_catalog_token(version or "").replace(".", "").replace("-", "").replace("_", "")
    if "13" in folded:
        return "1.3"
    if "12" in folded:
        return "1.2"

    return "1.3"


def option_choice_tokens(item: Dict[str, Any]) -> List[str]:
    choices = item.get("choices") or []
    return [str(c).strip() for c in choices if str(c).strip()]


def _coerce_cipher_tls13_only(cipher_side: str, ver_side: str, caps: Dict[str, Any]) -> Optional[str]:
    if tls_mode_from_version(ver_side) != "1.2":
        return None

    cipher_id = (cipher_side or "").strip()
    if not cipher_id:
        return None

    if BackendCapabilities(caps).cipher_modes(cipher_id) == {"1.3"}:
        return "1.3"

    return None


def _coerce_asymmetric_tls_version(
    cs_str: str,
    tv_str: str,
    srv_caps: Dict[str, Any],
    cli_caps: Dict[str, Any]
) -> Optional[str]:
    cs_left, cs_right = parse_asymmetric(cs_str)
    tv_left, tv_right = parse_asymmetric(tv_str)
    new_left = _coerce_cipher_tls13_only(cs_left, tv_left, srv_caps)
    new_right = _coerce_cipher_tls13_only(cs_right, tv_right, cli_caps)

    if new_left or new_right:
        return f"{new_left or tv_left}:{new_right or tv_right}"

    return None


def _load_role_capabilities(server: str, client: str) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    try:
        srv_caps = load_backend_capabilities(server).raw if server else {}
        cli_caps = load_backend_capabilities(client).raw if client else {}
    except (FileNotFoundError, ValueError):
        return None
    return srv_caps, cli_caps


def _apply_coerced_tls_version(args: Any, new_ver: Optional[str], warning_msg: str) -> None:
    if not new_ver:
        return
    print(warning_msg, file=sys.stderr)
    setattr(args, "tls_version", new_ver)


def _parse_coerce_tls_inputs(args: Any) -> Optional[Tuple[str, str, str, str]]:
    cs_raw = getattr(args, "cipher_suite", None)
    tv_raw = getattr(args, "tls_version", None)
    if cs_raw in (None, "", 0) or tv_raw in (None, "", 0):
        return None
    cs_str = str(cs_raw).strip()
    tv_str = str(tv_raw).strip()
    if not cs_str or not tv_str:
        return None
    server = (getattr(args, "server", None) or "").strip().lower()
    client = (getattr(args, "client", None) or "").strip().lower()
    return cs_str, tv_str, server, client


def coerce_tls_version_for_cipher_capabilities(args: Any, repo: Optional[Path] = None) -> None:
    parsed = _parse_coerce_tls_inputs(args)
    if parsed is None:
        return
    cs_str, tv_str, server, client = parsed
    loaded = _load_role_capabilities(server, client)
    if loaded is None:
        return
    srv_caps, cli_caps = loaded

    warning_msg = (
        "[catalog] TLS 1.3-only cipher with --tls-version 1.2: "
        "adjusting protocol version to 1.3 to avoid handshake mismatch.")

    if ":" in cs_str or ":" in tv_str:
        _apply_coerced_tls_version(
            args, _coerce_asymmetric_tls_version(cs_str, tv_str, srv_caps, cli_caps), warning_msg)
        return

    caps = srv_caps if server else cli_caps
    _apply_coerced_tls_version(
        args, _coerce_cipher_tls13_only(cs_str, tv_str, caps), warning_msg)


def _expand_all_subtraction(value: str, base_choices: List[str]) -> Optional[List[str]]:
    match = re.match(r"(?is)^ALL\s*[\\-]\s*(.+)$", value)
    if not match:
        return None

    exclusions = {x.strip() for x in match.group(1).split(",") if x.strip()}
    output = [x for x in base_choices if x not in exclusions]
    if not output:
        raise ValueError(f"ALL minus exclusions leaves empty set: {value!r}")

    return output


def _expand_csv_dimension_tokens(val: str, base_choices: List[str]) -> List[str]:
    parts = [x.strip() for x in val.split(",") if x.strip()]
    if not parts:
        raise ValueError(f"Empty dimension value: {val!r}")
    invalid_parts = [p for p in parts if p not in base_choices]
    if invalid_parts:
        known_str = ", ".join(sorted(set(base_choices)))
        raise ValueError(f"Unknown value(s) {invalid_parts!r}; known: {known_str}")
    return parts


def _expand_dimension_all_forms(val: str, base_choices: List[str]) -> Optional[List[str]]:
    if re.match(r"(?is)^ALL\s*$", val):
        return list(base_choices)
    return _expand_all_subtraction(val, base_choices)


def expand_dimension(value: str, choices: Sequence[str]) -> List[str]:
    base_choices = [str(c).strip() for c in choices if c and str(c).strip()]
    val = (value or "").strip()

    if not base_choices:
        return [val] if val else [""]
    if not val:
        return [""]

    special = _expand_dimension_all_forms(val, base_choices)
    if special is not None:
        return special
    if ":" in val:
        return [val]
    return _expand_csv_dimension_tokens(val, base_choices)


def expand_alpn_matrix_axis(
    value: str,
    wrapper_ids: Sequence[str],
    caps_by_wrapper: Dict[str, Dict[str, Any]],
    catalog_choices: Sequence[str]
) -> List[str]:
    val = (value or "").strip()
    if not val:
        return [""]

    tokens = expand_capability_dimension(
        val,
        "alpn_protocols",
        wrapper_ids=wrapper_ids,
        caps_by_wrapper=caps_by_wrapper,
        catalog_choices=catalog_choices
    )
    if ":" in val:
        return tokens
    if not tokens or tokens == [""]:
        return [""]

    return [f"{srv}:{cli}" for srv in tokens for cli in tokens]


def _union_capability_keys(
    dimension: str,
    wrapper_ids: Sequence[str],
    caps_by_wrapper: Dict[str, Dict[str, Any]],
    cipher_mode: Optional[TlsMode]
) -> Set[str]:
    if dimension == "cipher_suite" and cipher_mode is not None:
        return set(union_cipher_suite_ids_for_wrappers(caps_by_wrapper, wrapper_ids, mode=cipher_mode))

    keys: Set[str] = set()
    for wrapper_id in wrapper_ids:
        bc = BackendCapabilities(caps_by_wrapper.get(wrapper_id, {}))
        keys.update(bc.dimension_keys(dimension, tls_mode=cipher_mode))

    return keys


def _expand_cap_dim_all_subtraction(
    value: str,
    dimension: str,
    wrapper_ids: Sequence[str],
    caps_by_wrapper: Dict[str, Dict[str, Any]],
    catalog_tokens: List[str],
    cipher_mode: Optional[TlsMode]
) -> Optional[List[str]]:
    sub = re.match(r"(?is)^ALL\s*[\\-]\s*(.+)$", value)
    if not sub:
        return None

    exclusions = {x.strip() for x in sub.group(1).split(",") if x.strip()}
    keys = _union_capability_keys(dimension, wrapper_ids=wrapper_ids, caps_by_wrapper=caps_by_wrapper, cipher_mode=cipher_mode)
    if not keys:
        keys = set(catalog_tokens)

    output = sorted(k for k in keys if k not in exclusions)
    if not output:
        raise ValueError(f"ALL minus exclusions leaves empty set: {value!r}")

    return output


def _filter_expanded_cipher_suite(
    expanded: List[str],
    val: str,
    cipher_mode: TlsMode,
    wrapper_ids: Sequence[str],
    caps_by_wrapper: Dict[str, Dict[str, Any]]
) -> List[str]:
    allowed = set(union_cipher_suite_ids_for_wrappers(caps_by_wrapper, wrapper_ids, mode=cipher_mode))
    filtered = [x for x in expanded if x in allowed]

    if filtered:
        return filtered

    if not val:
        default = default_cipher_for_tls_mode(cipher_mode, allowed=allowed)
        return [default] if default else [""]

    if not re.match(r"(?is)^ALL", val):
        return expanded if expanded else [val]

    return []


def _expand_cap_dim_all(
    dimension: str,
    wrapper_ids: Sequence[str],
    caps_by_wrapper: Dict[str, Dict[str, Any]],
    catalog_tokens: List[str],
    cipher_mode: Optional[TlsMode]
) -> List[str]:
    keys = _union_capability_keys(
        dimension, wrapper_ids=wrapper_ids, caps_by_wrapper=caps_by_wrapper, cipher_mode=cipher_mode)
    return sorted(keys) if keys else list(catalog_tokens)


def _expand_cap_dim_tokens(
    val: str,
    dimension: str,
    wrapper_ids: Sequence[str],
    caps_by_wrapper: Dict[str, Dict[str, Any]],
    catalog_tokens: List[str],
    cipher_mode: Optional[TlsMode]
) -> List[str]:
    if ":" in val:
        return [val]
    expanded = expand_dimension(val, catalog_tokens)
    if dimension == "cipher_suite" and cipher_mode is not None:
        return _filter_expanded_cipher_suite(
            expanded, val, cipher_mode, wrapper_ids, caps_by_wrapper)
    return expanded


def expand_capability_dimension(
    value: str,
    dimension: str,
    wrapper_ids: Sequence[str],
    caps_by_wrapper: Dict[str, Dict[str, Any]],
    catalog_choices: Sequence[str],
    tls_mode: Optional[TlsMode] = None
) -> List[str]:
    val = (value or "").strip()
    catalog_tokens = [str(c).strip() for c in catalog_choices if c and str(c).strip()]
    cipher_mode = tls_mode if dimension == "cipher_suite" else None

    if re.match(r"(?is)^ALL\s*$", val):
        return _expand_cap_dim_all(
            dimension, wrapper_ids, caps_by_wrapper, catalog_tokens, cipher_mode)

    subtracted = _expand_cap_dim_all_subtraction(
        val, dimension, wrapper_ids, caps_by_wrapper, catalog_tokens, cipher_mode)
    if subtracted is not None:
        return subtracted
    return _expand_cap_dim_tokens(
        val, dimension, wrapper_ids, caps_by_wrapper, catalog_tokens, cipher_mode)


def _cell_cipher_id(cell: Dict[str, str], server: bool) -> str:
    cipher_suite = (cell.get("cipher_suite") or "").strip()
    if not cipher_suite:
        return ""

    if ":" in cipher_suite:
        left, right = cipher_suite.split(":", 1)
        return (left if server else right).strip()

    return cipher_suite


def effective_cell_tls_mode(cell: Dict[str, str], srv_caps: Dict[str, Any], cli_caps: Dict[str, Any]) -> TlsMode:
    tv = (cell.get("tls_version") or "").strip()
    if tv and ":" not in tv:
        return tls_mode_from_version(tv)

    if tv and ":" in tv:
        left, _ = parse_asymmetric(tv)
        if left:
            return tls_mode_from_version(left)

    srv_cipher = _cell_cipher_id(cell, server=True)
    cli_cipher = _cell_cipher_id(cell, server=False)
    modes: Set[TlsMode] = set()

    for cid, caps in ((srv_cipher, srv_caps), (cli_cipher, cli_caps)):
        if cid:
            modes |= BackendCapabilities(caps).cipher_modes(cid)

    if modes == {"1.2"}:
        return "1.2"

    return "1.3"


def _implicit_tls_version_for_side(cell: Dict[str, str], server: bool, caps: Dict[str, Any]) -> str:
    cipher_id = _cell_cipher_id(cell, server=server)
    if not cipher_id:
        return ""

    modes = BackendCapabilities(caps).cipher_modes(cipher_id)
    if modes == {"1.3"}:
        return "1.3"
    if modes == {"1.2"}:
        return "1.2"

    return ""


def _apply_implicit_tls_version(output: Dict[str, str], srv_caps: Dict[str, Any], cli_caps: Dict[str, Any]) -> None:
    if (output.get("tls_version") or "").strip():
        return

    srv_ver = _implicit_tls_version_for_side(output, server=True, caps=srv_caps)
    cli_ver = _implicit_tls_version_for_side(output, server=False, caps=cli_caps)
    if srv_ver or cli_ver:
        if srv_ver and cli_ver and srv_ver != cli_ver:
            output["tls_version"] = f"{srv_ver}:{cli_ver}"
        else:
            output["tls_version"] = srv_ver or cli_ver


def _clear_unset_tls13_orthogonal_dims(output: Dict[str, str], args_template: Any) -> None:
    for dim in TLS13_ORTHOGONAL_DIMS:
        user_raw = str(getattr(args_template, dim, "") or "").strip()
        if not user_raw:
            output[dim] = ""


def _apply_cell_tls_version_coerce(
    output: Dict[str, str], server: str, client: str, repo: Path) -> None:
    coerce_ns = SimpleNamespace(
        server=server, client=client,
        cipher_suite=output.get("cipher_suite", ""), tls_version=output.get("tls_version", ""))
    coerce_tls_version_for_cipher_capabilities(coerce_ns, repo)
    bumped_ver = str(getattr(coerce_ns, "tls_version", "") or "").strip()
    if bumped_ver:
        output["tls_version"] = bumped_ver


def normalize_cell_tls_micro_params(cell: Dict[str, str], args_template: Any, repo: Path) -> Dict[str, str]:
    output = dict(cell)
    port = int(getattr(args_template, "tls_port", 0) or 0)
    if port:
        output["tls_port"] = str(port)

    server = (cell.get("server") or "").strip().lower()
    client = (cell.get("client") or "").strip().lower()
    loaded = _load_role_capabilities(server, client)
    if loaded is None:
        return output
    srv_caps, cli_caps = loaded

    _apply_implicit_tls_version(output, srv_caps, cli_caps)
    feats = str(getattr(args_template, "test_features", "") or "").strip()
    if effective_cell_tls_mode(output, srv_caps, cli_caps) == "1.2":
        _clear_unset_tls13_orthogonal_dims(output, args_template)
    output["test_features"] = feats
    _apply_cell_tls_version_coerce(output, server, client, repo)
    return output


def _check_cipher_side(cell: Dict[str, str], server: bool, wrapper: str, caps: Dict[str, Any], mode: TlsMode) -> Optional[str]:
    cipher_id = _cell_cipher_id(cell, server=server)
    if not cipher_id:
        return None

    bc = BackendCapabilities(caps)
    if bc.supports_cipher(cipher_id, mode):
        return None

    modes = bc.cipher_modes(cipher_id)
    if not modes:
        return f"{wrapper} lacks cipher_suite={cipher_id!r}"

    modes_str = ", ".join(sorted(modes))
    return f"{wrapper} lacks cipher_suite={cipher_id!r} for TLS {mode} (supported modes: {modes_str})"


def _check_list_dim(
    cell: Dict[str, str],
    dim: str,
    server: bool,
    wrapper: str,
    caps: Dict[str, Any],
    mode: TlsMode
) -> Optional[str]:
    if mode == "1.2" and dim in TLS13_ORTHOGONAL_DIMS:
        raw_val = (cell.get(dim) or "").strip()
        if not raw_val:
            return None

    tokens = _split_cell_list_tokens(cell, dim, server=server)
    if not tokens:
        return None

    cap_dim = capability_dimension_name(dim)
    bc = BackendCapabilities(caps)
    for tok in tokens:
        if not bc.supports_token(cap_dim, tok, tls_mode=mode):
            return f"{wrapper} lacks {dim}={tok!r}"

    return None


@dataclass(frozen=True)
class Tls12CipherMetadata:
    kx: Literal["ecdhe", "dhe", "static-rsa", "unknown"]
    au: Literal["rsa", "ecdsa", "dsa", "unknown"]


def _split_cell_list_tokens(cell: Dict[str, str], field: str, server: bool) -> List[str]:
    return split_csv_tokens(asymmetric_role_part(cell.get(field), server=server))


def _tls12_kx_from_token(tok: str) -> Literal["ecdhe", "dhe", "static-rsa", "unknown"]:
    if "ecdhe" in tok:
        return "ecdhe"
    if re.search(r"(^|-)dhe(-|$)", tok):
        return "dhe"
    if "rsa" in tok or tok.startswith("aes"):
        return "static-rsa"
    return "unknown"


def _tls12_au_from_token(tok: str) -> Literal["rsa", "ecdsa", "dsa", "unknown"]:
    if re.search(r"(^|-)dss(-|$)", tok):
        return "dsa"
    if "ecdsa" in tok:
        return "ecdsa"
    if "rsa" in tok or tok.startswith("aes"):
        return "rsa"
    return "unknown"


def tls12_cipher_metadata_from_name(cipher_name: str) -> Tls12CipherMetadata:
    raw = (cipher_name or "").strip().lower()
    tok = raw.replace("_", "-").replace(" ", "")
    if not tok or tok.startswith("tls-"):
        return Tls12CipherMetadata(kx="unknown", au="unknown")
    return Tls12CipherMetadata(kx=_tls12_kx_from_token(tok), au=_tls12_au_from_token(tok))


def cipher_catalog_id_requires_psk(cipher_id: str) -> bool:
    c = norm_catalog_token(cipher_id)
    return bool(re.search(r"(^|-)psk(-|$)", c))


def cipher_catalog_id_requires_anon(cipher_id: str) -> bool:
    c = norm_catalog_token(cipher_id)
    return "anon" in c.split("-") or c.startswith("adh-")


def cipher_required_test_feature(cipher_id: str) -> Optional[str]:
    if cipher_catalog_id_requires_psk(cipher_id):
        return "psk"
    if cipher_catalog_id_requires_anon(cipher_id):
        return "anonymous"

    return None


def cipher_catalog_id_requires_identity_pem(cipher_id: str) -> bool:
    c = norm_catalog_token(cipher_id)
    if not c or cipher_catalog_id_requires_anon(c):
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


def _required_server_identity_prefix(cell: Dict[str, str]) -> Optional[str]:
    from core.identity import get_cert_prefix_for_scheme, get_cert_prefix_for_schemes

    schemes = _split_cell_list_tokens(cell, "signature_schemes", server=True)
    if schemes:
        return get_cert_prefix_for_schemes(schemes)

    cipher = _cell_cipher_id(cell, server=True)
    if not cipher or not cipher_catalog_id_requires_identity_pem(cipher):
        return None

    return get_cert_prefix_for_scheme(cipher)


def parse_test_features_enabled(raw: str) -> frozenset[str]:
    if not (raw or "").strip():
        return frozenset()

    return frozenset(p.strip().lower() for p in str(raw).split(",") if p.strip())


def psk_key_bits_for_cipher(cipher_id: str) -> int:
    c = norm_catalog_token(cipher_id)
    if "chacha20" in c:
        return 256

    aes256_pattern = r"(?:aes|aria|camellia)(?:-)?256|[-/]256[-/](?:gcm|ccm|cbc)|[-]256[-](?:gcm|ccm|cbc)"
    if re.search(aes256_pattern, c):
        return 256

    return 128


def _signature_scheme_auth_kind(token: str) -> Literal["rsa", "ecdsa", "dsa", "eddsa", "unknown"]:
    t = (token or "").strip().lower().replace("_", "").replace("-", "")
    if not t:
        return "unknown"
    if t.startswith("dsa"):
        return "dsa"
    if "rsa" in t:
        return "rsa"
    if "ecdsa" in t:
        return "ecdsa"
    if t.startswith(("ed25519", "ed448", "eddsa")):
        return "eddsa"
    return "unknown"


def _group_family(token: str) -> Literal["ec", "ffdhe", "other"]:
    t = (token or "").strip().lower().replace("_", "-")
    if not t:
        return "other"

    if t.startswith("ffdhe"):
        return "ffdhe"

    ec_prefixes = ("secp", "x25519", "x448", "brainpool", "xyber", "mlkem")
    if t.startswith(ec_prefixes) or "mlkem" in t:
        return "ec"

    return "other"


def _check_tls12_group_semantics(cipher_id: str, grp_tokens: List[str]) -> Optional[str]:
    if not grp_tokens:
        return None

    meta = tls12_cipher_metadata_from_name(cipher_id)
    if meta.kx == "static-rsa":
        return "TLS 1.2 static RSA cipher does not support groups"

    if meta.kx == "ecdhe" and any(_group_family(g) != "ec" for g in grp_tokens):
        return "TLS 1.2 ECDHE cipher requires EC groups (secp*/x25519/x448)"

    if meta.kx == "dhe" and any(_group_family(g) != "ffdhe" for g in grp_tokens):
        return "TLS 1.2 DHE cipher requires FFDHE groups"

    return None


def _check_tls12_sig_semantics(cipher_id: str, sig_tokens: List[str]) -> Optional[str]:
    if not sig_tokens:
        return None

    meta = tls12_cipher_metadata_from_name(cipher_id)
    if meta.au == "unknown":
        return None

    for sig in sig_tokens:
        sk = _signature_scheme_auth_kind(sig)
        if sk != "unknown" and meta.au != sk:
            return "Signature scheme type conflicts with TLS 1.2 cipher authentication"

    return None


def _tls12_semantic_skip_reason_side(cell: Dict[str, str], server: bool, mode: TlsMode) -> Optional[str]:
    if mode != "1.2":
        return None

    cipher_id = _cell_cipher_id(cell, server=server)
    if not cipher_id:
        return None

    grp_tokens = _split_cell_list_tokens(cell, "supported_groups", server=server)
    sig_tokens = _split_cell_list_tokens(cell, "signature_schemes", server=server)

    return (
        _check_tls12_group_semantics(cipher_id, grp_tokens)
        or _check_tls12_sig_semantics(cipher_id, sig_tokens)
    )


@dataclass(frozen=True)
class _CellSkipCtx:
    cell: Dict[str, str]
    repo: Path
    server: str
    client: str
    srv_caps: Dict[str, Any]
    cli_caps: Dict[str, Any]
    mode_srv: TlsMode
    mode_cli: TlsMode


def _feature_entry_skip(
    feat: str,
    role_label: str,
    caps: Dict[str, Any],
    wired_msg: Optional[str] = None
) -> Optional[str]:
    entry = BackendCapabilities(caps).feature_entry(feat)
    if not entry.get("wired", False):
        return wired_msg or f"Feature {feat} is not wired in {role_label} wrapper"
    if not entry.get("supported", False):
        return f"Feature {feat} is not supported in {role_label} wrapper"

    return None


def _semantic_skip_reason(ctx: _CellSkipCtx) -> Optional[str]:
    return (
        _tls12_semantic_skip_reason_side(ctx.cell, server=True, mode=ctx.mode_srv)
        or _tls12_semantic_skip_reason_side(ctx.cell, server=False, mode=ctx.mode_cli)
    )


def _enabled_features_skip_reason(
    enabled: frozenset[str], roles: Tuple[Tuple[str, Dict[str, Any]], ...]) -> Optional[str]:
    for feat in sorted(enabled):
        for role_label, caps in roles:
            reason = _feature_entry_skip(feat, role_label, caps)
            if reason:
                return reason
    return None


def _cipher_required_feature_skip_reason(
    ctx: _CellSkipCtx, enabled: frozenset[str],
    roles: Tuple[Tuple[str, Dict[str, Any]], ...]) -> Optional[str]:
    cid = _cell_cipher_id(ctx.cell, server=True) or _cell_cipher_id(ctx.cell, server=False)
    if not cid:
        return None
    feat = cipher_required_test_feature(cid)
    if not feat:
        return None
    if feat not in enabled:
        return "Feature disabled"
    for role_label, caps in roles:
        reason = _feature_entry_skip(feat, role_label, caps, wired_msg="Not wired")
        if reason:
            return reason
    return None


def _feature_skip_reason(ctx: _CellSkipCtx) -> Optional[str]:
    roles = (
        (f"server ({ctx.server})", ctx.srv_caps),
        (f"client ({ctx.client})", ctx.cli_caps))
    enabled = parse_test_features_enabled(str(ctx.cell.get("test_features") or ""))
    return (
        _enabled_features_skip_reason(enabled, roles)
        or _cipher_required_feature_skip_reason(ctx, enabled, roles))


def _identity_skip_reason(ctx: _CellSkipCtx) -> Optional[str]:
    from core.identity import identity_pem_present

    prefix = _required_server_identity_prefix(ctx.cell)
    if not prefix or identity_pem_present(prefix, repo=ctx.repo):
        return None

    return f"Missing identity PEM: certs/{prefix}.crt and certs/{prefix}.key"


def _expect_hrr_skip_reason(ctx: _CellSkipCtx) -> Optional[str]:
    if (ctx.cell.get("expect_hrr") or "").strip().lower() not in ("true", "1", "yes"):
        return None

    unsupported = BackendCapabilities(ctx.cli_caps).runtime().get("unsupported_tls_fields") or ()
    blocked = frozenset(str(x).strip() for x in unsupported)
    if "expect_hrr" in blocked:
        return f"client ({ctx.client}) does not support expect_hrr"

    return None


def _cipher_skip_reason(ctx: _CellSkipCtx) -> Optional[str]:
    return (
        _check_cipher_side(
            ctx.cell, server=True, wrapper=f"server ({ctx.server})", caps=ctx.srv_caps, mode=ctx.mode_srv
        )
        or _check_cipher_side(
            ctx.cell, server=False, wrapper=f"client ({ctx.client})", caps=ctx.cli_caps, mode=ctx.mode_cli
        )
    )


def _dimension_skip_reason(ctx: _CellSkipCtx) -> Optional[str]:
    for dim in ("supported_groups", "signature_schemes", "alpn"):
        reason = (
            _check_list_dim(
                ctx.cell, dim, server=True, wrapper=f"server ({ctx.server})", caps=ctx.srv_caps, mode=ctx.mode_srv
            )
            or _check_list_dim(
                ctx.cell, dim, server=False, wrapper=f"client ({ctx.client})", caps=ctx.cli_caps, mode=ctx.mode_cli
            )
        )
        if reason:
            return reason

    return None


def _tls_version_skip_reason(ctx: _CellSkipCtx) -> Optional[str]:
    tv = (ctx.cell.get("tls_version") or "").strip()
    if not tv or ":" in tv:
        return None

    wrappers = (
        (f"server ({ctx.server})", ctx.srv_caps, ctx.mode_srv),
        (f"client ({ctx.client})", ctx.cli_caps, ctx.mode_cli),
    )
    for wrapper, caps, mode in wrappers:
        block = caps.get("tls_version")
        if isinstance(block, dict) and block:
            key = "1.2" if mode == "1.2" else "1.3"
            if key not in block:
                return f"{wrapper} lacks tls_version={key!r}"

    return None


def _resolve_cell_tls_modes(
    cell: Dict[str, str], srv_caps: Dict[str, Any], cli_caps: Dict[str, Any]
) -> Tuple[TlsMode, TlsMode]:
    mode_srv = effective_cell_tls_mode(cell, srv_caps, cli_caps)
    mode_cli = mode_srv
    tv = (cell.get("tls_version") or "").strip()
    if tv and ":" in tv:
        lv, rv = parse_asymmetric(tv)
        if lv:
            mode_srv = tls_mode_from_version(lv)
        if rv:
            mode_cli = tls_mode_from_version(rv)
    return mode_srv, mode_cli


def cell_capability_skip_reason(cell: Dict[str, str], repo: Path) -> Optional[str]:
    server = (cell.get("server") or "").strip().lower()
    client = (cell.get("client") or "").strip().lower()
    if not server or not client:
        return None

    try:
        srv_caps = load_backend_capabilities(server).raw
        cli_caps = load_backend_capabilities(client).raw
    except (FileNotFoundError, ValueError) as exc:
        return str(exc)

    mode_srv, mode_cli = _resolve_cell_tls_modes(cell, srv_caps, cli_caps)
    ctx = _CellSkipCtx(
        cell=cell, repo=repo, server=server, client=client,
        srv_caps=srv_caps, cli_caps=cli_caps, mode_srv=mode_srv, mode_cli=mode_cli)
    for check in (
        _semantic_skip_reason,
        _feature_skip_reason,
        _identity_skip_reason,
        _expect_hrr_skip_reason,
        _cipher_skip_reason,
        _dimension_skip_reason,
        _tls_version_skip_reason):
        reason = check(ctx)
        if reason:
            return reason
    return None


def print_catalog_options(repo: Optional[Path] = None) -> None:
    for item in build_cli_options_catalog(repo):
        choices = item.get("choices") or []
        ctext = f" choices={choices}" if choices else ""
        print(f"{item.get('id')}{ctext}")


def _iterable_field_has_value(raw: Any) -> bool:
    return any(str(x).strip() for x in raw)


def _config_has_value(config: Any, field: str) -> bool:
    raw = getattr(config, field, None)
    if raw is None:
        return False
    if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes, bytearray)):
        return _iterable_field_has_value(raw)
    if isinstance(raw, Iterable) and not isinstance(raw, (str, bytes, bytearray, dict)):
        return _iterable_field_has_value(raw)
    if isinstance(raw, bytes):
        return bool(raw.strip())
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return raw != 0
    return bool(str(raw).strip())


def unsupported_cli_params(config: Any, backend: str, repo: Optional[Path] = None) -> List[str]:
    key = (backend or "").strip().lower()
    runtime_info = load_backend_capabilities(key).runtime()
    extra_fields = runtime_info.get("unsupported_tls_fields") or ()

    if not isinstance(extra_fields, (list, tuple)):
        return []

    bad: List[str] = []
    for field in extra_fields:
        name = str(field).strip()
        if name and _config_has_value(config, name):
            bad.append(name)

    return bad


def catalog_parameter_conflicts(
    config: Any,
    backend: str,
    role: Optional[Any] = None,
    capabilities: Optional[Dict[str, Any]] = None,
    repo: Optional[Path] = None
) -> List[str]:
    seen: Set[str] = set()
    output: List[str] = []

    for item in unsupported_cli_params(config, backend, repo):
        if item not in seen:
            seen.add(item)
            output.append(item)

    if capabilities:
        for item in tls_argv_for_config(config, backend, capabilities, role=role).unsupported:
            if item not in seen:
                seen.add(item)
                output.append(item)

    return output


def validate_run_args(
    args: Any,
    known_wrappers: Optional[frozenset[str]] = None,
    repo: Optional[Path] = None
) -> None:
    _ = (known_wrappers, repo)
    if not (0 <= int(args.tls_port) <= 65535):
        raise ValueError("--tls-port must be in range 0..65535")

    for attr in ("server_grpc_port", "client_grpc_port"):
        if not (0 <= int(getattr(args, attr, 0) or 0) <= 65535):
            flag_name = attr.replace('_', '-')
            raise ValueError(f"--{flag_name} must be in range 0..65535")


def _get_dimension_matrix_values(
    item: Dict[str, Any],
    args: Any,
    matrix_wrappers: Set[str],
    caps_cache: Dict[str, Dict[str, Any]],
    cipher_tls_mode: Optional[TlsMode]
) -> List[Any]:
    option_id = item["id"]
    tokens = option_choice_tokens(item) if item.get("choices") else []
    raw_val = str(getattr(args, option_id, "") or "")

    if option_id in CAPABILITY_DIMENSIONS and tokens:
        if option_id == "alpn":
            return expand_alpn_matrix_axis(
                raw_val,
                wrapper_ids=sorted(matrix_wrappers),
                caps_by_wrapper=caps_cache,
                catalog_choices=tokens
            )
        mode = cipher_tls_mode if option_id == "cipher_suite" else None
        return expand_capability_dimension(
            raw_val,
            capability_dimension_name(option_id),
            wrapper_ids=sorted(matrix_wrappers),
            caps_by_wrapper=caps_cache,
            catalog_choices=tokens,
            tls_mode=mode
        )

    if tokens:
        return expand_dimension(raw_val, tokens)

    return [""] if raw_val in (None, "", 0) else [str(raw_val)]


def matrix_axis_plan(
    args: Any,
    known_wrappers: frozenset[str],
    repo: Optional[Path] = None
) -> Tuple[List[str], List[List[Any]]]:
    root = repo or repository_root()
    wrappers_sorted = sorted(known_wrappers)
    caps_cache = {wid: load_backend_capabilities(wid).raw for wid in known_wrappers}
    catalog = build_cli_options_catalog(root)

    keys = ["server", "client"]
    server_vals = expand_dimension(str(args.server), wrappers_sorted)
    client_vals = expand_dimension(str(args.client), wrappers_sorted)
    vals: List[List[Any]] = [server_vals, client_vals]

    matrix_wrappers = set(server_vals) | set(client_vals)
    cipher_tls_mode = tls_mode_filter_from_args(args)

    for item in sorted(catalog, key=lambda x: str(x.get("id", ""))):
        option_id = item["id"]
        if option_id in NON_TLS_OPTION_IDS or option_id == "tls_port" or option_id in NON_MATRIX_OPTION_IDS:
            continue

        keys.append(option_id)
        vals.append(_get_dimension_matrix_values(item, args, matrix_wrappers, caps_cache, cipher_tls_mode))

    return keys, vals
"""Backend capabilities loading, wrapper discovery, and catalog token helpers."""

from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any, Literal

TlsMode = Literal["1.2", "1.3"]

STATIC_CLI_OPTIONS: tuple[dict[str, Any], ...] = (
    {"id": "cipher_suite",
     "description": "Cipher suite catalog id (per-backend mapping in capabilities.json)."},
    {"id": "tls_version",
     "description": "TLS protocol version for the endpoint (TlsConfig.version)."},
    {"id": "tls_port",
     "description": "TLS data-plane port override (default scenario value is 5555)."},
    {"id": "supported_groups",
     "description": "Advertised/allowed key exchange groups (supported_groups extension)."},
    {"id": "signature_schemes",
     "description": "Advertised TLS signature algorithms."},
    {"id": "alpn",
     "description": "ALPN protocol identifiers offered by the endpoint (e.g. h2, http/1.1)."},
    {"id": "test_features",
     "description": (
         "Credentials for special ciphers (psk, anonymous). "
         "cipher_suite ALL includes PSK/anon suites; without enabling a feature here, "
         "those cells are pre-SKIP (Feature disabled). "
         "Set test_features: psk,anonymous (or YAML map with true values) to run them.")})

NON_TLS_OPTION_IDS: frozenset[str] = frozenset({"server_wrapper", "client_wrapper"})
NON_MATRIX_OPTION_IDS: frozenset[str] = frozenset({"test_features"})

CAPABILITY_DIMENSIONS: frozenset[str] = frozenset(
    {"cipher_suite", "supported_groups", "signature_schemes", "tls_version", "alpn"})
TLS13_ORTHOGONAL_DIMS: frozenset[str] = frozenset({"supported_groups", "signature_schemes"})

DEFAULT_CIPHER_BY_TLS_MODE: dict[TlsMode, str] = {
    "1.3": "aes-128-gcm", "1.2": "ecdhe-rsa-aes-128-gcm-sha256"}

RUNTIME_DEFAULTS: dict[str, Any] = {
    "grpc_addr": None, "tls_host": "127.0.0.1", "tls_port": 15551,
    "unsupported_tls_fields": (), "local_cli": ()}


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


def tls_argv_for_config(
    config: Any, backend: str, capabilities: dict[str, Any], role: Any | None = None) -> TranslationResult:
    name = (backend or "").strip().lower()
    mod = importlib.import_module(f"wrappers.{name}.wrapper")
    fn = getattr(mod, "tls_argv_for_config", None)
    if fn is None:
        return TranslationResult((), (f"(backend {name!r} has no tls_argv_for_config)",))

    return fn(config, role=role, capabilities=capabilities)


def build_cli_options_catalog(repo: Path | None = None) -> list[dict[str, Any]]:
    root = repo or repository_root()
    union = aggregate_union(root, discover_wrapper_ids(root))
    output: list[dict[str, Any]] = []

    for template in STATIC_CLI_OPTIONS:
        item = dict(template)
        option_id = item["id"]
        if option_id in union:
            item["choices"] = list(union[option_id])
        output.append(item)

    return output


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


def _capability_token_supported(block: dict[str, Any], token: str) -> bool:
    if block.get("supported") is False:
        return False

    key = norm_catalog_token(token)
    entry = block.get(key) if key in block else block.get(token)
    if isinstance(entry, dict) and entry.get("supported") is False:
        return False

    return key in block or token in block


def _cipher_suite_map_from_tls_block(tls_block: Any) -> dict[str, str]:
    if not isinstance(tls_block, dict):
        return {}
    raw = tls_block.get("cipher_suite")
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items() if v}


@dataclass(frozen=True)
class BackendCapabilities:
    raw: dict[str, Any]

    def runtime(self) -> dict[str, Any]:
        raw_runtime = self.raw.get("runtime")
        if not isinstance(raw_runtime, dict):
            raw_runtime = {}

        output = dict(RUNTIME_DEFAULTS)
        for key in RUNTIME_DEFAULTS:
            if key in raw_runtime and raw_runtime[key] is not None:
                output[key] = raw_runtime[key]

        return output

    def cipher_maps(self) -> tuple[dict[str, str], dict[str, str]]:
        return (
            _cipher_suite_map_from_tls_block(self.raw.get("tls13")),
            _cipher_suite_map_from_tls_block(self.raw.get("tls12")))

    def cipher_ids(self, mode: TlsMode | None = None) -> list[str]:
        m13, m12 = self.cipher_maps()
        if mode is None:
            return sorted(set(m13) | set(m12))

        selected_map = m13 if mode == "1.3" else m12
        return sorted(str(k) for k in selected_map.keys() if k)

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
        selected_map = m13 if mode == "1.3" else m12

        return key in selected_map or catalog_id in selected_map

    def supports_token(self, dimension: str, token: str, tls_mode: TlsMode | None = None) -> bool:
        if dimension == "cipher_suite":
            if tls_mode is None:
                return bool(self.cipher_modes(token))
            return self.supports_cipher(token, tls_mode)

        block = self.raw.get(dimension)
        if not isinstance(block, dict):
            return False

        return _capability_token_supported(block, token)

    def dimension_keys(self, dimension: str, tls_mode: TlsMode | None = None) -> list[str]:
        if dimension == "cipher_suite":
            return self.cipher_ids(tls_mode)

        block = self.raw.get(dimension)
        if not isinstance(block, dict) or block.get("supported") is False:
            return []

        meta_keys = frozenset({"supported", "wired", "description"})
        output: list[str] = []
        for key, entry in block.items():
            if key in meta_keys:
                continue
            if isinstance(entry, dict) and entry.get("supported") is False:
                continue
            output.append(str(key))

        return sorted(output)

    def feature_block(self) -> dict[str, Any]:
        block = self.raw.get("test_features")
        return block if isinstance(block, dict) else {}

    def feature_entry(self, name: str) -> dict[str, Any]:
        entry = self.feature_block().get(name)
        return entry if isinstance(entry, dict) else {}

    def feature_ids(self) -> frozenset[str]:
        output: set[str] = set()
        for key, entry in self.feature_block().items():
            if isinstance(entry, dict) and entry.get("supported", False):
                output.add(str(key).strip().lower())

        return frozenset(x for x in output if x)

    def psk_secret_hex(self, cipher_id: str) -> str | None:
        from core.features import psk_key_bits_for_cipher

        entry = self.feature_entry("psk")
        bits = psk_key_bits_for_cipher(cipher_id)
        field = "secret_hex_256" if bits >= 256 else "secret_hex_128"

        secret_hex = str(entry.get(field) or entry.get("secret_hex") or "").strip()
        if not secret_hex or len(secret_hex) != bits // 4:
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


def capability_dimension_name(option_id: str) -> str:
    if (option_id or "").strip() == "alpn":
        return "alpn_protocols"

    return (option_id or "").strip()


def aggregate_union(repo: Path, wrapper_ids: tuple[str, ...] | frozenset[str]) -> dict[str, list[str]]:
    cipher_set: set[str] = set()
    groups_set: set[str] = set()
    sigs_set: set[str] = set()
    alpn_set: set[str] = set()
    test_feats_set: set[str] = set()

    for wrapper_id in wrapper_ids:
        capabilities = load_backend_capabilities(wrapper_id)
        cipher_set.update(capabilities.cipher_ids())
        groups_set.update(capabilities.dimension_keys("supported_groups"))
        sigs_set.update(capabilities.dimension_keys("signature_schemes"))
        alpn_set.update(capabilities.dimension_keys("alpn_protocols"))
        test_feats_set.update(capabilities.feature_ids())

    return {
        "cipher_suite": sorted(cipher_set), "supported_groups": sorted(groups_set),
        "signature_schemes": sorted(sigs_set), "alpn": sorted(alpn_set),
        "test_features": sorted(test_feats_set), "tls_version": ["1.2", "1.3"]}


def parse_asymmetric(val: str | None) -> tuple[str, str]:
    value = (val or "").strip()
    if ":" in value:
        left, right = value.split(":", 1)
        return left.strip(), right.strip()

    return value, value


def asymmetric_role_part(val: str | None, server: bool) -> str:
    left, right = parse_asymmetric(val)
    return left if server else right


def split_csv_tokens(part: str) -> list[str]:
    return [p.strip() for p in (part or "").split(",") if p.strip()]


def norm_catalog_token(raw: str) -> str:
    return (raw or "").strip().lower().replace(" ", "")


def tls_mode_from_version(version: str | None) -> TlsMode:
    if not (version or "").strip():
        return "1.3"

    folded = norm_catalog_token(version or "").replace(".", "").replace("-", "").replace("_", "")
    if "13" in folded:
        return "1.3"
    if "12" in folded:
        return "1.2"

    return "1.3"


def option_choice_tokens(item: dict[str, Any]) -> list[str]:
    choices = item.get("choices") or []
    return [str(c).strip() for c in choices if str(c).strip()]


def print_catalog_options(repo: Path | None = None) -> None:
    for item in build_cli_options_catalog(repo):
        choices = item.get("choices") or []
        ctext = f" choices={choices}" if choices else ""
        print(f"{item.get('id')}{ctext}")

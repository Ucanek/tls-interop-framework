"""Catalog options, ``capabilities.json`` token unions, and CLI option metadata."""

from __future__ import annotations

import importlib
import logging
import shutil
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, Literal, cast

from core.constants import TlsFeature, TlsVersionLabel
from core.crypto_semantics import(cipher_catalog_id_requires_anon, cipher_catalog_id_requires_identity_pem,
    cipher_catalog_id_requires_psk, cipher_required_test_feature, psk_key_bits_for_cipher,
    psk_material_from_capabilities, psk_secret_hex_for_cipher)
from core.matrix_cell import MatrixCell
from core.registry import(discover_wrapper_ids, grpc_port_overrides_from_args, load_capabilities,
    load_capabilities_cache, load_local_capabilities, repository_root, wrapper_runtime, wrapper_runtime_config)
from core.registry import TranslationResult
from core.tls_config_view import RoleLike, TlsConfigLike
from core.utils import norm_catalog_token

TlsMode = Literal["1.2", "1.3"]

DEFAULT_CIPHER_BY_TLS_MODE: dict[TlsMode, str] = {
    TlsVersionLabel.V13.value: "aes-128-gcm",
    TlsVersionLabel.V12.value: "ecdhe-rsa-aes-128-gcm-sha256",
}

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
    mp = m13 if mode == TlsVersionLabel.V13.value else m12
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
        modes.add(TlsVersionLabel.V13.value)
    if key in m12 or catalog_id in m12:
        modes.add(TlsVersionLabel.V12.value)
    return modes


def backend_supports_cipher(capabilities: dict[str, Any], catalog_id: str, mode: TlsMode) -> bool:
    m13, m12 = cipher_maps_from_capabilities(capabilities)
    key = norm_catalog_token(catalog_id)
    mp = m13 if mode == TlsVersionLabel.V13.value else m12
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
        "alpn": sorted(alpn), "test_features": sorted(test_feats),
        "tls_version": [TlsVersionLabel.V12.value, TlsVersionLabel.V13.value]}


def is_cipher_tls13_only(capabilities: dict[str, Any], catalog_id: str) -> bool:
    return backend_cipher_modes(capabilities, catalog_id) == {TlsVersionLabel.V13.value}


def is_cipher_tls12_only(capabilities: dict[str, Any], catalog_id: str) -> bool:
    return backend_cipher_modes(capabilities, catalog_id) == {TlsVersionLabel.V12.value}


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


def get_wrapper_class(backend_name: str) -> type["BaseTemplateWrapper"]:
    """Return ``WRAPPER_CLASS`` from ``wrappers.<backend>.wrapper``."""
    from wrappers.base import BaseTemplateWrapper

    name = (backend_name or "").strip().lower()
    mod = importlib.import_module(f"wrappers.{name}.wrapper")
    if not hasattr(mod, "WRAPPER_CLASS"):
        raise TypeError(f"wrappers.{name}.wrapper must export WRAPPER_CLASS")
    cls = cast(type[BaseTemplateWrapper], mod.WRAPPER_CLASS)
    if not issubclass(cls, BaseTemplateWrapper):
        raise TypeError(f"wrappers.{name}.wrapper WRAPPER_CLASS must extend BaseTemplateWrapper")
    return cls


def tls_argv_for_config(config: TlsConfigLike, backend: str, capabilities: dict[str, Any],
    *, role: RoleLike | None = None) -> TranslationResult:
    cls = get_wrapper_class(backend)
    return cls.tls_argv_for_config(config, role=role, capabilities=capabilities)


def local_cli_requirements(backend_name: str, capabilities: dict[str, Any]) -> tuple[str, ...]:
    req = get_wrapper_class(backend_name).local_cli_requirements()
    if req:
        return req
    cli = wrapper_runtime(capabilities).get("local_cli") or ()
    return tuple(str(x) for x in cli)


def resolve_wrapper_cli_tool(backend_name: str, exe: str) -> str | None:
    resolved = get_wrapper_class(backend_name).resolve_cli_tool(exe)
    if resolved:
        return str(resolved)
    return shutil.which(exe)


def wrapper_orchestration_env(backend_name: str, active_backends: frozenset[str] | set[str]) -> dict[str, str]:
    cls = get_wrapper_class(backend_name)
    return dict(cls.orchestration_env(active_backends))


def wrapper_local_env(backend_name: str, repo: Path, active_backends: frozenset[str] | set[str]) -> dict[str, str]:
    cls = get_wrapper_class(backend_name)
    return dict(cls.local_wrapper_env(repo, backend_name, active_backends))


# Re-export registry and crypto helpers for existing imports.
__all__ = [
    "TranslationResult",
    "TlsMode",
    "TlsFeature",
    "repository_root",
    "discover_wrapper_ids",
    "load_capabilities",
    "load_local_capabilities",
    "get_wrapper_class",
    "tls_argv_for_config",
    "local_cli_requirements",
    "resolve_wrapper_cli_tool",
    "wrapper_orchestration_env",
    "wrapper_local_env",
    "cipher_catalog_id_requires_psk",
    "cipher_catalog_id_requires_anon",
    "cipher_catalog_id_requires_identity_pem",
    "cipher_required_test_feature",
    "psk_material_from_capabilities",
]

"""Wrapper discovery, ``capabilities.json`` loading, and runtime config."""

from __future__ import annotations

import functools
import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from core.constants import TlsVersionLabel
from core.utils import norm_catalog_token

TlsMode = Literal["1.2", "1.3"]
_CAPABILITY_BLOCK_META_KEYS = frozenset({"supported", "wired", "description"})


@dataclass(frozen=True)
class TranslationResult:
    """Backend CLI argv fragments and unsupported catalog tokens."""

    argv: tuple[str, ...]
    unsupported: tuple[str, ...]


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


def load_local_capabilities(wrapper_file: str) -> dict[str, Any]:
    """Load ``capabilities.json`` next to a ``wrapper.py`` file."""
    path = Path(wrapper_file).resolve().parent / "capabilities.json"
    if not path.is_file():
        raise FileNotFoundError(f"capabilities.json not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"capabilities.json must be a JSON object: {path}")
    return data


@functools.lru_cache(maxsize=32)
@functools.lru_cache(maxsize=32)
def load_capabilities(backend_name: str, repo: Path | None = None) -> dict[str, Any]:
    name = (backend_name or "").strip().lower()
    path = wrappers_plugin_dir(repo or repository_root()) / name / "capabilities.json"
    if not path.is_file():
        raise FileNotFoundError(
            f"capabilities.json not found for backend {name!r}: {path}"
        )
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"capabilities.json must be a JSON object: {path}")
    return data


class CapabilityRegistry:
    """Object-oriented access to ``capabilities.json`` loading and catalog queries."""

    def __init__(self, repo: Path | None = None) -> None:
        self._repo = repo

    @property
    def repo(self) -> Path:
        return self._repo if self._repo is not None else repository_root()

    def load(self, backend_name: str, repo: Path | None = None) -> dict[str, Any]:
        return load_capabilities(backend_name, repo or self.repo)

    def runtime(self, capabilities: dict[str, Any]) -> dict[str, Any]:
        return wrapper_runtime(capabilities)

    def runtime_config(
        self, backend_name: str, repo: Path | None = None
    ) -> dict[str, Any]:
        return wrapper_runtime(self.load(backend_name, repo))

    def load_cache(
        self, wrapper_ids: frozenset[str] | set[str], repo: Path | None = None
    ) -> dict[str, dict[str, Any]]:
        root = repo or self.repo
        return {wid: self.load(wid, root) for wid in wrapper_ids}

    def discover_wrappers(self, repo: Path | None = None) -> tuple[str, ...]:
        return discover_wrapper_ids(repo or self.repo)

    @staticmethod
    def cipher_maps(
        capabilities: dict[str, Any],
    ) -> tuple[dict[str, str], dict[str, str]]:
        t13 = (
            capabilities.get("tls13")
            if isinstance(capabilities.get("tls13"), dict)
            else {}
        )
        t12 = (
            capabilities.get("tls12")
            if isinstance(capabilities.get("tls12"), dict)
            else {}
        )
        m13 = (
            dict(t13.get("cipher_suite") or {})
            if isinstance(t13.get("cipher_suite"), dict)
            else {}
        )
        m12 = (
            dict(t12.get("cipher_suite") or {})
            if isinstance(t12.get("cipher_suite"), dict)
            else {}
        )
        return (
            {str(k): str(v) for k, v in m13.items() if v},
            {str(k): str(v) for k, v in m12.items() if v},
        )

    @staticmethod
    def backend_cipher_modes(
        capabilities: dict[str, Any], catalog_id: str
    ) -> set[TlsMode]:
        m13, m12 = CapabilityRegistry.cipher_maps(capabilities)
        key = norm_catalog_token(catalog_id)
        modes: set[TlsMode] = set()
        if key in m13 or catalog_id in m13:
            modes.add(TlsVersionLabel.V13.value)
        if key in m12 or catalog_id in m12:
            modes.add(TlsVersionLabel.V12.value)
        return modes

    @staticmethod
    def backend_supports_cipher(
        capabilities: dict[str, Any], catalog_id: str, mode: TlsMode
    ) -> bool:
        m13, m12 = CapabilityRegistry.cipher_maps(capabilities)
        key = norm_catalog_token(catalog_id)
        mp = m13 if mode == TlsVersionLabel.V13.value else m12
        return key in mp or catalog_id in mp

    @staticmethod
    def _token_supported(block: dict[str, Any], token: str) -> bool:
        if block.get("supported") is False:
            return False
        key = norm_catalog_token(token)
        entry = block.get(key) if key in block else block.get(token)
        if isinstance(entry, dict) and entry.get("supported") is False:
            return False
        return key in block or token in block

    @staticmethod
    def backend_supports_token(
        capabilities: dict[str, Any],
        dimension: str,
        token: str,
        *,
        mode: TlsMode | None = None,
    ) -> bool:
        if dimension == "cipher_suite":
            if mode is None:
                return bool(
                    CapabilityRegistry.backend_cipher_modes(capabilities, token)
                )
            return CapabilityRegistry.backend_supports_cipher(capabilities, token, mode)
        block = capabilities.get(dimension)
        if not isinstance(block, dict):
            return False
        return CapabilityRegistry._token_supported(block, token)

    @staticmethod
    def dimension_keys(
        capabilities: dict[str, Any], dimension: str, *, tls_mode: TlsMode | None = None
    ) -> list[str]:
        if dimension == "cipher_suite":
            if tls_mode is not None:
                return CapabilityRegistry.cipher_suite_ids_for_mode(
                    capabilities, tls_mode
                )
            return CapabilityRegistry.all_cipher_suite_ids(capabilities)
        block = capabilities.get(dimension)
        if not isinstance(block, dict):
            return []
        if block.get("supported") is False:
            return []
        out: list[str] = []
        for key, entry in block.items():
            if key in _CAPABILITY_BLOCK_META_KEYS:
                continue
            if isinstance(entry, dict) and entry.get("supported") is False:
                continue
            out.append(str(key))
        return sorted(out)

    @staticmethod
    def all_cipher_suite_ids(capabilities: dict[str, Any]) -> list[str]:
        m13, m12 = CapabilityRegistry.cipher_maps(capabilities)
        return sorted(set(m13) | set(m12))

    @staticmethod
    def cipher_suite_ids_for_mode(
        capabilities: dict[str, Any], mode: TlsMode
    ) -> list[str]:
        m13, m12 = CapabilityRegistry.cipher_maps(capabilities)
        mp = m13 if mode == TlsVersionLabel.V13.value else m12
        return sorted(str(k) for k in mp.keys() if k)

    @staticmethod
    def is_cipher_tls13_only(capabilities: dict[str, Any], catalog_id: str) -> bool:
        return CapabilityRegistry.backend_cipher_modes(capabilities, catalog_id) == {
            TlsVersionLabel.V13.value
        }

    @staticmethod
    def is_cipher_tls12_only(capabilities: dict[str, Any], catalog_id: str) -> bool:
        return CapabilityRegistry.backend_cipher_modes(capabilities, catalog_id) == {
            TlsVersionLabel.V12.value
        }


_default_registry: CapabilityRegistry | None = None


def get_capability_registry(repo: Path | None = None) -> CapabilityRegistry:
    if repo is not None:
        return CapabilityRegistry(repo)
    global _default_registry
    if _default_registry is None:
        _default_registry = CapabilityRegistry()
    return _default_registry


_RUNTIME_DEFAULTS: dict[str, Any] = {
    "grpc_addr": None,
    "tls_host": "127.0.0.1",
    "tls_port": 15551,
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


def load_backend_component(
    backend_name: str, repo: Path | None = None
) -> tuple[type[Any], dict[str, Any]]:
    """Load wrapper class and ``capabilities.json`` for one backend."""
    from core.capabilities import get_wrapper_class

    name = (backend_name or "").strip().lower()
    return get_wrapper_class(name), load_capabilities(name, repo)


def load_backend(
    backend_name: str, repo: Path | None = None
) -> tuple[type[Any], dict[str, Any]]:
    return load_backend_component(backend_name, repo)


def merged_orchestration_env(active_backends: Iterable[str]) -> dict[str, str]:
    """Union env fragments from every active wrapper's ``orchestration_env`` hook."""
    from core.capabilities import wrapper_orchestration_env

    active = frozenset(
        (b or "").strip().lower() for b in active_backends if (b or "").strip()
    )
    merged: dict[str, str] = {}
    for backend in sorted(active):
        merged.update(wrapper_orchestration_env(backend, active))
    return merged


def session_wrapper_env(
    backend_name: str, repo: Path, active_backends: Iterable[str]
) -> dict[str, str]:
    """Orchestration + per-wrapper env for one wrapper subprocess."""
    from core.capabilities import wrapper_local_env

    active = frozenset(
        (b or "").strip().lower() for b in active_backends if (b or "").strip()
    )
    merged = dict(merged_orchestration_env(active))
    merged.update(wrapper_local_env(backend_name, repo, active))
    return merged


def backend_grpc_addr(
    backend_name: str, repo: Path | None = None, *, port_override: int | None = None
) -> str:
    rt = wrapper_runtime_config(backend_name, repo)
    addr = rt.get("grpc_addr")
    if not isinstance(addr, str) or not addr.strip():
        raise ValueError(
            f"capabilities.runtime.grpc_addr missing for backend {backend_name!r}"
        )
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


def backend_tls_endpoint(
    backend_name: str, repo: Path | None = None
) -> tuple[str, int]:
    rt = wrapper_runtime_config(backend_name, repo)
    host = str(rt.get("tls_host") or "127.0.0.1")
    port = int(rt.get("tls_port") or 15551)
    return host, port


def check_local_cli_tools(
    backends: Iterable[str], repo: Path | None = None
) -> list[str]:
    """Return human-readable missing-tool messages (delegates to each wrapper)."""
    from core.capabilities import local_cli_requirements, resolve_wrapper_cli_tool

    missing: list[str] = []
    root = repo or repository_root()
    for backend in backends:
        key = (backend or "").strip().lower()
        caps = load_capabilities(key, root)
        for exe in local_cli_requirements(key, caps):
            if resolve_wrapper_cli_tool(key, exe) is None:
                missing.append(f"{key}: {exe} not found")
    return missing


def load_capabilities_cache(
    wrapper_ids: frozenset[str] | set[str], repo: Path | None = None
) -> dict[str, dict[str, Any]]:
    return get_capability_registry(repo).load_cache(wrapper_ids, repo)


def create_wrapper_servicer(backend_name: str) -> Any:
    """Instantiate the gRPC servicer for one backend."""
    from core.capabilities import get_wrapper_class
    from wrappers.base import BaseTemplateWrapper

    cls = get_wrapper_class(backend_name)
    servicer = cls()
    if not isinstance(servicer, BaseTemplateWrapper):
        raise TypeError(f"{cls!r} must instantiate BaseTemplateWrapper")
    return servicer

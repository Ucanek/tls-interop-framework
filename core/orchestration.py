"""Wrapper process environment, gRPC/TLS endpoints, and local CLI tool checks."""

from __future__ import annotations

import shutil
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from core.catalog import BackendCapabilities, call_wrapper_hook, load_backend_capabilities


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

    return shutil.which(exe)


def wrapper_orchestration_env(
    backend_name: str, active_backends: frozenset[str] | set[str]) -> dict[str, str]:
    output = call_wrapper_hook(backend_name, "orchestration_env", active_backends)
    return dict(output) if isinstance(output, dict) else {}


def wrapper_local_env(
    backend_name: str, repo: Path, active_backends: frozenset[str] | set[str], slot_id: int | None = None) -> dict[str, str]:
    output = call_wrapper_hook(
        backend_name, "local_wrapper_env", repo, backend_name, active_backends, slot_id=slot_id)
    return dict(output) if isinstance(output, dict) else {}


def merged_orchestration_env(active_backends: Iterable[str]) -> dict[str, str]:
    active = frozenset((b or "").strip().lower() for b in active_backends if (b or "").strip())
    merged: dict[str, str] = {}
    for backend in sorted(active):
        merged.update(wrapper_orchestration_env(backend, active))

    return merged


def session_wrapper_env(
    backend_name: str, repo: Path, active_backends: Iterable[str], slot_id: int | None = None) -> dict[str, str]:
    active = frozenset((b or "").strip().lower() for b in active_backends if (b or "").strip())
    merged = dict(merged_orchestration_env(active))
    merged.update(wrapper_local_env(backend_name, repo, active, slot_id=slot_id))

    return merged


def backend_grpc_addr(
    backend_name: str, repo: Path | None = None, port_override: int | None = None) -> str:
    runtime_info = load_backend_capabilities(backend_name).runtime()
    addr = runtime_info.get("grpc_addr")
    if not isinstance(addr, str) or not addr.strip():
        raise ValueError(f"capabilities.runtime.grpc_addr missing for backend {backend_name!r}")

    addr = addr.strip()
    if port_override:
        host, _, _ = addr.rpartition(":")
        return f"{host or '127.0.0.1'}:{int(port_override)}"

    return addr


def backend_tls_endpoint(backend_name: str, repo: Path | None = None) -> tuple[str, int]:
    runtime_info = load_backend_capabilities(backend_name).runtime()
    host = str(runtime_info.get("tls_host") or "127.0.0.1")
    port = int(runtime_info.get("tls_port") or 25551)

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


def validate_run_args(
    args: Any, known_wrappers: frozenset[str] | None = None, repo: Path | None = None) -> None:
    _ = (known_wrappers, repo)
    if not (0 <= int(args.tls_port) <= 65535):
        raise ValueError("--tls-port must be in range 0..65535")

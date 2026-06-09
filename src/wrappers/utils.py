"""Stateless helpers shared by TLS backend wrappers (no gRPC servicer base class)."""

from __future__ import annotations

import fcntl
import os
import re
import shlex
import subprocess
import time
from typing import Any, Literal, Mapping, MutableMapping, Sequence, Type

from core.catalog import metadata_from_capabilities, tls_mode_from_version
from core.identity import repeated_config_tokens
from proto import interop_pb2

TlsModeLiteral = Literal["1.2", "1.3"]


def split_asymmetric_csv(val: str | None) -> tuple[list[str], list[str]]:
    """
    Split comma-separated tokens per role on the first ``:`` in the raw string.

    With no colon, both sides receive the same parsed list.
    """
    whole = (val or "").strip()
    if not whole:
        return [], []
    if ":" in whole:
        left, right = whole.split(":", 1)
        return (
            [p.strip() for p in left.split(",") if p.strip()],
            [p.strip() for p in right.split(",") if p.strip()],
        )
    parts = [p.strip() for p in whole.split(",") if p.strip()]
    return parts, parts


def parse_version_line(out: str | None) -> str:
    """Returns a compact version token from CLI stdout or stderr."""
    text = (out or "").strip()
    first_line = text.split("\n")[0].strip() if text else ""
    match = re.search(r"\d+\.\d+(?:\.\d+)?", first_line)
    return match.group(0) if match else (first_line[:40] if first_line else "unknown")


def alpn_protocols_from_config(config: Any) -> list[str]:
    raw = getattr(config, "alpn_protocols", None) or []
    return [str(p).strip() for p in raw if str(p).strip()]


def alpn_cli_protocol_list(config: Any) -> str:
    """Comma-separated ALPN ids for backend CLI flags (empty when unset)."""
    protos = alpn_protocols_from_config(config)
    return ",".join(protos) if protos else ""


def test_feature_enabled_in_config(config: Any, feature: str) -> bool:
    """True when ``test_features`` enabled this feature (mirrored in ``psk_modes``)."""
    return feature.strip().lower() in repeated_config_tokens(config, "psk_modes")


def remove_tls_session_artifact_files(repo_root: str) -> None:
    """Delete ``session.ticket`` and ``early_data.txt`` under the wrapper repo root."""
    root = (repo_root or "").strip()
    if not root:
        return
    for name in ("session.ticket", "early_data.txt"):
        path = os.path.join(root, name)
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def tls_mode_12_or_13(config: interop_pb2.TlsConfig | None) -> TlsModeLiteral:
    """Maps ``TlsConfig.version`` to TLS 1.2 or TLS 1.3 mode."""
    if config is None:
        return "1.3"
    return tls_mode_from_version(config.version)


def is_server_role(role: Any | None) -> bool:
    if role is None:
        return True
    try:
        return int(role) == int(interop_pb2.SERVER)
    except Exception:
        return True


def format_executed_command(
    cmd: Sequence[object],
    cwd: str | os.PathLike[str] | None = None,
) -> str:
    """Formats argv as a shell-safe log line."""
    line = shlex.join(str(x) for x in cmd)
    if cwd is not None:
        return f"cwd={shlex.quote(os.path.abspath(os.fspath(cwd)))} {line}"
    return line


def _make_non_blocking(fd: int) -> None:
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


def popen_stdio_merged(
    cmd: Sequence[object],
    *,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | MutableMapping[str, str] | None = None,
) -> subprocess.Popen[bytes]:
    """Starts subprocess with stdin and merged stdout/stderr (stdout non-blocking)."""
    p = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=os.fspath(cwd) if cwd is not None else None,
        env=dict(env) if env is not None else None,
    )
    if p.stdout:
        _make_non_blocking(p.stdout.fileno())
    return p


def read_nonblocking_stdout(
    proc: subprocess.Popen[bytes],
    *,
    timeout_s: float = 2.0,
    idle_s: float = 0.05,
    poll_s: float = 0.02,
    max_bytes: int = 1 << 20,
) -> bytes:
    """
    Read merged stdout until ``timeout_s`` or ``idle_s`` without new data after the first chunk.
    """
    if proc.stdout is None:
        return b""
    deadline = time.monotonic() + max(0.0, timeout_s)
    chunks: list[bytes] = []
    total = 0
    last_data_at: float | None = None
    while time.monotonic() < deadline and total < max_bytes:
        try:
            piece = proc.stdout.read(min(4096, max_bytes - total))
        except BlockingIOError:
            piece = None
        except OSError:
            break
        if piece:
            chunks.append(piece)
            total += len(piece)
            last_data_at = time.monotonic()
            if len(piece) < 4096:
                continue
        elif last_data_at is not None and (time.monotonic() - last_data_at) >= idle_s:
            break
        time.sleep(min(poll_s, max(0.0, deadline - time.monotonic())))
    return b"".join(chunks)


def capability(
    name: str,
    *flags: interop_pb2.ModifyFlag.ValueType,
) -> interop_pb2.Capability:
    return interop_pb2.Capability(name=name, flags=list(flags))


def standard_library_metadata(
    component_name: str,
    version: str,
    *,
    capabilities: dict | None = None,
) -> interop_pb2.LibraryMetadata:
    """Returns capability matrix from ``capabilities.json`` when provided."""
    cap = capability
    r, n = interop_pb2.READ, interop_pb2.NEGOTIATE
    s = interop_pb2.SET
    version_caps: list[tuple[str, bool]] = []
    cipher_caps: list[str] = []
    group_caps: list[str] = []
    try:
        if capabilities:
            version_caps, cipher_caps, group_caps = metadata_from_capabilities(
                capabilities, component_name=component_name
            )
    except Exception:
        pass
    version_caps_msg = [
        cap(name, r, s, n) if can_set else cap(name, r, n)
        for name, can_set in version_caps
    ]
    return interop_pb2.LibraryMetadata(
        component_name=component_name,
        version=version,
        roles=[interop_pb2.CLIENT, interop_pb2.SERVER],
        supported_versions=version_caps_msg,
        cipher_suites=[cap(name, r, n) for name in cipher_caps],
        groups=[cap(name, r, n) for name in group_caps],
    )


def run_cli_version(argv: list[str], timeout: float = 5) -> str:
    """Runs a ``--version``-style command and returns a short version string."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0:
            return parse_version_line(r.stdout or r.stderr)
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def serve_insecure(
    wrapper_cls: Type[Any],
    display_name: str,
) -> None:
    """Starts the gRPC ``TlsInteropWrapper`` service without TLS (port from ``GRPC_PORT``)."""
    from concurrent import futures

    import grpc
    from proto import interop_pb2_grpc

    port = int(os.environ.get("GRPC_PORT", "50051"))
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    interop_pb2_grpc.add_TlsInteropWrapperServicer_to_server(wrapper_cls(), server)
    server.add_insecure_port(f"0.0.0.0:{port}")
    server.start()
    print(f"{display_name} wrapper listening on {port}...")
    server.wait_for_termination()

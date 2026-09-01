"""Stateless helpers shared by TLS backend wrappers (no gRPC servicer base class)."""

from __future__ import annotations

import asyncio
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from typing import Any, BinaryIO, Literal, Mapping, MutableMapping, Sequence, Type, TYPE_CHECKING

from core.capabilities import metadata_from_capabilities
from core.tls_config_view import RoleLike, TlsConfigInput, TlsConfigLike, TlsConfigView
from core.utils import split_asymmetric_csv
from core.validation import tls_mode_from_version
from interop_proto import interop_pb2

if TYPE_CHECKING:
    from wrappers.base import WrapperSessionState

TlsModeLiteral = Literal["1.2", "1.3"]

_HRR_OUTPUT_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE) for p in (
        r"hello\s*retry\s*request",
        r"helloretryrequest",
        r"hello_retry_request",
        r"received\s+hrr",
        r"retry\s+request",
    ))


def hrr_detected_in_cli_output(text: str) -> bool:
    """Best-effort Hello Retry Request detection from merged CLI stdout/stderr."""
    blob = (text or "").strip()
    if not blob:
        return False
    for pat in _HRR_OUTPUT_PATTERNS:
        if pat.search(blob):
            return True
    lower = blob.lower()
    if lower.count("write client hello") >= 2:
        return True
    if lower.count("read client hello") >= 2:
        return True
    if len(re.findall(r"handshake\s*\[\s*length\s+[^\]]+\]\s*,\s*clienthello", blob, re.IGNORECASE)) >= 2:
        return True
    return False


def parse_version_line(out: str | None) -> str:
    """Returns a compact version token from CLI stdout or stderr."""
    text = (out or "").strip()
    first_line = text.split("\n")[0].strip() if text else ""
    match = re.search(r"\d+\.\d+(?:\.\d+)?", first_line)
    return match.group(0) if match else (first_line[:40] if first_line else "unknown")


def alpn_protocols_from_config(config: TlsConfigLike) -> list[str]:
    return TlsConfigView(config).alpn_protocols


def alpn_cli_protocol_list(config: TlsConfigLike) -> str:
    """Comma-separated ALPN ids for backend CLI flags (empty when unset)."""
    protos = alpn_protocols_from_config(config)
    return ",".join(protos) if protos else ""


def test_feature_enabled_in_config(config: TlsConfigLike, feature: str) -> bool:
    """True when ``test_features`` enabled this feature (mirrored in ``psk_modes``)."""
    return feature.strip().lower() in TlsConfigView(config).psk_modes


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


def ensure_interop_staging_dir(state: WrapperSessionState) -> str:
    """Per-session staging directory for PEM and sidecar files (``state.staging_dir``)."""
    staging = (getattr(state, "staging_dir", None) or "").strip()
    if staging:
        return staging
    staging = tempfile.mkdtemp(prefix="interop_staging_")
    state.staging_dir = staging
    return staging


def interop_staging_pem_paths(staging_dir: str) -> tuple[str, str]:
    """Cert/key PEM paths inside a session staging directory."""
    root = os.path.abspath(staging_dir)
    return os.path.join(root, "cert.pem"), os.path.join(root, "key.pem")


def interop_staging_sidecar_path(staging_dir: str, name: str) -> str:
    """Auxiliary file path inside a session staging directory (e.g. GnuTLS PSK passwd)."""
    root = os.path.abspath(staging_dir)
    safe = name.replace("/", "_").replace("\\", "_").strip() or "sidecar"
    return os.path.join(root, safe)


def cleanup_interop_staging_dir(staging_dir: str) -> None:
    """Remove a session staging directory tree."""
    root = (staging_dir or "").strip()
    if not root:
        return
    shutil.rmtree(root, ignore_errors=True)


def tls_mode_12_or_13(config: TlsConfigLike | None) -> TlsModeLiteral:
    """Maps ``TlsConfig.version`` to TLS 1.2 or TLS 1.3 mode."""
    if config is None:
        return "1.3"
    return tls_mode_from_version(TlsConfigView(config).version)


def is_server_role(role: RoleLike | None) -> bool:
    if role is None:
        return True
    try:
        return int(role) == int(interop_pb2.SERVER)
    except Exception:
        return True


def format_executed_command(cmd: Sequence[object], cwd: str | os.PathLike[str] | None = None) -> str:
    """Formats argv as a shell-safe log line."""
    line = shlex.join(str(x) for x in cmd)
    if cwd is not None:
        return f"cwd={shlex.quote(os.path.abspath(os.fspath(cwd)))} {line}"
    return line


def format_cli_debug_logs(*, cmd: str, exit_code: int | None = None,
    stdout: str = "", stderr: str = "") -> str:
    """
    Build ``OperationResponse.logs`` with CMD, exit code, stdout, and stderr.

    Wrappers merge stderr into stdout (``stderr=STDOUT``) to avoid pipe deadlocks
    on long-lived CLI processes; when ``stderr`` is empty, the stderr section notes that.
    """
    cmd_s = (cmd or "").strip()
    if cmd_s and not cmd_s.startswith("CMD:"):
        cmd_s = f"CMD: {cmd_s}"
    elif not cmd_s:
        cmd_s = "CMD: (unknown)"
    if exit_code is None:
        exit_s = "Exit code: (running)"
    else:
        exit_s = f"Exit code: {exit_code}"
    out_body = (stdout or "").rstrip() if (stdout or "").strip() else "(empty)"
    if (stderr or "").strip():
        err_body = stderr.rstrip()
    else:
        err_body = "(stderr merged into stdout; see stdout above)"
    return "\n".join([cmd_s, exit_s, "--- stdout ---", out_body, "--- stderr ---", err_body])


def _run_async(coro: Any) -> Any:
    """Run a coroutine from sync gRPC handler threads (no event loop on the worker thread)."""
    return asyncio.run(coro)


async def _read_fd_async(loop: asyncio.AbstractEventLoop, fd: int, nbytes: int) -> bytes:
    fut = loop.create_future()

    def _on_read() -> None:
        if fut.done():
            return
        try:
            chunk = os.read(fd, nbytes)
        except OSError as exc:
            loop.remove_reader(fd)
            fut.set_exception(exc)
            return
        loop.remove_reader(fd)
        fut.set_result(chunk)

    loop.add_reader(fd, _on_read)
    try:
        return await fut
    finally:
        if not fut.done():
            loop.remove_reader(fd)


async def _read_merged_async(fd: int, *, timeout_s: float, idle_s: float, max_bytes: int) -> bytes:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.0, timeout_s)
    chunks: list[bytes] = []
    total = 0
    last_data_at: float | None = None
    poll_s = 0.02

    while loop.time() < deadline and total < max_bytes:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        wait_s = min(poll_s, remaining)
        piece: bytes | None = None
        try:
            piece = await asyncio.wait_for(
                _read_fd_async(loop, fd, min(4096, max_bytes - total)),
                timeout=max(0.001, wait_s),
            )
        except asyncio.TimeoutError:
            piece = b""
        except OSError:
            break
        if piece:
            chunks.append(piece)
            total += len(piece)
            last_data_at = loop.time()
            continue
        if last_data_at is not None and (loop.time() - last_data_at) >= idle_s:
            break

    return b"".join(chunks)


def read_merged_stdout(stream: BinaryIO | None, *, timeout_s: float = 2.0, idle_s: float = 0.05,
    max_bytes: int = 1 << 20) -> bytes:
    """Read merged stdout/stderr until ``timeout_s`` or ``idle_s`` without new data."""
    if stream is None:
        return b""
    return _run_async(_read_merged_async(stream.fileno(), timeout_s=timeout_s, idle_s=idle_s, max_bytes=max_bytes))


def peek_merged_stdout(stream: BinaryIO | None, *, limit: int = 65536, idle_s: float = 0.05) -> bytes:
    """Best-effort read of early merged output without waiting for process exit."""
    if stream is None:
        return b""
    data = read_merged_stdout(stream, timeout_s=idle_s + 0.15, idle_s=idle_s, max_bytes=limit)
    return data[:limit]


def drain_merged_stdout(stream: BinaryIO | None, *, limit: int = 1 << 20) -> bytes:
    """Read available merged output; blocking tail read when the pipe still has buffered data."""
    if stream is None:
        return b""
    peeked = peek_merged_stdout(stream, limit=limit)
    if peeked:
        return peeked
    try:
        tail = stream.read(limit) or b""
    except OSError:
        return peeked
    if not tail:
        return peeked
    combined = peeked + tail
    return combined[:limit]


def popen_stdio_merged(cmd: Sequence[object], *, cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | MutableMapping[str, str] | None = None) -> subprocess.Popen[bytes]:
    """Starts subprocess with stdin and merged stdout/stderr (``stderr=STDOUT``)."""
    return subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        cwd=os.fspath(cwd) if cwd is not None else None, env=dict(env) if env is not None else None)


def read_nonblocking_stdout(proc: subprocess.Popen[bytes], *, timeout_s: float = 2.0,
    idle_s: float = 0.05, poll_s: float = 0.02, max_bytes: int = 1 << 20) -> bytes:
    """
    Read merged stdout until ``timeout_s`` or ``idle_s`` without new data after the first chunk.

    ``poll_s`` is accepted for API compatibility; asyncio event-loop polling replaces manual sleep.
    """
    del poll_s
    return read_merged_stdout(proc.stdout, timeout_s=timeout_s, idle_s=idle_s, max_bytes=max_bytes)


def capability(name: str, *flags: interop_pb2.ModifyFlag.ValueType) -> interop_pb2.Capability:
    return interop_pb2.Capability(name=name, flags=list(flags))


def standard_library_metadata(component_name: str, version: str, *,
    capabilities: dict | None = None) -> interop_pb2.LibraryMetadata:
    """Returns capability matrix from ``capabilities.json`` when provided."""
    cap = capability
    r, n = interop_pb2.READ, interop_pb2.NEGOTIATE
    s = interop_pb2.SET
    version_caps: list[tuple[str, bool]] = []
    cipher_caps: list[str] = []
    group_caps: list[str] = []
    try:
        if capabilities:
            version_caps, cipher_caps, group_caps = metadata_from_capabilities(capabilities,
                component_name=component_name)
    except Exception:
        pass
    version_caps_msg = [cap(name, r, s, n) if can_set else cap(name, r, n) for name, can_set in version_caps]
    return interop_pb2.LibraryMetadata(component_name=component_name, version=version,
        roles=[interop_pb2.CLIENT, interop_pb2.SERVER], supported_versions=version_caps_msg,
        cipher_suites=[cap(name, r, n) for name in cipher_caps], groups=[cap(name, r, n) for name in group_caps])


def run_cli_version(argv: list[str], timeout: float = 5) -> str:
    """Runs a ``--version``-style command and returns a short version string."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0:
            return parse_version_line(r.stdout or r.stderr)
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def serve_insecure(wrapper_cls: Type[Any], display_name: str) -> None:
    """Starts the gRPC ``TlsInteropWrapper`` service without TLS (port from ``GRPC_PORT``)."""
    from concurrent import futures

    import grpc
    from interop_proto import interop_pb2_grpc

    port = int(os.environ.get("GRPC_PORT", "50051"))
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    interop_pb2_grpc.add_TlsInteropWrapperServicer_to_server(wrapper_cls(), server)
    server.add_insecure_port(f"0.0.0.0:{port}")
    server.start()
    print(f"{display_name} wrapper listening on {port}...")
    server.wait_for_termination()

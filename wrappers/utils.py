"""Stateless helpers shared by TLS backend wrappers (no gRPC servicer base class)."""

from __future__ import annotations

import fcntl
import os
import re
import shlex
import subprocess
import time
from contextlib import suppress
from collections.abc import Mapping, MutableMapping, Sequence
from pathlib import Path
from typing import Any, Literal

from core.catalog import repository_root, tls_mode_from_version
from core.identity import repeated_config_tokens
from interop_proto import interop_pb2

TlsModeLiteral = Literal["1.2", "1.3"]

_HRR_OUTPUT_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"hello\s*retry\s*request", r"helloretryrequest", r"hello_retry_request",
        r"received\s+hrr", r"retry\s+request"))


def hrr_detected_in_cli_output(text: str) -> bool:
    """Best-effort Hello Retry Request detection from merged CLI stdout/stderr."""
    blob = (text or "").strip()
    if not blob:
        return False
    if any(pat.search(blob) for pat in _HRR_OUTPUT_PATTERNS):
        return True
    lower = blob.lower()
    if lower.count("write client hello") >= 2 or lower.count("read client hello") >= 2:
        return True
    return len(re.findall(r"handshake\s*\[\s*length\s+[^\]]+\]\s*,\s*clienthello", blob, re.IGNORECASE)) >= 2


def split_asymmetric_csv(val: str | None) -> tuple[list[str], list[str]]:
    """Split comma-separated tokens per role on the first ``:`` in the raw string."""
    whole = (val or "").strip()
    if not whole:
        return [], []
    if ":" in whole:
        left, right = whole.split(":", 1)
        return [p.strip() for p in left.split(",") if p.strip()], [p.strip() for p in right.split(",") if p.strip()]
    parts = [p.strip() for p in whole.split(",") if p.strip()]
    return parts, parts


def parse_version_line(out: str | None) -> str:
    """Returns a compact version token from CLI stdout or stderr."""
    text = (out or "").strip()
    first_line = text.split("\n")[0].strip() if text else ""
    match = re.search(r"\d+\.\d+(?:\.\d+)?", first_line)
    return match.group(0) if match else (first_line[:40] if first_line else "unknown")


def alpn_cli_protocol_list(config: Any) -> str:
    """Comma-separated ALPN ids for backend CLI flags (empty when unset)."""
    raw = getattr(config, "alpn_protocols", None) or []
    protos = [str(p).strip() for p in raw if str(p).strip()]
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
        with suppress(OSError):
            os.unlink(os.path.join(root, name))


def tls_session_state_paths(config) -> tuple[str, str]:
    """Session ticket and 0-RTT payload paths under ``TlsConfig.repo_root`` (or repo root)."""
    raw = (getattr(config, "repo_root", None) or "").strip()
    root = Path(raw).resolve() if raw else repository_root()
    return str(root / "session.ticket"), str(root / "early_data.txt")


def _interop_slot_suffix() -> str:
    slot = os.environ.get("INTEROP_SLOT_ID", "").strip()
    return f"_{slot}" if slot else ""


def interop_staging_pem_paths(prefix: str) -> tuple[str, str]:
    """Per-process PEM staging under ``/tmp``; ``INTEROP_SLOT_ID`` avoids parallel collisions."""
    suffix = _interop_slot_suffix()
    return f"/tmp/interop_{prefix}_cert{suffix}.pem", f"/tmp/interop_{prefix}_key{suffix}.pem"


def interop_staging_sidecar_path(prefix: str, name: str) -> str:
    """Auxiliary staging file (e.g. GnuTLS PSK passwd) with optional slot suffix."""
    return f"/tmp/interop_{prefix}_{name}{_interop_slot_suffix()}"


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


def format_executed_command(cmd: Sequence[object], cwd: str | os.PathLike[str] | None = None) -> str:
    """Formats argv as a shell-safe log line."""
    line = shlex.join(str(x) for x in cmd)
    return f"cwd={shlex.quote(os.path.abspath(os.fspath(cwd)))} {line}" if cwd is not None else line


def format_cli_debug_logs(*, cmd: str, exit_code: int | None = None, stdout: str = "", stderr: str = "") -> str:
    """Build ``OperationResponse.logs`` (CMD, exit, stdout; stderr is usually merged)."""
    cmd_s = (cmd or "").strip()
    cmd_line = f"CMD: {cmd_s}" if cmd_s and not cmd_s.startswith("CMD:") else (cmd_s or "CMD: (unknown)")
    out_body = (stdout or "").rstrip() or "(empty)"
    err_body = (stderr or "").rstrip() or "(stderr merged into stdout; see stdout above)"
    exit_s = "Exit code: (running)" if exit_code is None else f"Exit code: {exit_code}"
    return "\n".join((cmd_line, exit_s, "--- stdout ---", out_body, "--- stderr ---", err_body))


def popen_stdio_merged(
    cmd: Sequence[object], *, cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | MutableMapping[str, str] | None = None
) -> subprocess.Popen[bytes]:
    """Starts subprocess with stdin and merged stdout/stderr (stdout non-blocking)."""
    p = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        cwd=os.fspath(cwd) if cwd is not None else None,
        env=dict(env) if env is not None else None)
    if p.stdout:
        flags = fcntl.fcntl(p.stdout.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(p.stdout.fileno(), fcntl.F_SETFL, flags | os.O_NONBLOCK)
    return p


def read_nonblocking_stdout(
    proc: subprocess.Popen[bytes], *, timeout_s: float = 2.0, idle_s: float = 0.05,
    poll_s: float = 0.02, max_bytes: int = 1 << 20) -> bytes:
    """Read merged stdout until ``timeout_s`` or ``idle_s`` without new data after the first chunk."""
    if proc.stdout is None:
        return b""
    deadline = time.monotonic() + max(0.0, timeout_s)
    chunks: list[bytes] = []
    total = 0
    last_data_at: float | None = None

    while time.monotonic() < deadline and total < max_bytes:
        try:
            piece = proc.stdout.read(min(4096, max_bytes - total))
        except (BlockingIOError, OSError):
            piece = None

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


def standard_library_metadata(component_name: str, version: str) -> interop_pb2.LibraryMetadata:
    """Identity for ``GetMetadata`` (name + version + roles). Catalogs live in JSON."""
    return interop_pb2.LibraryMetadata(
        component_name=component_name, version=version,
        roles=[interop_pb2.CLIENT, interop_pb2.SERVER])


def run_cli_version(argv: list[str], timeout: float = 5) -> str:
    """Runs a ``--version``-style command and returns a short version string."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0:
            return parse_version_line(r.stdout or r.stderr)
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def serve_insecure(wrapper_cls: type[Any], display_name: str) -> None:
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
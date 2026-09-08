"""TLS interop runner: local wrapper subprocesses + gRPC matrix driver."""

from __future__ import annotations

import logging
import os
import re
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Mapping

import grpc

from core.cleanup import ensure_interop_certs
from core.orchestration_context import orchestration_context_for_backends, set_orchestration_context
from core.registry import(backend_grpc_addr, backend_tls_endpoint, check_local_cli_tools,
    discover_wrapper_ids, load_capabilities, session_wrapper_env)
from core.matrix_cell import MatrixCell
from core.matrix import normalize_cell_tls_micro_params
from core.utils import norm_token, parse_asymmetric
from core.validation import cell_capability_skip_reason, tls_version_to_capability_name

from wrappers.utils import remove_tls_session_artifact_files
from interop_proto import interop_pb2, interop_pb2_grpc
from wrappers.base import wait_tcp_connect
from core.utils import split_asymmetric_csv

logger = logging.getLogger(__name__)

# Distinct from 0 (pass) and 1 (fail) so matrix runners can show SKIP vs OK / TIMEOUT.
EXIT_SKIP = 77
EXIT_TIMEOUT = 78

_DEFAULT_GRPC_STARTUP_S = 90.0
_GRPC_STARTUP_POLL_S = 0.4
_DEFAULT_CELL_TIMEOUT_S = 45.0
_CELL_TIMEOUT_POLL_S = 0.25
_CELL_TIMEOUT_CLEANUP_WAIT_S = 15.0
_EMERGENCY_CLOSE_GRPC_S = 10.0
_WORKER_PORT_STRIDE = 100
_MAX_PARALLEL_JOBS = 32


def _worker_slot_grpc_overrides(repo: Path, backends: frozenset[str] | set[str], slot_id: int,
    base_overrides: Mapping[str, int] | None = None) -> dict[str, int]:
    """gRPC listen ports per backend for one parallel worker slot."""
    overrides = {k.strip().lower(): int(v) for k, v in (base_overrides or {}).items()}
    offset = int(slot_id) * _WORKER_PORT_STRIDE
    for backend in backends:
        key = (backend or "").strip().lower()
        if key in overrides:
            continue
        _, base_grpc = _grpc_host_port(backend_grpc_addr(key, repo))
        overrides[key] = base_grpc + offset
    return overrides


def _grpc_host_port(addr: str) -> tuple[str, int]:
    host, _, port_s = addr.rpartition(":")
    if not port_s.isdigit():
        raise ValueError(f"invalid gRPC address {addr!r}")
    return host or "127.0.0.1", int(port_s)


def apply_matrix_tls_endpoints(server: str, client: str, server_conf: interop_pb2.TlsConfig,
    client_conf: interop_pb2.TlsConfig, *, repo: Path, cell: MatrixCell | None = None,
    session: BaseExecutionSession | None = None) -> tuple[str, int]:
    """Return host TCP coordinates for the driver check after ESTABLISH."""
    port_raw = (cell.tls_port or "").strip() if cell is not None else ""
    if port_raw:
        tcp_host, default_port = backend_tls_endpoint(server, repo)
        tcp_port = int(port_raw)
    elif session is not None:
        tcp_host, tcp_port = session.tls_endpoint(server)
    else:
        tcp_host, default_port = backend_tls_endpoint(server, repo)
        tcp_port = default_port
    server_conf.port = tcp_port
    client_conf.server_hostname = "127.0.0.1"
    client_conf.port = tcp_port
    return tcp_host, tcp_port


def required_backends_from_matrix(axis_keys: list[str], combos: list[tuple[Any, ...]], *,
    args_template: Any, repo: Path, known: frozenset[str]) -> tuple[frozenset[str], int]:
    """
    Collect backends needed by non-SKIP matrix cells.

    Returns ``(backend_ids, skip_count)``.
    """
    needed: set[str] = set()
    skips = 0
    for tup in combos:
        cell = MatrixCell.from_axis(axis_keys, tup)
        cell = normalize_cell_tls_micro_params(cell, args_template, repo)
        if cell_capability_skip_reason(cell, repo):
            skips += 1
            continue
        srv = cell.server
        cli = cell.client
        if srv in known:
            needed.add(srv)
        if cli in known:
            needed.add(cli)
    return frozenset(needed), skips


class BaseExecutionSession(ABC):
    """Shared lifecycle for persistent local wrapper sessions."""

    repo: Path
    backends: list[str]
    verbose: bool
    metadata: dict[str, interop_pb2.LibraryMetadata]

    @abstractmethod
    def start(self) -> None:
        """Start backends and wait until gRPC (and metadata) are ready."""

    @abstractmethod
    def stop(self) -> None:
        """Tear down backends and release resources."""

    @abstractmethod
    def grpc_addr(self, backend: str) -> str:
        """Host:port for ``TlsInteropWrapper`` gRPC on this backend."""

    @abstractmethod
    def tls_endpoint(self, backend: str) -> tuple[str, int]:
        """Host TCP coordinates for post-ESTABLISH connectivity checks."""


class WrapperSession(BaseExecutionSession):
    """Start wrapper gRPC services as host subprocesses, or attach to existing ones."""

    def __init__(self, repo: Path, backends: frozenset[str], *, verbose: bool = False,
        attach: bool = False, grpc_port_overrides: Mapping[str, int] | None = None) -> None:
        known = frozenset(discover_wrapper_ids(repo))
        unknown = backends - known
        if unknown:
            raise ValueError(f"Unknown backend(s): {sorted(unknown)}")
        self.repo = repo.resolve()
        self.backends = sorted(backends)
        self.verbose = verbose
        self.attach = attach
        self._grpc_port_overrides = {k.strip().lower(): int(v) for k, v in (grpc_port_overrides or {}).items()}
        self.metadata: dict[str, interop_pb2.LibraryMetadata] = {}
        self._procs: list[subprocess.Popen[bytes]] = []

    def grpc_addr(self, backend: str) -> str:
        key = (backend or "").strip().lower()
        override = self._grpc_port_overrides.get(key)
        return backend_grpc_addr(key, self.repo, port_override=override or None)

    def tls_endpoint(self, backend: str) -> tuple[str, int]:
        return backend_tls_endpoint(backend, self.repo)

    def _wrapper_env(self, backend: str) -> dict[str, str]:
        env = os.environ.copy()
        _, grpc_port = _grpc_host_port(self.grpc_addr(backend))
        env["GRPC_PORT"] = str(grpc_port)
        env["WRAPPER"] = backend
        env.update(session_wrapper_env(backend, self.repo, self.backends))
        return env

    def _wrapper_cmd(self, backend: str) -> list[str]:
        return [sys.executable, "-m", f"wrappers.{backend}.wrapper"]

    def up(self) -> None:
        if not self.backends:
            return
        if self.attach:
            targets = ", ".join(f"{b} @ {self.grpc_addr(b)}" for b in self.backends)
            logger.info("Attach mode: connecting to existing wrapper(s) on localhost (%s)", targets)
            return
        try:
            import grpc  # noqa: F401
        except ImportError as e:
            raise RuntimeError("Requires grpcio on the host Python "
                "(pip install 'grpcio>=1.60' 'protobuf>=4.21')") from e
        ensure_interop_certs(self.repo, verbose=self.verbose)
        missing = check_local_cli_tools(self.backends, self.repo)
        if missing:
            raise RuntimeError("Requires TLS CLI tools on PATH:\n  " + "\n  ".join(missing))
        for backend in self.backends:
            addr = self.grpc_addr(backend)
            host, port = _grpc_host_port(addr)
            in_use, _ = wait_tcp_connect(host, port, timeout_s=0.35)
            if in_use:
                raise RuntimeError(f"Port {port} already in use ({addr}); stop other wrapper processes")
        if self.verbose:
            logger.debug("Starting wrappers: %s", ", ".join(self.backends))
        for backend in self.backends:
            cmd = self._wrapper_cmd(backend)
            if self.verbose:
                logger.debug("[Wrapper] %s: %s (GRPC_PORT from env)", backend, " ".join(cmd))
            proc = subprocess.Popen(cmd, cwd=self.repo, env=self._wrapper_env(backend), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE if self.verbose else subprocess.DEVNULL,
                stderr=subprocess.STDOUT if self.verbose else subprocess.DEVNULL, start_new_session=True)
            self._procs.append(proc)
            if proc.poll() is not None:
                out = ""
                if proc.stdout is not None:
                    try:
                        out = proc.stdout.read().decode("utf-8", errors="replace")
                    except Exception:
                        pass
                raise RuntimeError(f"Wrapper {backend} exited immediately (code {proc.returncode})"
                    + (f":\n{out}" if out else ""))

    def down(self) -> None:
        if self.attach:
            return
        for proc in self._procs:
            if proc.poll() is not None:
                continue
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                proc.terminate()
        deadline = time.monotonic() + 8.0
        for proc in self._procs:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    proc.kill()
        self._procs.clear()

    def wait_grpc_ready(self, timeout_s: float = _DEFAULT_GRPC_STARTUP_S) -> None:
        addrs = sorted({self.grpc_addr(b) for b in self.backends})
        if not addrs:
            return
        deadline = time.monotonic() + timeout_s
        pending = set(addrs)
        while time.monotonic() < deadline and pending:
            for addr in list(pending):
                if _wait_grpc_channel_ready(addr, deadline=deadline, verbose=self.verbose):
                    pending.discard(addr)
            if pending:
                time.sleep(_GRPC_STARTUP_POLL_S)
        if pending:
            raise TimeoutError(f"gRPC not reachable within {timeout_s}s: {', '.join(sorted(pending))}")

    def load_metadata(self) -> None:
        for backend in self.backends:
            addr = self.grpc_addr(backend)
            ch = grpc.insecure_channel(addr)
            try:
                stub = interop_pb2_grpc.TlsInteropWrapperStub(ch)
                self.metadata[backend] = stub.GetMetadata(interop_pb2.Empty())
            finally:
                try:
                    ch.close()
                except Exception:
                    pass

    def start(self) -> None:
        set_orchestration_context(orchestration_context_for_backends(self.backends))
        self.up()
        self.wait_grpc_ready()
        self.load_metadata()

    def stop(self, *, clear_context: bool = True) -> None:
        self.down()
        if clear_context:
            set_orchestration_context(None)

    def __enter__(self) -> WrapperSession:
        self.start()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.stop()


class WorkerSlotSession(WrapperSession):
    """Isolated wrapper subprocess set for one parallel matrix worker (unique gRPC/TLS ports)."""

    def __init__(self, repo: Path, backends: frozenset[str], slot_id: int, *,
        verbose: bool = False, grpc_port_overrides: Mapping[str, int] | None = None) -> None:
        overrides = _worker_slot_grpc_overrides(repo, backends, slot_id, grpc_port_overrides)
        super().__init__(repo, backends, verbose=verbose, attach=False, grpc_port_overrides=overrides)
        self.slot_id = int(slot_id)

    def tls_endpoint(self, backend: str) -> tuple[str, int]:
        key = (backend or "").strip().lower()
        host, base_port = backend_tls_endpoint(key, self.repo)
        return host, base_port + self.slot_id * _WORKER_PORT_STRIDE

    def _wrapper_env(self, backend: str) -> dict[str, str]:
        env = super()._wrapper_env(backend)
        env["INTEROP_SLOT_ID"] = str(self.slot_id)
        key = (backend or "").strip().lower()
        if key == "nss":
            from wrappers.nss.wrapper import nss_db_directory

            env["NSSDB"] = str(nss_db_directory(self.repo, f"nss_slot{self.slot_id}"))
        return env


class WorkerSlotPool:
    """Pool of ``WorkerSlotSession`` instances (one isolated wrapper set per slot)."""

    def __init__(self, repo: Path, backends: frozenset[str], num_slots: int, *,
        verbose: bool = False, grpc_base_overrides: Mapping[str, int] | None = None) -> None:
        if num_slots < 1:
            raise ValueError("num_slots must be >= 1")
        self.repo = repo.resolve()
        self.backends = frozenset(backends)
        self.verbose = verbose
        self._sessions = [WorkerSlotSession(self.repo, self.backends, slot_id=i, verbose=verbose,
            grpc_port_overrides=grpc_base_overrides) for i in range(num_slots)]

    def session(self, slot_id: int) -> WorkerSlotSession:
        return self._sessions[int(slot_id)]

    def start(self) -> None:
        set_orchestration_context(orchestration_context_for_backends(self.backends))
        for session in self._sessions:
            session.start()
        if self.verbose:
            logger.debug("Parallel workers: %d slot(s), port stride %d", len(self._sessions), _WORKER_PORT_STRIDE)

    def stop(self) -> None:
        for session in self._sessions:
            session.stop(clear_context=False)
        set_orchestration_context(None)

    def __enter__(self) -> WorkerSlotPool:
        self.start()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.stop()


def _server_accepts_inline_pem_identity(backend: str, repo: Path) -> bool:
    """False when wrapper uses out-of-band identity (e.g. NSS DB nicknames)."""
    try:
        rt = load_capabilities(backend, repo).get("runtime") or {}
    except (FileNotFoundError, ValueError):
        return True
    blocked = frozenset(rt.get("unsupported_tls_fields") or ())
    return "certificate" not in blocked and "private_key" not in blocked


def _cell_log_basename(server: str, client: str, cell: MatrixCell | None, *, kind: str) -> str:
    base = f"{server}_x_{client}"
    if cell:
        tags: list[str] = []
        mapping = cell.to_mapping()
        for key in ("tls_version", "cipher_suite", "supported_groups", "signature_schemes", "alpn", "tls_port"):
            raw = (mapping.get(key) or "").strip()
            if raw:
                safe = re.sub(r"[^\w.-]+", "-", raw)[:48]
                tags.append(safe)
        if tags:
            base = f"{base}_{'_'.join(tags)}"
    prefix = f"{kind.lower()}_" if kind else "fail_"
    return f"{prefix}{base}.log"


def _attach_cell_server_identity(cfg: interop_pb2.TlsConfig, cell: MatrixCell, *, repo: Path) -> None:
    """Load server leaf PEM bytes from ``certs/{prefix}.*`` for this cell's sig schemes."""
    from core.identity import(get_cert_prefix_for_cipher_suite, get_cert_prefix_for_schemes, read_identity_pem_bytes)

    schemes = cell.list_tokens("signature_schemes", server=True)
    if schemes:
        prefix = get_cert_prefix_for_schemes(schemes)
    else:
        prefix = get_cert_prefix_for_cipher_suite(cell.cipher_id(server=True))
    cert_b, key_b = read_identity_pem_bytes(prefix, repo=repo)
    if cert_b and key_b:
        cfg.certificate = cert_b
        cfg.private_key = key_b


def tls_config_from_cell(cell: MatrixCell, role: int, *, repo: Path | None = None) -> interop_pb2.TlsConfig:
    """Build ``TlsConfig`` for one matrix role from a normalized cell."""
    server = role == interop_pb2.SERVER
    cfg = interop_pb2.TlsConfig()
    ver = cell.scalar("tls_version", server=server)
    if ver:
        cfg.version = ver
    else:
        cfg.version = "1.3"
    cs = cell.scalar("cipher_suite", server=server)
    if cs:
        cfg.cipher_suite = cs
    port_raw = cell.scalar("tls_port", server=server)
    if port_raw:
        cfg.port = int(port_raw)
    elif not (cell.tls_port or "").strip():
        cfg.port = 5555
    cfg.supported_groups.extend(cell.list_tokens("supported_groups", server=server))
    cfg.signature_schemes.extend(cell.list_tokens("signature_schemes", server=server))
    cfg.alpn_protocols.extend(cell.list_tokens("alpn", server=server))
    from core.capabilities import enabled_test_features_from_cell

    cfg.psk_modes.extend(sorted(enabled_test_features_from_cell(cell)))
    if cell.truthy("expect_hrr"):
        cfg.expect_hrr = True
    if server and repo is not None:
        backend = cell.server
        if _server_accepts_inline_pem_identity(backend, repo):
            _attach_cell_server_identity(cfg, cell, repo=repo)
    return cfg


def wrapper_filesystem_root(session: BaseExecutionSession) -> str:
    """Repo root path as seen inside wrapper subprocesses (per-slot dir when parallel)."""
    if isinstance(session, WorkerSlotSession):
        root = session.repo / ".interop_worker" / f"slot{session.slot_id}"
        root.mkdir(parents=True, exist_ok=True)
        return str(root.resolve())
    return str(session.repo.resolve())


def _copy_tls_config(cfg: interop_pb2.TlsConfig) -> interop_pb2.TlsConfig:
    out = interop_pb2.TlsConfig()
    out.CopyFrom(cfg)
    return out


def tls_config_resumption_or_0rtt_active(cfg: interop_pb2.TlsConfig) -> bool:
    from wrappers.utils import test_feature_enabled_in_config

    return test_feature_enabled_in_config(cfg, "resumption") or test_feature_enabled_in_config(cfg, "0rtt")


def _format_output_data(data: bytes) -> str:
    if not data:
        return "(empty)"
    ascii_repr = data.decode("ascii", errors="replace")
    lines = [f"len={len(data)}", f"ascii: {ascii_repr!r}", f"hex: {data.hex()}"]
    return "\n".join(lines)


def _negotiated_debug_text(neg: interop_pb2.NegotiatedTlsParameters | None) -> str:
    if neg is None:
        return "(none)"
    parts = []
    if (neg.protocol_version or "").strip():
        parts.append(f"protocol_version={neg.protocol_version}")
    if (neg.cipher_suite or "").strip():
        parts.append(f"cipher_suite={neg.cipher_suite}")
    if (neg.named_group or "").strip():
        parts.append(f"named_group={neg.named_group}")
    if neg.hrr_occurred:
        parts.append("hrr_occurred=true")
    return ", ".join(parts) if parts else "(empty negotiated block)"


def _metadata_debug_text(label: str, meta: interop_pb2.LibraryMetadata | None) -> str:
    if meta is None:
        return f"{label}: (not loaded)"
    roles = [str(r) for r in meta.roles]
    versions = [c.name for c in meta.supported_versions[:8]]
    ciphers = [c.name for c in meta.cipher_suites[:8]]
    groups = [c.name for c in meta.groups[:8]]
    return "\n".join([
        f"{label}: {meta.component_name} {meta.version}",
        f"  roles: {', '.join(roles) or '-'}",
        f"  supported_versions (sample): {', '.join(versions) or '-'}",
        f"  cipher_suites (sample): {', '.join(ciphers) or '-'}",
        f"  groups (sample): {', '.join(groups) or '-'}",
    ])


def _wrapper_env_debug_text(repo: Path, backends: list[str]) -> str:
    active = frozenset(backends)
    lines = ["=== Orchestration environment ==="]
    merged = merged_orchestration_env(active)
    if merged:
        for key in sorted(merged):
            lines.append(f"{key}={merged[key]}")
    else:
        lines.append("(no merged orchestration env)")
    for backend in sorted(active):
        lines.append(f"--- {backend} session_wrapper_env ---")
        env = session_wrapper_env(backend, repo, active)
        if env:
            for key in sorted(env):
                lines.append(f"{key}={env[key]}")
        else:
            lines.append("(empty)")
    return "\n".join(lines)


def _tls_config_debug_text(label: str, cfg: interop_pb2.TlsConfig) -> str:
    cert_b = getattr(cfg, "certificate", None) or b""
    key_b = getattr(cfg, "private_key", None) or b""
    lines = [
        f"=== {label} TlsConfig ===",
        f"version: {cfg.version or '-'}",
        f"cipher_suite: {cfg.cipher_suite or '-'}",
        f"port: {cfg.port}",
        f"server_hostname: {cfg.server_hostname or '-'}",
        f"supported_groups: {', '.join(cfg.supported_groups) or '-'}",
        f"signature_schemes: {', '.join(cfg.signature_schemes) or '-'}",
        f"signature_schemes_cert: {', '.join(cfg.signature_schemes_cert) or '-'}",
        f"alpn_protocols: {', '.join(cfg.alpn_protocols) or '-'}",
        f"supported_versions: {', '.join(cfg.supported_versions) or '-'}",
        f"psk_modes / test_features: {', '.join(cfg.psk_modes) or '-'}",
        f"resumption_step: {cfg.resumption_step or '-'}",
        f"repo_root: {cfg.repo_root or '-'}",
        f"certificate inline: {'yes (' + str(len(cert_b)) + ' bytes)' if cert_b.strip() else 'no'}",
        f"private_key inline: {'yes (' + str(len(key_b)) + ' bytes)' if key_b.strip() else 'no'}",
        f"ca_file: {cfg.ca_file or '-'}",
        f"ca_path: {cfg.ca_path or '-'}",
        f"session_tickets_enabled: {cfg.session_tickets_enabled}",
        f"enable_early_data: {cfg.enable_early_data}",
        f"prefer_server_ciphers: {cfg.prefer_server_ciphers}",
        f"record_size_limit: {cfg.record_size_limit or '-'}",
        f"max_fragment_length: {cfg.max_fragment_length or '-'}",
        f"ocsp_stapling: {cfg.ocsp_stapling}",
        f"renegotiation: {cfg.renegotiation or '-'}",
        f"post_handshake_auth: {cfg.post_handshake_auth}",
        f"expect_hrr: {cfg.expect_hrr}",
    ]
    return "\n".join(lines)


@dataclass
class OpTrace:
    label: str
    status: int
    message: str
    logs: str
    negotiated: interop_pb2.NegotiatedTlsParameters | None = None
    output_data: bytes = b""


def _format_op_trace(trace: OpTrace) -> str:
    status_map = {
        interop_pb2.OperationResponse.SUCCESS: "SUCCESS",
        interop_pb2.OperationResponse.FAILURE: "FAILURE",
        interop_pb2.OperationResponse.ERROR: "ERROR",
    }
    status_name = status_map.get(trace.status, str(trace.status))
    parts = [f"--- {trace.label} (status={status_name}) ---"]
    if trace.message:
        parts.append(f"message: {trace.message}")
    if trace.negotiated is not None:
        parts.append(f"negotiated: {_negotiated_debug_text(trace.negotiated)}")
    if trace.output_data:
        parts.append("output_data:")
        parts.append(_format_output_data(trace.output_data))
    if trace.logs:
        parts.append(trace.logs)
    return "\n".join(parts)


def prepare_debug_run_dir(repo: Path) -> Path:
    """Create ``debug_logs/run_<timestamp>/`` for one matrix invocation."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = repo / "debug_logs" / f"run_{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


class DebugRunLogs:
    """Lazy debug log directory: created on first FAIL, omitted when all cells pass."""

    def __init__(self, repo: Path) -> None:
        self.repo = repo
        self._dir: Path | None = None

    @property
    def ready(self) -> bool:
        return self._dir is not None

    @property
    def path(self) -> Path | None:
        return self._dir

    def ensure_dir(self) -> Path:
        if self._dir is None:
            self._dir = prepare_debug_run_dir(self.repo)
        return self._dir


def _unique_log_path(run_dir: Path, basename: str) -> Path:
    path = run_dir / basename
    if not path.exists():
        return path
    stem = basename[:-4] if basename.endswith(".log") else basename
    for i in range(2, 1000):
        alt = run_dir / f"{stem}_{i}.log"
        if not alt.exists():
            return alt
    return run_dir / f"{stem}_dup.log"


def write_cell_debug_log(repo: Path, *, server: str, client: str,
    server_conf: interop_pb2.TlsConfig, client_conf: interop_pb2.TlsConfig,
    driver: "InteropDriver", debug_logs: DebugRunLogs, cell: MatrixCell | None = None,
    tcp_host: str = "", tcp_port: int = 0, extra_error: str = "", result_kind: str = "FAIL") -> Path:
    """Write one cell log into the run's debug directory; return the log file path."""
    debug_run_dir = debug_logs.ensure_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    kind = (result_kind or "FAIL").strip().upper()
    path = _unique_log_path(debug_run_dir, _cell_log_basename(server, client, cell, kind=kind))
    parts: list[str] = [
        f"TLS interop {kind} log",
        f"timestamp: {ts}",
        f"server: {server}",
        f"client: {client}",
    ]
    if cell:
        parts.append("matrix_cell: " + ", ".join(f"{k}={v}" for k, v in sorted(cell.to_mapping().items()) if str(v).strip()))
    if driver._last_failure:
        label, status, detail = driver._last_failure
        parts.append(f"last_failure: label={label} status={status}")
        parts.append(f"last_failure_summary: {detail}")
    if extra_error:
        parts.append(f"extra_error: {extra_error}")
    parts.append("")
    parts.append("=== Endpoints ===")
    parts.append(f"gRPC server: {driver.server_addr}")
    parts.append(f"gRPC client: {driver.client_addr}")
    if tcp_host or tcp_port:
        parts.append(f"TCP check (post-ESTABLISH): {tcp_host}:{tcp_port}")
    parts.append("")
    parts.append("=== Wrapper metadata ===")
    parts.append(_metadata_debug_text("server", driver.server_metadata))
    parts.append(_metadata_debug_text("client", driver.client_metadata))
    parts.append("")
    parts.append(_wrapper_env_debug_text(repo, sorted({server, client})))
    parts.append("")
    parts.append(_tls_config_debug_text("SERVER", server_conf))
    parts.append("")
    parts.append(_tls_config_debug_text("CLIENT", client_conf))
    parts.append("")
    parts.append("=== Operation traces ===")
    if driver._op_traces:
        for trace in driver._op_traces:
            parts.append(_format_op_trace(trace))
            parts.append("")
    else:
        parts.append("(no gRPC operation traces captured)")
    path.write_text("\n".join(parts).rstrip() + "\n", encoding="utf-8")
    return path


def write_fail_debug_log(repo: Path, *, server: str, client: str,
    server_conf: interop_pb2.TlsConfig, client_conf: interop_pb2.TlsConfig,
    driver: "InteropDriver", debug_logs: DebugRunLogs, cell: MatrixCell | None = None,
    tcp_host: str = "", tcp_port: int = 0, extra_error: str = "") -> Path:
    return write_cell_debug_log(repo, server=server, client=client, server_conf=server_conf,
        client_conf=client_conf, driver=driver, debug_logs=debug_logs, cell=cell, tcp_host=tcp_host,
        tcp_port=tcp_port, extra_error=extra_error, result_kind="FAIL")


def _run_driver_test_timed(driver: InteropDriver, server_conf: interop_pb2.TlsConfig,
    client_conf: interop_pb2.TlsConfig, *, tcp_host: str, tcp_port: int, client_wrapper: str,
    cell_timeout_s: float) -> tuple[bool | None, bool, Exception | None]:
    """
    Run one cell in a worker thread. Returns ``(ok, timed_out, worker_exception)``.
    ``ok`` is None when ``timed_out`` is True.
    """
    holder: dict[str, Any] = {"ok": None, "exc": None}

    def _worker() -> None:
        try:
            holder["ok"] = driver.run_test_with_configs(server_conf, client_conf,
                tcp_host=tcp_host, tcp_port=tcp_port, client_wrapper=client_wrapper)
        except Exception as e:
            holder["exc"] = e

    thread = threading.Thread(target=_worker, name="interop-cell", daemon=True)
    thread.start()
    deadline = time.monotonic() + max(0.1, cell_timeout_s)
    while thread.is_alive() and time.monotonic() < deadline:
        thread.join(timeout=_CELL_TIMEOUT_POLL_S)
    if not thread.is_alive():
        return holder["ok"], False, holder["exc"]

    logger.debug("[Driver] cell timeout (%.0fs): sending CLOSE to wrappers", cell_timeout_s)
    driver.emergency_cleanup()
    thread.join(timeout=_CELL_TIMEOUT_CLEANUP_WAIT_S)
    if thread.is_alive():
        logger.debug("[Driver] worker still running after emergency cleanup; continuing matrix")
    return None, True, holder["exc"]


def run_matrix_cell_grpc(cell: MatrixCell, session: BaseExecutionSession, *, verbose: bool,
    debug_logs: DebugRunLogs | None = None, cell_timeout_s: float = _DEFAULT_CELL_TIMEOUT_S) -> int:
    """Run one matrix cell over persistent local wrappers."""
    server = cell.server
    client = cell.client
    logger.info("========== %sx%s ==========", server, client)

    repo = session.repo
    server_conf = tls_config_from_cell(cell, interop_pb2.SERVER, repo=repo)
    client_conf = tls_config_from_cell(cell, interop_pb2.CLIENT, repo=repo)
    wroot = wrapper_filesystem_root(session)
    server_conf.repo_root = wroot
    client_conf.repo_root = wroot
    tcp_host, tcp_port = apply_matrix_tls_endpoints(server, client,
        server_conf, client_conf, repo=session.repo, cell=cell, session=session)
    driver: InteropDriver | None = None
    try:
        driver = InteropDriver(session.grpc_addr(server), session.grpc_addr(client))
        driver.server_metadata = session.metadata.get(server)
        driver.client_metadata = session.metadata.get(client)

        if skip := driver.scenario_skip_reason_for_configs(server_conf, client_conf):
            if verbose:
                logger.debug("[Driver] SKIP: %s", skip)
            else:
                short = skip[:120].replace("\n", " ")
                logger.info("SKIP  interop  (%s)", short)
            return EXIT_SKIP

        driver._last_skip_reason = None
        driver._last_failure = None
        ok, timed_out, worker_exc = _run_driver_test_timed(driver, server_conf, client_conf,
            tcp_host=tcp_host, tcp_port=tcp_port, client_wrapper=client, cell_timeout_s=cell_timeout_s)

        if timed_out:
            summary = f"cell exceeded {cell_timeout_s}s wall-clock limit (CLOSE sent, CLI processes killed)"
            driver._last_failure = ("cell_timeout", FAILURE, summary)
            if debug_logs is not None:
                log_path = write_cell_debug_log(repo, server=server, client=client,
                    server_conf=server_conf, client_conf=client_conf, driver=driver, debug_logs=debug_logs,
                    cell=cell, tcp_host=tcp_host, tcp_port=tcp_port, result_kind="TIMEOUT")
                rel = log_path.relative_to(repo) if log_path.is_relative_to(repo) else log_path
                logger.error("TEST TIMEOUT! Details saved to: %s", rel)
            if verbose:
                logger.debug("[Driver] TIMEOUT: %s", summary)
            else:
                logger.info("TIMEOUT  interop  (%s)", summary)
            return EXIT_TIMEOUT

        if worker_exc is not None:
            raise worker_exc

        if driver._last_skip_reason:
            if verbose:
                logger.debug("[Driver] SKIP: %s", driver._last_skip_reason)
                return EXIT_SKIP
            short = driver._last_skip_reason[:200].replace("\n", " ").strip()
            logger.info("SKIP  interop  (%s)", short)
            return EXIT_SKIP
        if not ok:
            if debug_logs is not None:
                log_path = write_fail_debug_log(repo, server=server, client=client,
                    server_conf=server_conf, client_conf=client_conf, driver=driver, debug_logs=debug_logs,
                    cell=cell, tcp_host=tcp_host, tcp_port=tcp_port)
                rel = log_path.relative_to(repo) if log_path.is_relative_to(repo) else log_path
                logger.error("TEST FAILED! Details saved to: %s", rel)
            if verbose:
                return 1
            detail = ""
            if driver._last_failure:
                detail = (driver._last_failure[2] or "").replace("\n", " ").strip()[:220]
            suf = f"  ({detail})" if detail else ""
            logger.info("FAIL  interop%s", suf)
            return 1
        if verbose:
            return 0
        logger.info("OK  interop")
        return 0
    except Exception as e:
        if driver is None:
            driver = InteropDriver(session.grpc_addr(server), session.grpc_addr(client))
            driver._last_failure = ("grpc", FAILURE, str(e))
        else:
            driver._last_failure = driver._last_failure or ("grpc", FAILURE, str(e))
        if debug_logs is not None:
            log_path = write_fail_debug_log(repo, server=server, client=client,
                server_conf=server_conf, client_conf=client_conf, driver=driver, debug_logs=debug_logs,
                cell=cell, tcp_host=tcp_host, tcp_port=tcp_port, extra_error=str(e))
            rel = log_path.relative_to(repo) if log_path.is_relative_to(repo) else log_path
            logger.error("TEST FAILED! Details saved to: %s", rel)
        if verbose:
            logger.debug("[Driver] exception: %s", e)
        else:
            logger.info("FAIL  interop  (%s)", str(e).replace("\n", " ").strip()[:220])
        return 1
    finally:
        remove_tls_session_artifact_files(wroot)


# --- gRPC test driver ---

SUCCESS = interop_pb2.OperationResponse.SUCCESS
FAILURE = interop_pb2.OperationResponse.FAILURE

_TCP_AFTER_ESTABLISH_S = 20.0
_TRANSMIT_GAP_S = 1.0
_NSS_RESUMPTION_PRE_TRANSMIT_S = 0.5
_TEST_PAYLOAD = b"PAYLOAD"


def _wait_grpc_channel_ready(address: str, *, deadline: float, verbose: bool) -> bool:
    channel = grpc.insecure_channel(address)
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        grpc.channel_ready_future(channel).result(timeout=min(3.0, remaining))
        if verbose:
            logger.debug("[Driver] gRPC reachable: %s", address)
        return True
    except (grpc.FutureTimeoutError, Exception):
        return False
    finally:
        try:
            channel.close()
        except Exception:
            pass


def _operation_response_detail(resp: interop_pb2.OperationResponse) -> str:
    msg = (resp.message or "").strip()
    logs = (resp.logs or "").strip()
    if msg and logs:
        return f"{msg}\n{logs}"
    return msg or logs or "no message"


class InteropDriver:
    def __init__(self, server_addr: str, client_addr: str) -> None:
        self.server_addr = server_addr
        self.client_addr = client_addr
        self._last_failure: tuple[str, int, str] | None = None
        self._last_skip_reason: str | None = None
        self._op_traces: list[OpTrace] = []
        self._last_transmit_client_data: bytes = b""
        self._last_transmit_server_data: bytes = b""
        self.session_id = uuid.uuid4().hex
        self.server_metadata: interop_pb2.LibraryMetadata | None = None
        self.client_metadata: interop_pb2.LibraryMetadata | None = None
        self._channels: list[grpc.Channel] = []
        if server_addr == client_addr:
            ch = grpc.insecure_channel(server_addr)
            self._channels.append(ch)
            stub = interop_pb2_grpc.TlsInteropWrapperStub(ch)
            self.server_stub = stub
            self.client_stub = stub
        else:
            ch_s = grpc.insecure_channel(server_addr)
            ch_c = grpc.insecure_channel(client_addr)
            self._channels.extend([ch_s, ch_c])
            self.server_stub = interop_pb2_grpc.TlsInteropWrapperStub(ch_s)
            self.client_stub = interop_pb2_grpc.TlsInteropWrapperStub(ch_c)

    def _record_response(self, resp: interop_pb2.OperationResponse, label: str) -> OpTrace:
        neg = None
        if (resp.negotiated.protocol_version or resp.negotiated.cipher_suite or resp.negotiated.named_group
            or resp.negotiated.hrr_occurred):
            neg = interop_pb2.NegotiatedTlsParameters()
            neg.CopyFrom(resp.negotiated)
        trace = OpTrace(label=label, status=resp.status, message=(resp.message or "").strip(),
            logs=(resp.logs or "").strip(), negotiated=neg, output_data=bytes(resp.output_data or b""))
        self._op_traces.append(trace)
        if label.startswith("TRANSMIT client"):
            self._last_transmit_client_data = trace.output_data
        elif label.startswith("TRANSMIT server"):
            self._last_transmit_server_data = trace.output_data
        return trace

    def _log_metadata(self, label: str, metadata: interop_pb2.LibraryMetadata) -> None:
        role_names: Mapping[int, str] = {
            interop_pb2.CLIENT: "CLIENT",
            interop_pb2.SERVER: "SERVER",
        }
        roles_str = [role_names.get(r, str(r)) for r in metadata.roles]
        logger.debug("[Driver] %s: %s %s", label, metadata.component_name, metadata.version)
        logger.debug("         roles=%s", roles_str)
        versions = [c.name for c in metadata.supported_versions]
        suf = "..." if len(versions) > 5 else ""
        logger.debug("         supported_versions=%s%s", versions[:5], suf)

    def _metadata_can_negotiate_version(self, metadata: interop_pb2.LibraryMetadata | None,
        capability_name: str, role: int) -> bool:
        if metadata is None:
            return True
        if metadata.roles and role not in metadata.roles:
            return False
        caps = list(metadata.supported_versions)
        if not caps:
            return True
        return any(c.name == capability_name and interop_pb2.NEGOTIATE in c.flags for c in caps)

    def scenario_skip_reason_for_configs(self, server_conf: interop_pb2.TlsConfig,
        client_conf: interop_pb2.TlsConfig) -> str | None:
        """Skip run if peer metadata disagrees with role ``TlsConfig`` values."""
        if self.server_metadata is None or self.client_metadata is None:
            return None
        srv = server_conf
        cli = client_conf
        return self._scenario_skip_reason_impl(srv, cli)

    def _scenario_skip_reason_impl(self, srv: interop_pb2.TlsConfig, cli: interop_pb2.TlsConfig) -> str | None:
        cap_srv = tls_version_to_capability_name(srv.version)
        cap_cli = tls_version_to_capability_name(cli.version)
        if not self._metadata_can_negotiate_version(self.server_metadata, cap_srv, interop_pb2.SERVER):
            cn = self.server_metadata.component_name
            return f"server ({cn}) cannot negotiate {cap_srv} per GetMetadata"
        if not self._metadata_can_negotiate_version(self.client_metadata, cap_cli, interop_pb2.CLIENT):
            cn = self.client_metadata.component_name
            return f"client ({cn}) cannot negotiate {cap_cli} per GetMetadata"
        if (ciph := (srv.cipher_suite or "").strip()):
            cn_s = self.server_metadata.component_name
            if not self._metadata_supports_cipher(self.server_metadata, ciph):
                return f"server ({cn_s}) cannot offer cipher '{ciph}' per GetMetadata"
        if (ciph := (cli.cipher_suite or "").strip()):
            cn_c = self.client_metadata.component_name
            if not self._metadata_supports_cipher(self.client_metadata, ciph):
                return f"client ({cn_c}) cannot offer cipher '{ciph}' per GetMetadata"
        if (grp := list(srv.supported_groups)):
            cn_s = self.server_metadata.component_name
            if not self._metadata_supports_groups(self.server_metadata, grp):
                return f"server ({cn_s}) lacks group(s) {grp} per GetMetadata"
        if (grp := list(cli.supported_groups)):
            cn_c = self.client_metadata.component_name
            if not self._metadata_supports_groups(self.client_metadata, grp):
                return f"client ({cn_c}) lacks group(s) {grp} per GetMetadata"
        return None

    def _metadata_supports_cipher(self, metadata: interop_pb2.LibraryMetadata | None, catalog_cipher: str) -> bool:
        if metadata is None or not (catalog_cipher or "").strip():
            return True
        cat_fold = norm_token(catalog_cipher)
        if not cat_fold:
            return True
        for cap in metadata.cipher_suites:
            native_fold = norm_token(cap.name or "")
            if native_fold and cat_fold in native_fold:
                return True
        return False

    def _metadata_supports_groups(self, metadata: interop_pb2.LibraryMetadata | None, group_tokens: list[str]) -> bool:
        if metadata is None or not group_tokens:
            return True
        avail = {norm_token(c.name) for c in metadata.groups}
        for g in group_tokens:
            gt = norm_token(g)
            if gt in avail:
                continue
            if not any(gt in m or m in gt or gt == m for m in avail):
                return False
        return True

    def _check_response(self, resp: interop_pb2.OperationResponse, label: str) -> bool:
        trace = self._record_response(resp, label)
        msg = trace.message
        if resp.status == SUCCESS and msg.lower().startswith("skip:"):
            self._last_skip_reason = msg[5:].strip() or "wrapper reported unsupported option"
            logger.debug("[Driver] %s: SKIP - %s", label, self._last_skip_reason)
            return False
        if resp.status == SUCCESS:
            if trace.logs:
                first = trace.logs.split("\n", 1)[0]
                logger.debug("[Driver] %s (wrapper cmd): %s", label, first)
            return True
        fail_summary = msg or "no message"
        self._last_failure = (label, resp.status, fail_summary)
        lab = "FAILURE" if resp.status == FAILURE else "ERROR"
        logger.debug("[Driver] %s: %s - %s", label, lab, fail_summary)
        return False

    def _check_hrr_assertion(self, resp: interop_pb2.OperationResponse, client_conf: interop_pb2.TlsConfig,
        label: str, *, client_wrapper: str = "") -> bool:
        if not getattr(client_conf, "expect_hrr", False):
            return True
        cw = (client_wrapper or "").strip().lower()
        if cw == "nss":
            logger.debug("[Driver] %s: HRR assertion skipped (NSS client cannot provoke HRR reliably)", label)
            return True
        if resp.negotiated.hrr_occurred:
            logger.debug("[Driver] %s: HRR assertion OK", label)
            return True
        summary = "expected Hello Retry Request (expect_hrr=true) but negotiated.hrr_occurred is false"
        self._last_failure = (label, FAILURE, summary)
        logger.debug("[Driver] %s: FAILURE - %s", label, summary)
        return False

    def _operation_request(self, op_type: int, *, role: int = 0, payload: bytes = b"",
        config: interop_pb2.TlsConfig | None = None) -> interop_pb2.OperationRequest:
        req = interop_pb2.OperationRequest(type=op_type, session_id=self.session_id)
        if role:
            req.role = role
        if payload:
            req.payload = payload
        if config is not None:
            req.config.CopyFrom(config)
        return req

    def _execute_establish(self, stub: interop_pb2_grpc.TlsInteropWrapperStub,
        role: int, cfg: interop_pb2.TlsConfig) -> interop_pb2.OperationResponse:
        return stub.ExecuteOperation(self._operation_request(interop_pb2.OperationRequest.ESTABLISH,
            role=role, config=cfg))

    def _cleanup(self) -> None:
        logger.debug("[Driver] Cleaning up...")
        close_req = self._operation_request(interop_pb2.OperationRequest.CLOSE)
        for stub, role in [(self.server_stub, "server"), (self.client_stub, "client")]:
            try:
                self._check_response(stub.ExecuteOperation(close_req), f"CLOSE {role}")
            except Exception as e:
                logger.info("FAIL  CLOSE %s: %s", role, e)

    def emergency_cleanup(self, *, grpc_timeout_s: float = _EMERGENCY_CLOSE_GRPC_S) -> None:
        """On cell timeout: CLOSE both roles with a short gRPC deadline (kills wrapper CLI procs)."""
        close_req = self._operation_request(interop_pb2.OperationRequest.CLOSE)
        for stub, role in [(self.server_stub, "server"), (self.client_stub, "client")]:
            try:
                resp = stub.ExecuteOperation(close_req, timeout=max(0.5, grpc_timeout_s))
                self._record_response(resp, f"CLOSE {role} (timeout watchdog)")
            except Exception as e:
                trace = OpTrace(label=f"CLOSE {role} (timeout watchdog)", status=interop_pb2.OperationResponse.ERROR,
                    message=str(e), logs="", negotiated=None, output_data=b"")
                self._op_traces.append(trace)
                logger.debug("[Driver] emergency CLOSE %s: %s", role, e)

    def _run_post_establish_round_trip(self, *, server_conf: interop_pb2.TlsConfig,
        client_conf: interop_pb2.TlsConfig, tcp_host: str, tcp_port: int, ver: str, client_wrapper: str = "") -> bool:
        """Host TCP check, TRANSMIT client→server, verify echoed payload."""
        ok_peer, tcp_err = wait_tcp_connect(tcp_host, int(tcp_port), timeout_s=_TCP_AFTER_ESTABLISH_S)
        if not ok_peer:
            logger.debug("[Driver] Timeout waiting for TCP %s:%s", tcp_host, tcp_port)
            summary = f"TCP {tcp_host}:{tcp_port} not accepting after ESTABLISH ({tcp_err})"
            establish_hints: list[str] = []
            for trace in self._op_traces:
                if trace.label.startswith("ESTABLISH"):
                    establish_hints.append(f"{trace.label}: {trace.message or 'ok'}")
            if establish_hints:
                summary += "\nPrior ESTABLISH: " + "; ".join(establish_hints)
            self._last_failure = ("wait_tcp", FAILURE, summary)
            return False

        if (client_wrapper or "").strip().lower() == "nss" and tls_config_resumption_or_0rtt_active(client_conf):
            time.sleep(_NSS_RESUMPTION_PRE_TRANSMIT_S)

        logger.debug("[Driver] Transmitting: %s", _TEST_PAYLOAD.decode())
        r_tx = self.client_stub.ExecuteOperation(self._operation_request(
            interop_pb2.OperationRequest.TRANSMIT, role=interop_pb2.CLIENT, payload=_TEST_PAYLOAD))
        if not self._check_response(r_tx, "TRANSMIT client"):
            return False

        time.sleep(_TRANSMIT_GAP_S)
        r_srv = self.server_stub.ExecuteOperation(self._operation_request(
            interop_pb2.OperationRequest.TRANSMIT, role=interop_pb2.SERVER))
        if not self._check_response(r_srv, "TRANSMIT server"):
            return False

        if _TEST_PAYLOAD in r_srv.output_data:
            logger.debug(">>> PASSED: payload echoed (TLS %s) <<<", ver)
            return True
        logger.debug(">>> FAILED: echo mismatch <<<")
        summary = "server output did not contain echoed payload"
        summary += "\nexpected payload: " + _TEST_PAYLOAD.decode(errors="replace")
        summary += "\nTRANSMIT client output_data:\n" + _format_output_data(self._last_transmit_client_data)
        summary += "\nTRANSMIT server output_data:\n" + _format_output_data(self._last_transmit_server_data)
        self._last_failure = ("verify", FAILURE, summary)
        return False

    def _run_resumption_or_0rtt_test(self, server_conf: interop_pb2.TlsConfig,
        client_conf: interop_pb2.TlsConfig, *, tcp_host: str, tcp_port: int, client_wrapper: str = "") -> bool:
        """Server stays up; client save handshake then resume (final result + logs from resume)."""
        ver = (server_conf.version or "").strip() or "default"
        try:
            logger.debug("[Driver] Resumption/0-RTT round-trip (TLS %s)", ver)
            logger.debug("[Driver] Establishing server (persistent)...")
            r = self._execute_establish(self.server_stub, interop_pb2.SERVER, server_conf)
            if not self._check_response(r, "ESTABLISH server"):
                return False

            save_conf = _copy_tls_config(client_conf)
            save_conf.resumption_step = "save"
            logger.debug("[Driver] Resumption step 1: save session ticket...")
            r = self._execute_establish(self.client_stub, interop_pb2.CLIENT, save_conf)
            if not self._check_response(r, "ESTABLISH client (resumption save)"):
                return False
            if not self._check_hrr_assertion(r, client_conf, "ESTABLISH client (resumption save)",
                client_wrapper=client_wrapper):
                return False

            resume_conf = _copy_tls_config(client_conf)
            resume_conf.resumption_step = "resume"
            logger.debug("[Driver] Resumption step 2: resume session...")
            r = self._execute_establish(self.client_stub, interop_pb2.CLIENT, resume_conf)
            if not self._check_response(r, "ESTABLISH client (resumption resume)"):
                return False

            return self._run_post_establish_round_trip(server_conf=server_conf, client_conf=client_conf,
                tcp_host=tcp_host, tcp_port=tcp_port, ver=ver, client_wrapper=client_wrapper)
        finally:
            self._cleanup()

    def run_test_with_configs(self, server_conf: interop_pb2.TlsConfig, client_conf: interop_pb2.TlsConfig,
        *, tcp_host: str, tcp_port: int, client_wrapper: str = "") -> bool:
        """ESTABLISH server → client → host TCP check → TRANSMIT → CLOSE (wrapper idle)."""
        self._last_skip_reason = None
        if tls_config_resumption_or_0rtt_active(client_conf):
            return self._run_resumption_or_0rtt_test(server_conf, client_conf,
                tcp_host=tcp_host, tcp_port=tcp_port, client_wrapper=client_wrapper)
        ver = (server_conf.version or "").strip() or "default"
        try:
            logger.debug("[Driver] Round-trip (TLS %s)", ver)
            logger.debug("[Driver] Establishing connection...")
            r = self._execute_establish(self.server_stub, interop_pb2.SERVER, server_conf)
            if not self._check_response(r, "ESTABLISH server"):
                return False
            r = self._execute_establish(self.client_stub, interop_pb2.CLIENT, client_conf)
            if not self._check_response(r, "ESTABLISH client"):
                return False
            if not self._check_hrr_assertion(r, client_conf, "ESTABLISH client", client_wrapper=client_wrapper):
                return False

            return self._run_post_establish_round_trip(server_conf=server_conf, client_conf=client_conf,
                tcp_host=tcp_host, tcp_port=tcp_port, ver=ver, client_wrapper=client_wrapper)
        finally:
            self._cleanup()

"""TLS interop runner: local wrapper subprocesses + gRPC matrix driver."""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

import grpc

from core.catalog import (
    backend_grpc_addr, backend_tls_endpoint, cell_capability_skip_reason,
    check_local_cli_tools, discover_wrapper_ids, ensure_import_paths, load_capabilities,
    merged_orchestration_env, norm_token, normalize_cell_tls_micro_params, parse_asymmetric,
    session_wrapper_env, tls_version_to_capability_name)

ensure_import_paths()

from wrappers.utils import remove_tls_session_artifact_files, test_feature_enabled_in_config
from proto import interop_pb2, interop_pb2_grpc
from wrappers.base import split_asymmetric_csv, wait_tcp_connect

# Distinct from 0 (pass) and 1 (fail) so matrix runners can show SKIP vs OK / TIMEOUT.
EXIT_SKIP = 77
EXIT_TIMEOUT = 78

DEFAULT_GRPC_STARTUP_S = 90.0
DEFAULT_CELL_TIMEOUT_S = 45.0
EMERGENCY_CLOSE_GRPC_S = 10.0
WORKER_PORT_STRIDE = 100
MAX_PARALLEL_JOBS = 32


def _worker_slot_grpc_overrides(
    repo: Path, backends: frozenset[str] | set[str], slot_id: int,
    base_overrides: Mapping[str, int] | None = None) -> dict[str, int]:
    """gRPC listen ports per backend for one parallel worker slot."""
    overrides = {k.strip().lower(): int(v) for k, v in (base_overrides or {}).items()}
    offset = int(slot_id) * WORKER_PORT_STRIDE
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


def ensure_certs(repo: Path, *, verbose: bool = False) -> None:
    """Create ``certs/{prefix}.crt`` bundles when any are missing."""
    from core.identity import IDENTITY_PREFIXES

    cert_dir = repo / "certs"
    missing = [
        prefix
        for prefix in IDENTITY_PREFIXES
        if not (cert_dir / f"{prefix}.crt").is_file()
        or not (cert_dir / f"{prefix}.key").is_file()
    ]
    if not missing:
        return
    script = repo / "core" / "gen_interop_certs.sh"
    if not script.is_file():
        raise FileNotFoundError(
            f"Missing certs/ bundles ({', '.join(missing)}); "
            f"run core/gen_interop_certs.sh or create certs/ manually")
    if verbose:
        print(f"Generating identity PEMs ({', '.join(missing)}) via {script}")
    subprocess.run(["bash", str(script)], cwd=repo, check=True)


def remove_certs(repo: Path, *, verbose: bool = False) -> None:
    """Remove ``certs/`` after a matrix run."""
    cert_dir = repo / "certs"
    if not cert_dir.is_dir():
        return
    if verbose:
        print(f"Removing generated {cert_dir}")
    shutil.rmtree(cert_dir, ignore_errors=True)


def apply_matrix_tls_endpoints(
    server: str, client: str, server_conf: interop_pb2.TlsConfig,
    client_conf: interop_pb2.TlsConfig, *, repo: Path,
    cell: dict[str, str] | None = None, session: BaseExecutionSession | None = None) -> tuple[str, int]:
    """Return host TCP coordinates for the driver check after ESTABLISH."""
    port_raw = ((cell or {}).get("tls_port") or "").strip()
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


def required_backends_from_matrix(
    axis_keys: list[str], combos: list[tuple[Any, ...]], *, args_template: Any,
    repo: Path, known: frozenset[str]) -> tuple[frozenset[str], int]:
    """
    Collect backends needed by non-SKIP matrix cells.

    Returns ``(backend_ids, skip_count)``.
    """
    needed: set[str] = set()
    skips = 0
    for tup in combos:
        cell = {k: str(v) for k, v in zip(axis_keys, tup)}
        cell = normalize_cell_tls_micro_params(cell, args_template, repo)
        if cell_capability_skip_reason(cell, repo):
            skips += 1
            continue
        srv = (cell.get("server") or "").strip().lower()
        cli = (cell.get("client") or "").strip().lower()
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


def serve_wrapper_process(backend: str) -> int:
    """Block as one wrapper gRPC service (driver-spawned subprocess entry)."""
    import runpy

    name = (backend or "").strip().lower()
    repo = Path.cwd()
    known = discover_wrapper_ids(repo)
    if name not in known:
        print(f"Unknown wrapper {name!r}. Known: {', '.join(known)}", file=sys.stderr)
        return 2
    if not os.environ.get("GRPC_PORT"):
        addr = backend_grpc_addr(name, repo)
        _, _, port_s = addr.rpartition(":")
        if port_s.isdigit():
            os.environ["GRPC_PORT"] = port_s
    load_capabilities(name, repo)
    runpy.run_module(f"wrappers.{name}.wrapper", run_name="__main__")
    return 0


class WrapperSession(BaseExecutionSession):
    """Start wrapper gRPC services as host subprocesses, or attach to existing ones."""

    def __init__(
        self, repo: Path, backends: frozenset[str], *, verbose: bool = False,
        attach: bool = False, grpc_port_overrides: Mapping[str, int] | None = None) -> None:
        known = frozenset(discover_wrapper_ids(repo))
        unknown = backends - known
        if unknown:
            raise ValueError(f"Unknown backend(s): {sorted(unknown)}")
        self.repo = repo.resolve()
        self.backends = sorted(backends)
        self.verbose = verbose
        self.attach = attach
        self._grpc_port_overrides = {
            k.strip().lower(): int(v) for k, v in (grpc_port_overrides or {}).items()
        }
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
        # Do not inject PYTHONPATH: cwd is the repo for ``python -c`` spawn, and
        # forcing PYTHONPATH on Fedora makes distro ``google.protobuf`` shadow pip.
        env.pop("PYTHONPATH", None)
        return env

    def _wrapper_cmd(self, backend: str) -> list[str]:
        # ``cwd`` is the repo; avoid ``python -m`` (Fedora protobuf) and CLI ``--serve``.
        code = (
            "from core.catalog import ensure_import_paths; ensure_import_paths(); "
            "from core.runner import serve_wrapper_process; "
            "import sys; raise SystemExit(serve_wrapper_process(sys.argv[1]))")
        return [sys.executable, "-c", code, backend]

    def _wrapper_crash_report(self) -> str | None:
        """If a spawned wrapper exited, return a diagnostic including its output."""
        parts: list[str] = []
        for backend, proc in zip(self.backends, self._procs):
            code = proc.poll()
            if code is None:
                continue
            out = ""
            if proc.stdout is not None:
                try:
                    out = proc.stdout.read().decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
            detail = f"Wrapper {backend} exited (code {code})"
            if out:
                detail += f":\n{out}"
            parts.append(detail)
        return "\n".join(parts) if parts else None

    def up(self) -> None:
        if not self.backends:
            return
        if self.attach:
            targets = ", ".join(f"{b} @ {self.grpc_addr(b)}" for b in self.backends)
            print(f"Attach mode: connecting to existing wrapper(s) on localhost ({targets})")
            return
        try:
            import grpc  # noqa: F401
        except ImportError as e:
            raise RuntimeError(
                "Requires grpcio on the host Python "
                "(pip install 'grpcio>=1.60' 'protobuf>=4.21')") from e
        ensure_certs(self.repo, verbose=self.verbose)
        missing = check_local_cli_tools(self.backends, self.repo)
        if missing:
            raise RuntimeError(
                "Requires TLS CLI tools on PATH:\n  " + "\n  ".join(missing))
        for backend in self.backends:
            addr = self.grpc_addr(backend)
            host, port = _grpc_host_port(addr)
            in_use, _ = wait_tcp_connect(host, port, timeout_s=0.35)
            if in_use:
                raise RuntimeError(
                    f"Port {port} already in use ({addr}); stop other wrapper processes")
        if self.verbose:
            print(f"Starting wrappers: {', '.join(self.backends)}")
        for backend in self.backends:
            cmd = self._wrapper_cmd(backend)
            if self.verbose:
                print(f"[Wrapper] {backend}: {' '.join(cmd)} (GRPC_PORT from env)")
            proc = subprocess.Popen(
                cmd, cwd=self.repo, env=self._wrapper_env(backend), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE if self.verbose else subprocess.DEVNULL,
                stderr=subprocess.STDOUT if self.verbose else subprocess.DEVNULL,
                start_new_session=True)
            self._procs.append(proc)
            if proc.poll() is not None:
                out = ""
                if proc.stdout is not None:
                    try:
                        out = proc.stdout.read().decode("utf-8", errors="replace")
                    except Exception:
                        pass
                raise RuntimeError(
                    f"Wrapper {backend} exited immediately (code {proc.returncode})"
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

    def wait_grpc_ready(self, timeout_s: float = DEFAULT_GRPC_STARTUP_S) -> None:
        grpc_startup_poll_s = 0.4
        addrs = sorted({self.grpc_addr(b) for b in self.backends})
        if not addrs:
            return
        deadline = time.monotonic() + timeout_s
        pending = set(addrs)
        while time.monotonic() < deadline and pending:
            crash = self._wrapper_crash_report()
            if crash:
                raise RuntimeError(crash)
            for addr in list(pending):
                if _wait_grpc_channel_ready(addr, deadline=deadline, verbose=self.verbose):
                    pending.discard(addr)
            if pending:
                time.sleep(grpc_startup_poll_s)
        if pending:
            crash = self._wrapper_crash_report()
            if crash:
                raise RuntimeError(crash)
            raise TimeoutError(
                f"gRPC not reachable within {timeout_s}s: {', '.join(sorted(pending))}")

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
        self.up()
        self.wait_grpc_ready()
        self.load_metadata()

    def stop(self) -> None:
        self.down()


class WorkerSlotSession(WrapperSession):
    """Isolated wrapper subprocess set for one parallel matrix worker (unique gRPC/TLS ports)."""

    def __init__(
        self, repo: Path, backends: frozenset[str], slot_id: int, *, verbose: bool = False,
        grpc_port_overrides: Mapping[str, int] | None = None) -> None:
        overrides = _worker_slot_grpc_overrides(
            repo, backends, slot_id, grpc_port_overrides)
        super().__init__(
            repo, backends, verbose=verbose, attach=False, grpc_port_overrides=overrides)
        self.slot_id = int(slot_id)

    def tls_endpoint(self, backend: str) -> tuple[str, int]:
        key = (backend or "").strip().lower()
        host, base_port = backend_tls_endpoint(key, self.repo)
        return host, base_port + self.slot_id * WORKER_PORT_STRIDE

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

    def __init__(
        self, repo: Path, backends: frozenset[str], num_slots: int, *, verbose: bool = False,
        grpc_base_overrides: Mapping[str, int] | None = None) -> None:
        if num_slots < 1:
            raise ValueError("num_slots must be >= 1")
        self.repo = repo.resolve()
        self.backends = frozenset(backends)
        self.verbose = verbose
        self._sessions = [
            WorkerSlotSession(
                self.repo, self.backends, slot_id=i, verbose=verbose,
                grpc_port_overrides=grpc_base_overrides)
            for i in range(num_slots)
        ]

    def session(self, slot_id: int) -> WorkerSlotSession:
        return self._sessions[int(slot_id)]

    def start(self) -> None:
        for session in self._sessions:
            session.start()
        if self.verbose:
            print(
                f"Parallel workers: {len(self._sessions)} slot(s), port stride {WORKER_PORT_STRIDE}")

    def stop(self) -> None:
        for session in self._sessions:
            session.stop()


def _pick_cell_scalar(cell: dict[str, str], field: str, *, server: bool) -> str:
    raw = (cell.get(field) or "").strip()
    if not raw:
        return ""
    if ":" in raw:
        left, right = parse_asymmetric(raw)
        return left if server else right
    return raw


def _pick_cell_list(cell: dict[str, str], field: str, *, server: bool) -> list[str]:
    raw = (cell.get(field) or "").strip()
    if not raw:
        return []
    left, right = split_asymmetric_csv(raw)
    return list(left if server else right)


def _server_accepts_inline_pem_identity(backend: str, repo: Path) -> bool:
    """False when wrapper uses out-of-band identity (e.g. NSS DB nicknames)."""
    try:
        rt = load_capabilities(backend, repo).get("runtime") or {}
    except (FileNotFoundError, ValueError):
        return True
    blocked = frozenset(rt.get("unsupported_tls_fields") or ())
    return "certificate" not in blocked and "private_key" not in blocked


def _attach_cell_server_identity(cfg: interop_pb2.TlsConfig, cell: dict[str, str], *, repo: Path) -> None:
    """Load server leaf PEM bytes from ``certs/{prefix}.*`` for this cell's sig schemes."""
    from core.identity import (
        get_cert_prefix_for_cipher_suite, get_cert_prefix_for_schemes,
        read_identity_pem_bytes)

    schemes = _pick_cell_list(cell, "signature_schemes", server=True)
    if schemes:
        prefix = get_cert_prefix_for_schemes(schemes)
    else:
        cs = _pick_cell_scalar(cell, "cipher_suite", server=True)
        prefix = get_cert_prefix_for_cipher_suite(cs)
    cert_b, key_b = read_identity_pem_bytes(prefix, repo=repo)
    if cert_b and key_b:
        cfg.certificate = cert_b
        cfg.private_key = key_b


def tls_config_from_cell(cell: dict[str, str], role: int, *, repo: Path | None = None) -> interop_pb2.TlsConfig:
    """Build ``TlsConfig`` for one matrix role from a normalized cell dict."""
    server = role == interop_pb2.SERVER
    cfg = interop_pb2.TlsConfig()
    ver = _pick_cell_scalar(cell, "tls_version", server=server)
    if ver:
        cfg.version = ver
    else:
        cfg.version = "1.3"
    cs = _pick_cell_scalar(cell, "cipher_suite", server=server)
    if cs:
        cfg.cipher_suite = cs
    port_raw = _pick_cell_scalar(cell, "tls_port", server=server)
    if port_raw:
        cfg.port = int(port_raw)
    elif (cell.get("tls_port") or "").strip() == "":
        cfg.port = 5555
    cfg.supported_groups.extend(_pick_cell_list(cell, "supported_groups", server=server))
    cfg.signature_schemes.extend(_pick_cell_list(cell, "signature_schemes", server=server))
    # Other role's schemes → trust/peer leaf selection (``signature_schemes_cert``).
    peer_schemes = _pick_cell_list(cell, "signature_schemes", server=not server)
    if peer_schemes:
        cfg.signature_schemes_cert.extend(peer_schemes)
    cfg.alpn_protocols.extend(_pick_cell_list(cell, "alpn", server=server))
    from core.catalog import enabled_test_features_from_cell

    cfg.psk_modes.extend(sorted(enabled_test_features_from_cell(cell)))
    if cell.get("expect_hrr") == "true":
        cfg.expect_hrr = True
    if server and repo is not None:
        backend = (cell.get("server") or "").strip().lower()
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


def _console_print(console_lock: threading.Lock | None, *args: Any, **kwargs: Any) -> None:
    if console_lock is not None:
        with console_lock:
            print(*args, **kwargs)
    else:
        print(*args, **kwargs)


def _format_output_data(data: bytes) -> str:
    if not data:
        return "(empty)"
    ascii_repr = data.decode("ascii", errors="replace")
    return f"len={len(data)}\nascii: {ascii_repr!r}\nhex: {data.hex()}"


def _negotiated_debug_text(neg: interop_pb2.NegotiatedTlsParameters | None) -> str:
    if neg is None:
        return "(none)"
    parts = [
        f"protocol_version={neg.protocol_version}"
        if (neg.protocol_version or "").strip() else "",
        f"cipher_suite={neg.cipher_suite}" if (neg.cipher_suite or "").strip() else "",
        f"named_group={neg.named_group}" if (neg.named_group or "").strip() else "",
        "hrr_occurred=true" if neg.hrr_occurred else ""]
    return ", ".join(p for p in parts if p) or "(empty negotiated block)"


def _metadata_debug_text(label: str, meta: interop_pb2.LibraryMetadata | None) -> str:
    if meta is None:
        return f"{label}: (not loaded)"
    sample = lambda caps: ", ".join(c.name for c in caps[:8]) or "-"
    return "\n".join([
        f"{label}: {meta.component_name} {meta.version}",
        f"  roles: {', '.join(str(r) for r in meta.roles) or '-'}",
        f"  supported_versions (sample): {sample(meta.supported_versions)}",
        f"  cipher_suites (sample): {sample(meta.cipher_suites)}",
        f"  groups (sample): {sample(meta.groups)}"])


def _wrapper_env_debug_text(repo: Path, backends: list[str]) -> str:
    active = frozenset(backends)
    lines = ["=== Orchestration environment ==="]
    merged = merged_orchestration_env(active)
    lines += [f"{k}={merged[k]}" for k in sorted(merged)] or ["(no merged orchestration env)"]
    for backend in sorted(active):
        env = session_wrapper_env(backend, repo, active)
        lines.append(f"--- {backend} session_wrapper_env ---")
        lines += [f"{k}={env[k]}" for k in sorted(env)] or ["(empty)"]
    return "\n".join(lines)


def _tls_config_debug_text(label: str, cfg: interop_pb2.TlsConfig) -> str:
    cert_b = getattr(cfg, "certificate", None) or b""
    key_b = getattr(cfg, "private_key", None) or b""
    join = lambda xs: ", ".join(xs) or "-"
    inline = lambda blob: f"yes ({len(blob)} bytes)" if blob.strip() else "no"
    fields = [
        ("version", cfg.version or "-"),
        ("cipher_suite", cfg.cipher_suite or "-"),
        ("port", cfg.port),
        ("server_hostname", cfg.server_hostname or "-"),
        ("supported_groups", join(cfg.supported_groups)),
        ("signature_schemes", join(cfg.signature_schemes)),
        ("signature_schemes_cert", join(cfg.signature_schemes_cert)),
        ("alpn_protocols", join(cfg.alpn_protocols)),
        ("supported_versions", join(cfg.supported_versions)),
        ("psk_modes / test_features", join(cfg.psk_modes)),
        ("resumption_step", cfg.resumption_step or "-"),
        ("repo_root", cfg.repo_root or "-"),
        ("certificate inline", inline(cert_b)),
        ("private_key inline", inline(key_b)),
        ("ca_file", cfg.ca_file or "-"),
        ("ca_path", cfg.ca_path or "-"),
        ("session_tickets_enabled", cfg.session_tickets_enabled),
        ("enable_early_data", cfg.enable_early_data),
        ("prefer_server_ciphers", cfg.prefer_server_ciphers),
        ("record_size_limit", cfg.record_size_limit or "-"),
        ("max_fragment_length", cfg.max_fragment_length or "-"),
        ("ocsp_stapling", cfg.ocsp_stapling),
        ("renegotiation", cfg.renegotiation or "-"),
        ("post_handshake_auth", cfg.post_handshake_auth),
        ("expect_hrr", cfg.expect_hrr)]
    return "\n".join([f"=== {label} TlsConfig ==="] + [f"{k}: {v}" for k, v in fields])


@dataclass
class OpTrace:
    label: str
    status: int
    message: str
    logs: str
    negotiated: interop_pb2.NegotiatedTlsParameters | None = None
    output_data: bytes = b""


def _format_op_trace(trace: OpTrace) -> str:
    status_name = {
        interop_pb2.OperationResponse.SUCCESS: "SUCCESS",
        interop_pb2.OperationResponse.FAILURE: "FAILURE",
        interop_pb2.OperationResponse.ERROR: "ERROR"
    }.get(trace.status, str(trace.status))
    parts = [f"--- {trace.label} (status={status_name}) ---"]
    if trace.message:
        parts.append(f"message: {trace.message}")
    if trace.negotiated is not None:
        parts.append(f"negotiated: {_negotiated_debug_text(trace.negotiated)}")
    if trace.output_data:
        parts.extend(["output_data:", _format_output_data(trace.output_data)])
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


def _cell_log_basename(server: str, client: str, cell: dict[str, str] | None, *, kind: str) -> str:
    base = f"{server}_x_{client}"
    if cell:
        tags: list[str] = []
        for key in (
            "tls_version", "cipher_suite", "supported_groups", "signature_schemes",
            "alpn", "tls_port"):
            raw = (cell.get(key) or "").strip()
            if raw:
                safe = re.sub(r"[^\w.-]+", "-", raw)[:48]
                tags.append(safe)
        if tags:
            base = f"{base}_{'_'.join(tags)}"
    prefix = f"{kind.lower()}_" if kind else "fail_"
    return f"{prefix}{base}.log"


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


def write_cell_debug_log(
    repo: Path, *, server: str, client: str, server_conf: interop_pb2.TlsConfig,
    client_conf: interop_pb2.TlsConfig, driver: "InteropDriver", debug_logs: DebugRunLogs,
    cell: dict[str, str] | None = None, tcp_host: str = "", tcp_port: int = 0,
    extra_error: str = "", result_kind: str = "FAIL") -> Path:
    """Write one cell log into the run's debug directory; return the log file path."""
    debug_run_dir = debug_logs.ensure_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    kind = (result_kind or "FAIL").strip().upper()
    path = _unique_log_path(
        debug_run_dir, _cell_log_basename(server, client, cell, kind=kind))
    parts: list[str] = [
        f"TLS interop {kind} log",
        f"timestamp: {ts}",
        f"server: {server}",
        f"client: {client}"]
    if cell:
        parts.append(
            "matrix_cell: "
            + ", ".join(f"{k}={v}" for k, v in sorted(cell.items()) if str(v).strip()))
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


def _run_driver_test_timed(
    driver: InteropDriver, server_conf: interop_pb2.TlsConfig,
    client_conf: interop_pb2.TlsConfig, *, tcp_host: str, tcp_port: int,
    client_wrapper: str, cell_timeout_s: float, verbose: bool) -> tuple[bool | None, bool, Exception | None]:
    """
    Run one cell in a worker thread. Returns ``(ok, timed_out, worker_exception)``.
    ``ok`` is None when ``timed_out`` is True.
    """
    cell_timeout_poll_s = 0.25
    cell_timeout_cleanup_wait_s = 15.0
    holder: dict[str, Any] = {"ok": None, "exc": None}

    def _worker() -> None:
        try:
            holder["ok"] = driver.run_test_with_configs(
                server_conf, client_conf, tcp_host=tcp_host, tcp_port=tcp_port,
                client_wrapper=client_wrapper)
        except Exception as e:
            holder["exc"] = e

    thread = threading.Thread(target=_worker, name="interop-cell", daemon=True)
    thread.start()
    deadline = time.monotonic() + max(0.1, cell_timeout_s)
    while thread.is_alive() and time.monotonic() < deadline:
        thread.join(timeout=cell_timeout_poll_s)
    if not thread.is_alive():
        return holder["ok"], False, holder["exc"]

    if verbose:
        print(f"[Driver] cell timeout ({cell_timeout_s}s): sending CLOSE to wrappers")
    driver.emergency_cleanup()
    thread.join(timeout=cell_timeout_cleanup_wait_s)
    if thread.is_alive() and verbose:
        print("[Driver] worker still running after emergency cleanup; continuing matrix")
    return None, True, holder["exc"]


def run_matrix_cell_grpc(
    cell: dict[str, str], session: BaseExecutionSession, *, verbose: bool,
    debug_logs: DebugRunLogs | None = None, cell_timeout_s: float = DEFAULT_CELL_TIMEOUT_S,
    console_lock: threading.Lock | None = None) -> int:
    """Run one matrix cell over persistent local wrappers."""
    server = (cell.get("server") or "").strip().lower()
    client = (cell.get("client") or "").strip().lower()
    _console_print(console_lock, f"========== {server}x{client} ==========")

    repo = session.repo
    server_conf = tls_config_from_cell(cell, interop_pb2.SERVER, repo=repo)
    client_conf = tls_config_from_cell(cell, interop_pb2.CLIENT, repo=repo)
    wroot = wrapper_filesystem_root(session)
    server_conf.repo_root = wroot
    client_conf.repo_root = wroot
    tcp_host, tcp_port = apply_matrix_tls_endpoints(
        server, client, server_conf, client_conf, repo=session.repo, cell=cell,
        session=session)
    driver: InteropDriver | None = None
    try:
        driver = InteropDriver(
            session.grpc_addr(server), session.grpc_addr(client), verbose=verbose)
        driver.server_metadata = session.metadata.get(server)
        driver.client_metadata = session.metadata.get(client)

        if skip := driver.scenario_skip_reason_for_configs(server_conf, client_conf):
            if verbose:
                _console_print(console_lock, f"[Driver] SKIP: {skip}")
            else:
                short = skip[:120].replace("\n", " ")
                _console_print(console_lock, f"SKIP  ({short})")
            return EXIT_SKIP

        driver._last_skip_reason = None
        driver._last_failure = None
        ok, timed_out, worker_exc = _run_driver_test_timed(
            driver, server_conf, client_conf, tcp_host=tcp_host, tcp_port=tcp_port,
            client_wrapper=client, cell_timeout_s=cell_timeout_s, verbose=verbose)

        if timed_out:
            summary = (
                f"cell exceeded {cell_timeout_s}s wall-clock limit "
                "(CLOSE sent, CLI processes killed)")
            driver._last_failure = ("cell_timeout", FAILURE, summary)
            if debug_logs is not None:
                log_path = write_cell_debug_log(
                    repo, server=server, client=client, server_conf=server_conf,
                    client_conf=client_conf, driver=driver, debug_logs=debug_logs,
                    cell=cell, tcp_host=tcp_host, tcp_port=tcp_port, result_kind="TIMEOUT")
                rel = (
                    log_path.relative_to(repo)
                    if log_path.is_relative_to(repo) else log_path)
                _console_print(console_lock, f"TIMEOUT! Details saved to: {rel}")
            if verbose:
                _console_print(console_lock, f"[Driver] TIMEOUT: {summary}")
            else:
                _console_print(console_lock, f"TIMEOUT  ({summary})")
            return EXIT_TIMEOUT

        if worker_exc is not None:
            raise worker_exc

        if driver._last_skip_reason:
            if verbose:
                _console_print(console_lock, f"[Driver] SKIP: {driver._last_skip_reason}")
                return EXIT_SKIP
            short = driver._last_skip_reason[:200].replace("\n", " ").strip()
            _console_print(console_lock, f"SKIP  ({short})")
            return EXIT_SKIP
        if not ok:
            if debug_logs is not None:
                log_path = write_cell_debug_log(
                    repo, server=server, client=client, server_conf=server_conf,
                    client_conf=client_conf, driver=driver, debug_logs=debug_logs,
                    cell=cell, tcp_host=tcp_host, tcp_port=tcp_port, result_kind="FAIL")
                rel = (
                    log_path.relative_to(repo)
                    if log_path.is_relative_to(repo) else log_path)
                _console_print(console_lock, f"FAIL! Details saved to: {rel}")
            if verbose:
                return 1
            detail = ""
            if driver._last_failure:
                detail = (
                    (driver._last_failure[2] or "").replace("\n", " ").strip()[:220])
            suf = f"  ({detail})" if detail else ""
            _console_print(console_lock, f"FAIL{suf}")
            return 1
        if verbose:
            return 0
        _console_print(console_lock, "PASS")
        return 0
    except Exception as e:
        if driver is None:
            driver = InteropDriver(
                session.grpc_addr(server), session.grpc_addr(client), verbose=verbose)
            driver._last_failure = ("grpc", FAILURE, str(e))
        else:
            driver._last_failure = driver._last_failure or ("grpc", FAILURE, str(e))
        if debug_logs is not None:
            log_path = write_cell_debug_log(
                repo, server=server, client=client, server_conf=server_conf,
                client_conf=client_conf, driver=driver, debug_logs=debug_logs, cell=cell,
                tcp_host=tcp_host, tcp_port=tcp_port, extra_error=str(e), result_kind="FAIL")
            rel = (
                log_path.relative_to(repo)
                if log_path.is_relative_to(repo) else log_path)
            _console_print(console_lock, f"FAIL! Details saved to: {rel}")
        if verbose:
            _console_print(console_lock, f"[Driver] exception: {e}")
        else:
            _console_print(
                console_lock,
                f"FAIL  ({str(e).replace(chr(10), ' ').strip()[:220]})")
        return 1
    finally:
        remove_tls_session_artifact_files(wroot)


# --- gRPC test driver ---

SUCCESS = interop_pb2.OperationResponse.SUCCESS
FAILURE = interop_pb2.OperationResponse.FAILURE


def _wait_grpc_channel_ready(address: str, *, deadline: float, verbose: bool) -> bool:
    channel = grpc.insecure_channel(address)
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        grpc.channel_ready_future(channel).result(timeout=min(3.0, remaining))
        if verbose:
            print(f"[Driver] gRPC reachable: {address}")
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
    def __init__(self, server_addr: str, client_addr: str, verbose: bool = False) -> None:
        self._verbose = verbose
        self.server_addr = server_addr
        self.client_addr = client_addr
        self._last_failure: tuple[str, int, str] | None = None
        self._last_skip_reason: str | None = None
        self._op_traces: list[OpTrace] = []
        self._last_transmit_client_data: bytes = b""
        self._last_transmit_server_data: bytes = b""
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
        if (
            resp.negotiated.protocol_version
            or resp.negotiated.cipher_suite
            or resp.negotiated.named_group
            or resp.negotiated.hrr_occurred
        ):
            neg = interop_pb2.NegotiatedTlsParameters()
            neg.CopyFrom(resp.negotiated)
        trace = OpTrace(
            label=label, status=resp.status, message=(resp.message or "").strip(),
            logs=(resp.logs or "").strip(), negotiated=neg,
            output_data=bytes(resp.output_data or b""))
        self._op_traces.append(trace)
        if label.startswith("TRANSMIT client"):
            self._last_transmit_client_data = trace.output_data
        elif label.startswith("TRANSMIT server"):
            self._last_transmit_server_data = trace.output_data
        return trace

    def _vprint(self, *args: Any, **kwargs: Any) -> None:
        if self._verbose:
            print(*args, **kwargs)

    def _log_metadata(self, label: str, metadata: interop_pb2.LibraryMetadata) -> None:
        role_names: Mapping[int, str] = {
            interop_pb2.CLIENT: "CLIENT",
            interop_pb2.SERVER: "SERVER"}
        roles_str = [role_names.get(r, str(r)) for r in metadata.roles]
        self._vprint(f"[Driver] {label}: {metadata.component_name} {metadata.version}")
        self._vprint(f"         roles={roles_str}")
        versions = [c.name for c in metadata.supported_versions]
        suf = "..." if len(versions) > 5 else ""
        self._vprint(f"         supported_versions={versions[:5]}{suf}")

    def _metadata_can_negotiate_version(self, metadata: interop_pb2.LibraryMetadata | None, capability_name: str, role: int) -> bool:
        if metadata is None:
            return True
        if metadata.roles and role not in metadata.roles:
            return False
        caps = list(metadata.supported_versions)
        if not caps:
            return True
        return any(
            c.name == capability_name and interop_pb2.NEGOTIATE in c.flags for c in caps)

    def scenario_skip_reason_for_configs(self, server_conf: interop_pb2.TlsConfig, client_conf: interop_pb2.TlsConfig) -> str | None:
        """Skip run if peer metadata disagrees with role ``TlsConfig`` values."""
        if self.server_metadata is None or self.client_metadata is None:
            return None
        srv, cli = server_conf, client_conf
        cap_srv = tls_version_to_capability_name(srv.version)
        cap_cli = tls_version_to_capability_name(cli.version)
        if not self._metadata_can_negotiate_version(
            self.server_metadata, cap_srv, interop_pb2.SERVER):
            cn = self.server_metadata.component_name
            return f"server ({cn}) cannot negotiate {cap_srv} per GetMetadata"
        if not self._metadata_can_negotiate_version(
            self.client_metadata, cap_cli, interop_pb2.CLIENT):
            cn = self.client_metadata.component_name
            return f"client ({cn}) cannot negotiate {cap_cli} per GetMetadata"
        if ciph := (srv.cipher_suite or "").strip():
            cn_s = self.server_metadata.component_name
            if not self._metadata_supports_cipher(self.server_metadata, ciph):
                return f"server ({cn_s}) cannot offer cipher '{ciph}' per GetMetadata"
        if ciph := (cli.cipher_suite or "").strip():
            cn_c = self.client_metadata.component_name
            if not self._metadata_supports_cipher(self.client_metadata, ciph):
                return f"client ({cn_c}) cannot offer cipher '{ciph}' per GetMetadata"
        if grp := list(srv.supported_groups):
            cn_s = self.server_metadata.component_name
            if not self._metadata_supports_groups(self.server_metadata, grp):
                return f"server ({cn_s}) lacks group(s) {grp} per GetMetadata"
        if grp := list(cli.supported_groups):
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
            self._last_skip_reason = (
                msg[5:].strip() or "wrapper reported unsupported option")
            if self._verbose:
                print(f"[Driver] {label}: SKIP - {self._last_skip_reason}")
            return False
        if resp.status == SUCCESS:
            if self._verbose and trace.logs:
                first = trace.logs.split("\n", 1)[0]
                self._vprint(f"[Driver] {label} (wrapper cmd): {first}")
            return True
        fail_summary = msg or "no message"
        self._last_failure = (label, resp.status, fail_summary)
        if self._verbose:
            lab = "FAILURE" if resp.status == FAILURE else "ERROR"
            print(f"[Driver] {label}: {lab} - {fail_summary}")
        return False

    def _check_hrr_assertion(
        self, resp: interop_pb2.OperationResponse, client_conf: interop_pb2.TlsConfig,
        label: str, *, client_wrapper: str = "") -> bool:
        if not getattr(client_conf, "expect_hrr", False):
            return True
        cw = (client_wrapper or "").strip().lower()
        if cw == "nss":
            if self._verbose:
                self._vprint(
                    f"[Driver] {label}: HRR assertion skipped "
                    "(NSS client cannot provoke HRR reliably)")
            return True
        if resp.negotiated.hrr_occurred:
            if self._verbose:
                self._vprint(f"[Driver] {label}: HRR assertion OK")
            return True
        summary = (
            "expected Hello Retry Request (expect_hrr=true) "
            "but negotiated.hrr_occurred is false")
        self._last_failure = (label, FAILURE, summary)
        if self._verbose:
            print(f"[Driver] {label}: FAILURE - {summary}")
        return False

    def _execute_establish(
        self, stub: interop_pb2_grpc.TlsInteropWrapperStub, role: int,
        cfg: interop_pb2.TlsConfig) -> interop_pb2.OperationResponse:
        return stub.ExecuteOperation(
            interop_pb2.OperationRequest(
                type=interop_pb2.OperationRequest.ESTABLISH, role=role, config=cfg))

    def _cleanup(self) -> None:
        self._vprint("[Driver] Cleaning up...")
        close_req = interop_pb2.OperationRequest(type=interop_pb2.OperationRequest.CLOSE)
        for stub, role in [(self.server_stub, "server"), (self.client_stub, "client")]:
            try:
                self._check_response(stub.ExecuteOperation(close_req), f"CLOSE {role}")
            except Exception as e:
                msg = f"[Driver] CLOSE {role} exception: {e}"
                print(msg if self._verbose else f"FAIL  CLOSE {role}: {e}")

    def emergency_cleanup(self, *, grpc_timeout_s: float = EMERGENCY_CLOSE_GRPC_S) -> None:
        """On cell timeout: CLOSE both roles with a short gRPC deadline (kills wrapper CLI procs)."""
        close_req = interop_pb2.OperationRequest(type=interop_pb2.OperationRequest.CLOSE)
        for stub, role in [(self.server_stub, "server"), (self.client_stub, "client")]:
            try:
                resp = stub.ExecuteOperation(close_req, timeout=max(0.5, grpc_timeout_s))
                self._record_response(resp, f"CLOSE {role} (timeout watchdog)")
            except Exception as e:
                trace = OpTrace(
                    label=f"CLOSE {role} (timeout watchdog)",
                    status=interop_pb2.OperationResponse.ERROR, message=str(e), logs="",
                    negotiated=None, output_data=b"")
                self._op_traces.append(trace)
                if self._verbose:
                    print(f"[Driver] emergency CLOSE {role}: {e}")

    def _run_post_establish_round_trip(
        self, *, server_conf: interop_pb2.TlsConfig, client_conf: interop_pb2.TlsConfig,
        tcp_host: str, tcp_port: int, ver: str, client_wrapper: str = "") -> bool:
        """Host TCP check, TRANSMIT client→server, verify echoed payload."""
        tcp_after_establish_s = 20.0
        transmit_gap_s = 1.0
        nss_resumption_pre_transmit_s = 0.5
        test_payload = b"PAYLOAD"

        ok_peer, tcp_err = wait_tcp_connect(
            tcp_host, int(tcp_port), timeout_s=tcp_after_establish_s)
        if not ok_peer:
            self._vprint(f"[Driver] Timeout waiting for TCP {tcp_host}:{tcp_port}")
            summary = (
                f"TCP {tcp_host}:{tcp_port} not accepting after ESTABLISH ({tcp_err})")
            establish_hints: list[str] = []
            for trace in self._op_traces:
                if trace.label.startswith("ESTABLISH"):
                    establish_hints.append(f"{trace.label}: {trace.message or 'ok'}")
            if establish_hints:
                summary += "\nPrior ESTABLISH: " + "; ".join(establish_hints)
            self._last_failure = ("wait_tcp", FAILURE, summary)
            return False

        if (
            (client_wrapper or "").strip().lower() == "nss"
            and (
                test_feature_enabled_in_config(client_conf, "resumption")
                or test_feature_enabled_in_config(client_conf, "0rtt"))        ):
            time.sleep(nss_resumption_pre_transmit_s)

        self._vprint(f"[Driver] Transmitting: {test_payload.decode()}")
        r_tx = self.client_stub.ExecuteOperation(
            interop_pb2.OperationRequest(
                type=interop_pb2.OperationRequest.TRANSMIT, role=interop_pb2.CLIENT,
                payload=test_payload))
        if not self._check_response(r_tx, "TRANSMIT client"):
            return False

        time.sleep(transmit_gap_s)
        r_srv = self.server_stub.ExecuteOperation(
            interop_pb2.OperationRequest(
                type=interop_pb2.OperationRequest.TRANSMIT, role=interop_pb2.SERVER))
        if not self._check_response(r_srv, "TRANSMIT server"):
            return False

        if test_payload in r_srv.output_data:
            self._vprint(f">>> PASSED: payload echoed (TLS {ver}) <<<")
            return True
        self._vprint(">>> FAILED: echo mismatch <<<")
        summary = "server output did not contain echoed payload"
        summary += "\nexpected payload: " + test_payload.decode(errors="replace")
        summary += "\nTRANSMIT client output_data:\n" + _format_output_data(
            self._last_transmit_client_data)
        summary += "\nTRANSMIT server output_data:\n" + _format_output_data(
            self._last_transmit_server_data)
        self._last_failure = ("verify", FAILURE, summary)
        return False

    def run_test_with_configs(
        self, server_conf: interop_pb2.TlsConfig, client_conf: interop_pb2.TlsConfig, *,
        tcp_host: str, tcp_port: int, client_wrapper: str = "") -> bool:
        """ESTABLISH server → client (optional save/resume) → TCP → TRANSMIT → CLOSE."""
        self._last_skip_reason = None
        ver = (server_conf.version or "").strip() or "default"
        resumption = (
            test_feature_enabled_in_config(client_conf, "resumption")
            or test_feature_enabled_in_config(client_conf, "0rtt"))
        try:
            kind = "Resumption/0-RTT round-trip" if resumption else "Round-trip"
            self._vprint(f"[Driver] {kind} (TLS {ver})")
            self._vprint(
                "[Driver] Establishing server (persistent)..."
                if resumption else "[Driver] Establishing connection...")
            r = self._execute_establish(
                self.server_stub, interop_pb2.SERVER, server_conf)
            if not self._check_response(r, "ESTABLISH server"):
                return False

            if resumption:
                save_conf = interop_pb2.TlsConfig()
                save_conf.CopyFrom(client_conf)
                save_conf.resumption_step = "save"
                self._vprint("[Driver] Resumption step 1: save session ticket...")
                r = self._execute_establish(
                    self.client_stub, interop_pb2.CLIENT, save_conf)
                if not self._check_response(r, "ESTABLISH client (resumption save)"):
                    return False
                if not self._check_hrr_assertion(
                    r, client_conf, "ESTABLISH client (resumption save)",
                    client_wrapper=client_wrapper):
                    return False
                resume_conf = interop_pb2.TlsConfig()
                resume_conf.CopyFrom(client_conf)
                resume_conf.resumption_step = "resume"
                self._vprint("[Driver] Resumption step 2: resume session...")
                r = self._execute_establish(
                    self.client_stub, interop_pb2.CLIENT, resume_conf)
                if not self._check_response(r, "ESTABLISH client (resumption resume)"):
                    return False
            else:
                r = self._execute_establish(
                    self.client_stub, interop_pb2.CLIENT, client_conf)
                if not self._check_response(r, "ESTABLISH client"):
                    return False
                if not self._check_hrr_assertion(
                    r, client_conf, "ESTABLISH client", client_wrapper=client_wrapper):
                    return False

            return self._run_post_establish_round_trip(
                server_conf=server_conf, client_conf=client_conf, tcp_host=tcp_host,
                tcp_port=tcp_port, ver=ver, client_wrapper=client_wrapper)
        finally:
            self._cleanup()

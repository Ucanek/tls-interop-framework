"""Wrapper session lifecycle: subprocess spawn, gRPC readiness, metadata."""

from __future__ import annotations


import logging
import os
import signal
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Mapping

import grpc

from core.cleanup import ensure_interop_certs
from core.orchestration_context import (
    orchestration_context_for_backends,
    set_orchestration_context,
)
from core.registry import (
    backend_grpc_addr,
    backend_tls_endpoint,
    check_local_cli_tools,
    discover_wrapper_ids,
    session_wrapper_env,
)
from core.matrix_cell import MatrixCell
from core.matrix import normalize_cell_tls_micro_params
from core.validation import cell_capability_skip_reason

from interop_proto import interop_pb2, interop_pb2_grpc
from wrappers.base import wait_tcp_connect

logger = logging.getLogger(__name__)

_DEFAULT_GRPC_STARTUP_S = 90.0
_GRPC_STARTUP_POLL_S = 0.4
_DEFAULT_CELL_TIMEOUT_S = 45.0
_CELL_TIMEOUT_POLL_S = 0.25
_CELL_TIMEOUT_CLEANUP_WAIT_S = 15.0
_EMERGENCY_CLOSE_GRPC_S = 10.0
_WORKER_PORT_STRIDE = 100
_MAX_PARALLEL_JOBS = 32


def _worker_slot_grpc_overrides(
    repo: Path,
    backends: frozenset[str] | set[str],
    slot_id: int,
    base_overrides: Mapping[str, int] | None = None,
) -> dict[str, int]:
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


def apply_matrix_tls_endpoints(
    server: str,
    client: str,
    server_conf: interop_pb2.TlsConfig,
    client_conf: interop_pb2.TlsConfig,
    *,
    repo: Path,
    cell: MatrixCell | None = None,
    session: BaseExecutionSession | None = None,
) -> tuple[str, int]:
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


def required_backends_from_matrix(
    axis_keys: list[str],
    combos: list[tuple[Any, ...]],
    *,
    args_template: Any,
    repo: Path,
    known: frozenset[str],
) -> tuple[frozenset[str], int]:
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

    def __init__(
        self,
        repo: Path,
        backends: frozenset[str],
        *,
        verbose: bool = False,
        attach: bool = False,
        grpc_port_overrides: Mapping[str, int] | None = None,
    ) -> None:
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
        return env

    def _wrapper_cmd(self, backend: str) -> list[str]:
        return [sys.executable, "-m", f"wrappers.{backend}.wrapper"]

    def up(self) -> None:
        if not self.backends:
            return
        if self.attach:
            targets = ", ".join(f"{b} @ {self.grpc_addr(b)}" for b in self.backends)
            logger.info(
                "Attach mode: connecting to existing wrapper(s) on localhost (%s)",
                targets,
            )
            return
        try:
            import grpc  # noqa: F401
        except ImportError as e:
            raise RuntimeError(
                "Requires grpcio on the host Python "
                "(pip install 'grpcio>=1.60' 'protobuf>=4.21')"
            ) from e
        ensure_interop_certs(self.repo, verbose=self.verbose)
        missing = check_local_cli_tools(self.backends, self.repo)
        if missing:
            raise RuntimeError(
                "Requires TLS CLI tools on PATH:\n  " + "\n  ".join(missing)
            )
        for backend in self.backends:
            addr = self.grpc_addr(backend)
            host, port = _grpc_host_port(addr)
            in_use, _ = wait_tcp_connect(host, port, timeout_s=0.35)
            if in_use:
                raise RuntimeError(
                    f"Port {port} already in use ({addr}); stop other wrapper processes"
                )
        if self.verbose:
            logger.debug("Starting wrappers: %s", ", ".join(self.backends))
        for backend in self.backends:
            cmd = self._wrapper_cmd(backend)
            if self.verbose:
                logger.debug(
                    "[Wrapper] %s: %s (GRPC_PORT from env)", backend, " ".join(cmd)
                )
            proc = subprocess.Popen(
                cmd,
                cwd=self.repo,
                env=self._wrapper_env(backend),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE if self.verbose else subprocess.DEVNULL,
                stderr=subprocess.STDOUT if self.verbose else subprocess.DEVNULL,
                start_new_session=True,
            )
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
                    + (f":\n{out}" if out else "")
                )

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
                if _wait_grpc_channel_ready(
                    addr, deadline=deadline, verbose=self.verbose
                ):
                    pending.discard(addr)
            if pending:
                time.sleep(_GRPC_STARTUP_POLL_S)
        if pending:
            raise TimeoutError(
                f"gRPC not reachable within {timeout_s}s: {', '.join(sorted(pending))}"
            )

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

    def __init__(
        self,
        repo: Path,
        backends: frozenset[str],
        slot_id: int,
        *,
        verbose: bool = False,
        grpc_port_overrides: Mapping[str, int] | None = None,
    ) -> None:
        overrides = _worker_slot_grpc_overrides(
            repo, backends, slot_id, grpc_port_overrides
        )
        super().__init__(
            repo, backends, verbose=verbose, attach=False, grpc_port_overrides=overrides
        )
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

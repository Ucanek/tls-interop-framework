"""TLS interop runner: local wrapper subprocesses + gRPC matrix driver."""

from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import threading
import time
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

import grpc

from core.catalog import (
    backend_grpc_addr, backend_tls_endpoint, load_backend_capabilities,
    cell_capability_skip_reason, check_local_cli_tools, discover_wrapper_ids,
    normalize_cell_tls_micro_params, parse_asymmetric, session_wrapper_env)

from wrappers.utils import remove_tls_session_artifact_files, test_feature_enabled_in_config
from interop_proto import interop_pb2, interop_pb2_grpc
from wrappers.base import split_asymmetric_csv, wait_tcp_connect

# Distinct from 0 (pass) and 1 (fail) so matrix runners can show SKIP vs OK / TIMEOUT.
EXIT_SKIP = 77
EXIT_TIMEOUT = 78

DEFAULT_GRPC_STARTUP_S = 90.0
DEFAULT_CELL_TIMEOUT_S = 45.0
EMERGENCY_CLOSE_GRPC_S = 10.0
WORKER_PORT_STRIDE = 100
MAX_PARALLEL_JOBS = 32
TCP_AFTER_ESTABLISH_S = 20.0
TRANSMIT_GAP_S = 1.0
TEST_PAYLOAD = b"PAYLOAD"
CELL_TIMEOUT_POLL_S = 0.25
CELL_TIMEOUT_CLEANUP_WAIT_S = 15.0


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
    from core.identity import IDENTITY_PREFIXES

    cert_dir = repo / "certs"
    if all((cert_dir / f"{p}.crt").is_file() and (cert_dir / f"{p}.key").is_file()
           for p in IDENTITY_PREFIXES):
        return
    script = repo / "core" / "gen_interop_certs.sh"
    if not script.is_file():
        raise FileNotFoundError(
            f"Missing certs/ bundles; run {script.name} or create certs/ manually")
    if verbose:
        print(f"Generating identity PEMs via {script}")
    subprocess.run(["bash", str(script)], cwd=repo, check=True)


def apply_matrix_tls_endpoints(
    server: str, client: str, server_conf: interop_pb2.TlsConfig,
    client_conf: interop_pb2.TlsConfig, *, repo: Path,
    cell: dict[str, str] | None = None, session: WrapperSession | None = None) -> tuple[str, int]:
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
    """Collect backends needed by non-SKIP matrix cells."""
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
    load_backend_capabilities(name)
    runpy.run_module(f"wrappers.{name}.wrapper", run_name="__main__")
    return 0


class WrapperSession:
    """Start wrapper gRPC services as host subprocesses, or attach to existing ones."""

    def __init__(
        self, repo: Path, backends: frozenset[str], *, verbose: bool = False,
        attach: bool = False, grpc_port_overrides: Mapping[str, int] | None = None,
        slot_id: int | None = None) -> None:
        known = frozenset(discover_wrapper_ids(repo))
        unknown = backends - known
        if unknown:
            raise ValueError(f"Unknown backend(s): {sorted(unknown)}")
        self.repo = repo.resolve()
        self.backends = sorted(backends)
        self.verbose = verbose
        self.attach = attach
        self.slot_id = None if slot_id is None else int(slot_id)
        if self.slot_id is not None:
            if attach:
                raise ValueError("attach mode is incompatible with parallel slot_id")
            overrides = _worker_slot_grpc_overrides(
                repo, backends, self.slot_id, grpc_port_overrides)
        else:
            overrides = {
                k.strip().lower(): int(v) for k, v in (grpc_port_overrides or {}).items()
            }
        self._grpc_port_overrides = overrides
        self.metadata: dict[str, interop_pb2.LibraryMetadata] = {}
        self._procs: list[subprocess.Popen[bytes]] = []

    def grpc_addr(self, backend: str) -> str:
        key = (backend or "").strip().lower()
        override = self._grpc_port_overrides.get(key)
        return backend_grpc_addr(key, self.repo, port_override=override or None)

    def tls_endpoint(self, backend: str) -> tuple[str, int]:
        key = (backend or "").strip().lower()
        host, base_port = backend_tls_endpoint(key, self.repo)
        if self.slot_id is None:
            return host, base_port
        return host, base_port + self.slot_id * WORKER_PORT_STRIDE

    def _wrapper_env(self, backend: str) -> dict[str, str]:
        env = os.environ.copy()
        _, grpc_port = _grpc_host_port(self.grpc_addr(backend))
        env["GRPC_PORT"] = str(grpc_port)
        env["WRAPPER"] = backend
        if self.slot_id is not None:
            env["INTEROP_SLOT_ID"] = str(self.slot_id)
        env.update(session_wrapper_env(
            backend, self.repo, self.backends, slot_id=self.slot_id))
        # Do not inject PYTHONPATH: cwd is the repo for ``python -c`` spawn, and
        # forcing PYTHONPATH on Fedora makes distro ``google.protobuf`` shadow pip.
        env.pop("PYTHONPATH", None)
        return env

    def _wrapper_cmd(self, backend: str) -> list[str]:
        # Prefer installed package imports; cwd is still the repo for certs/hooks.
        code = (
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

    def _spawn_wrappers(self) -> None:
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

    def _wait_grpc_ready(self, timeout_s: float = DEFAULT_GRPC_STARTUP_S) -> None:
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

    def _load_metadata(self) -> None:
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
        self._spawn_wrappers()
        self._wait_grpc_ready()
        self._load_metadata()

    def stop(self) -> None:
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
        rt = load_backend_capabilities(backend).runtime()
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
    from core.catalog import parse_test_features_enabled

    cfg.psk_modes.extend(sorted(parse_test_features_enabled(str(cell.get("test_features") or ""))))
    # expect_hrr is a client-side provoke/assert flag (single-key-share / log parse).
    if not server and cell.get("expect_hrr") == "true":
        cfg.expect_hrr = True
    if server and repo is not None:
        backend = (cell.get("server") or "").strip().lower()
        if _server_accepts_inline_pem_identity(backend, repo):
            _attach_cell_server_identity(cfg, cell, repo=repo)
    return cfg


def wrapper_filesystem_root(session: WrapperSession) -> str:
    """Repo root path as seen inside wrapper subprocesses (per-slot dir when parallel)."""
    if session.slot_id is not None:
        root = session.repo / ".interop_worker" / f"slot{session.slot_id}"
        root.mkdir(parents=True, exist_ok=True)
        return str(root.resolve())
    return str(session.repo.resolve())


def _console_print(console_lock: threading.Lock | None, *args: Any, **kwargs: Any) -> None:
    with console_lock or nullcontext():
        print(*args, **kwargs)


@dataclass
class DebugRunLogs:
    """Lazy ``debug_logs/run_<timestamp>/`` holder for one matrix run."""

    path: Path | None = None

    def ensure_run_dir(self, repo: Path) -> Path:
        if self.path is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.path = repo / "debug_logs" / f"run_{ts}"
            self.path.mkdir(parents=True, exist_ok=True)
        return self.path

    def write_fail_log(
        self, *, repo: Path, server: str, client: str, driver: "InteropDriver",
        cell: dict[str, str] | None = None, extra: str = "", kind: str = "FAIL") -> Path:
        run_dir = self.ensure_run_dir(repo)
        kind_u = (kind or "FAIL").strip().upper()
        cipher = ""
        if cell:
            cipher = re.sub(r"[^\w.-]+", "-", (cell.get("cipher_suite") or "").strip())[:48]
        name = f"{kind_u.lower()}_{server}_x_{client}"
        if cipher:
            name = f"{name}_{cipher}"
        path = run_dir / f"{name}.log"
        parts: list[str] = [f"TLS interop {kind_u}", f"server={server} client={client}"]
        if cell:
            parts.append(
                "cell: "
                + ", ".join(f"{k}={v}" for k, v in sorted(cell.items()) if str(v).strip()))
        if driver._last_failure:
            label, detail = driver._last_failure
            parts.append(f"last_failure: {label}")
            parts.append(detail)
        if extra:
            parts.append(f"extra: {extra}")
        parts.append("")
        parts.extend(driver._fail_log or ["(no operation logs)"])
        path.write_text("\n".join(parts).rstrip() + "\n", encoding="utf-8")
        return path


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


class InteropDriver:
    """ESTABLISH → (resume) → TRANSMIT → CLOSE over local wrapper gRPC stubs."""

    def __init__(self, server_addr: str, client_addr: str, verbose: bool = False) -> None:
        self._verbose = verbose
        self._channels: list[grpc.Channel] = []
        self._last_failure: tuple[str, str] | None = None
        self._last_skip_reason: str | None = None
        self._fail_log: list[str] = []
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

    def _stub(self, role: int) -> interop_pb2_grpc.TlsInteropWrapperStub:
        return self.server_stub if role == interop_pb2.SERVER else self.client_stub

    def _establish(self, role: int, cfg: interop_pb2.TlsConfig) -> interop_pb2.OperationResponse:
        return self._stub(role).ExecuteOperation(
            interop_pb2.OperationRequest(
                type=interop_pb2.OperationRequest.ESTABLISH, role=role, config=cfg))

    def _transmit(self, role: int, payload: bytes = b"") -> interop_pb2.OperationResponse:
        return self._stub(role).ExecuteOperation(
            interop_pb2.OperationRequest(
                type=interop_pb2.OperationRequest.TRANSMIT, role=role, payload=payload))

    def _close(self, role: int, *, timeout_s: float | None = None) -> interop_pb2.OperationResponse:
        close_req = interop_pb2.OperationRequest(type=interop_pb2.OperationRequest.CLOSE)
        timeout = None if timeout_s is None else max(0.5, timeout_s)
        return self._stub(role).ExecuteOperation(close_req, timeout=timeout)

    def _note_response(self, label: str, resp: interop_pb2.OperationResponse) -> None:
        status_name = {
            SUCCESS: "SUCCESS", FAILURE: "FAILURE",
            interop_pb2.OperationResponse.ERROR: "ERROR"
        }.get(resp.status, str(resp.status))
        parts = [f"--- {label} ({status_name}) ---"]
        msg = (resp.message or "").strip()
        if msg:
            parts.append(msg)
        logs = (resp.logs or "").strip()
        if logs:
            parts.append(logs)
        out = bytes(resp.output_data or b"")
        if out:
            parts.append(f"output_data: {out!r}")
        self._fail_log.append("\n".join(parts))

    def _vprint(self, *args: Any, **kwargs: Any) -> None:
        if self._verbose:
            print(*args, **kwargs)

    def _check_response(self, resp: interop_pb2.OperationResponse, label: str) -> bool:
        self._note_response(label, resp)
        msg = (resp.message or "").strip()
        if resp.status == SUCCESS and msg.lower().startswith("skip:"):
            self._last_skip_reason = (
                msg[5:].strip() or "wrapper reported unsupported option")
            if self._verbose:
                print(f"[Driver] {label}: SKIP - {self._last_skip_reason}")
            return False
        if resp.status == SUCCESS:
            logs = (resp.logs or "").strip()
            if self._verbose and logs:
                first = logs.split("\n", 1)[0]
                self._vprint(f"[Driver] {label} (wrapper cmd): {first}")
            return True
        fail_summary = msg or "no message"
        self._last_failure = (label, fail_summary)
        if self._verbose:
            lab = "FAILURE" if resp.status == FAILURE else "ERROR"
            print(f"[Driver] {label}: {lab} - {fail_summary}")
        return False

    def _check_hrr_assertion(
        self, resp: interop_pb2.OperationResponse, client_conf: interop_pb2.TlsConfig,
        label: str) -> bool:
        if not getattr(client_conf, "expect_hrr", False):
            return True
        if resp.negotiated.hrr_occurred:
            if self._verbose:
                self._vprint(f"[Driver] {label}: HRR assertion OK")
            return True
        summary = (
            "expected Hello Retry Request (expect_hrr=true) "
            "but negotiated.hrr_occurred is false")
        self._last_failure = (label, summary)
        if self._verbose:
            print(f"[Driver] {label}: FAILURE - {summary}")
        return False

    def _cleanup(self) -> None:
        self._vprint("[Driver] Cleaning up...")
        for label, role in (("server", interop_pb2.SERVER), ("client", interop_pb2.CLIENT)):
            try:
                self._check_response(self._close(role), f"CLOSE {label}")
            except Exception as e:
                if self._verbose:
                    print(f"[Driver] CLOSE {label} exception: {e}")
                else:
                    print(f"FAIL  CLOSE {label}: {e}")

    def emergency_cleanup(self, *, grpc_timeout_s: float = EMERGENCY_CLOSE_GRPC_S) -> None:
        """On cell timeout: CLOSE both roles with a short gRPC deadline (kills wrapper CLI procs)."""
        for label, role in (("server", interop_pb2.SERVER), ("client", interop_pb2.CLIENT)):
            try:
                resp = self._close(role, timeout_s=grpc_timeout_s)
                self._note_response(f"CLOSE {label} (timeout watchdog)", resp)
            except Exception as e:
                self._fail_log.append(
                    f"--- CLOSE {label} (timeout watchdog) (ERROR) ---\n{e}")
                if self._verbose:
                    print(f"[Driver] emergency CLOSE {label}: {e}")

    def _run_post_establish_round_trip(
        self, *, tcp_host: str, tcp_port: int, ver: str) -> bool:
        ok_peer, tcp_err = wait_tcp_connect(
            tcp_host, int(tcp_port), timeout_s=TCP_AFTER_ESTABLISH_S)
        if not ok_peer:
            self._vprint(f"[Driver] Timeout waiting for TCP {tcp_host}:{tcp_port}")
            self._last_failure = (
                "wait_tcp",
                f"TCP {tcp_host}:{tcp_port} not accepting after ESTABLISH ({tcp_err})")
            return False

        self._vprint(f"[Driver] Transmitting: {TEST_PAYLOAD.decode()}")
        r_tx = self._transmit(interop_pb2.CLIENT, TEST_PAYLOAD)
        if not self._check_response(r_tx, "TRANSMIT client"):
            return False

        time.sleep(TRANSMIT_GAP_S)
        r_srv = self._transmit(interop_pb2.SERVER)
        if not self._check_response(r_srv, "TRANSMIT server"):
            return False

        if TEST_PAYLOAD in r_srv.output_data:
            self._vprint(f">>> PASSED: payload echoed (TLS {ver}) <<<")
            return True
        self._vprint(">>> FAILED: echo mismatch <<<")
        self._last_failure = (
            "verify",
            "server output did not contain echoed payload\n"
            f"expected: {TEST_PAYLOAD!r}\n"
            f"client out: {bytes(r_tx.output_data)!r}\n"
            f"server out: {bytes(r_srv.output_data)!r}")
        return False

    def run_test_with_configs(
        self, server_conf: interop_pb2.TlsConfig, client_conf: interop_pb2.TlsConfig, *,
        tcp_host: str, tcp_port: int) -> bool:
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
            r = self._establish(interop_pb2.SERVER, server_conf)
            if not self._check_response(r, "ESTABLISH server"):
                return False

            if resumption:
                save_conf = interop_pb2.TlsConfig()
                save_conf.CopyFrom(client_conf)
                save_conf.resumption_step = "save"
                self._vprint("[Driver] Resumption step 1: save session ticket...")
                r = self._establish(interop_pb2.CLIENT, save_conf)
                if not self._check_response(r, "ESTABLISH client (resumption save)"):
                    return False
                if not self._check_hrr_assertion(
                    r, client_conf, "ESTABLISH client (resumption save)"):
                    return False
                resume_conf = interop_pb2.TlsConfig()
                resume_conf.CopyFrom(client_conf)
                resume_conf.resumption_step = "resume"
                self._vprint("[Driver] Resumption step 2: resume session...")
                r = self._establish(interop_pb2.CLIENT, resume_conf)
                if not self._check_response(r, "ESTABLISH client (resumption resume)"):
                    return False
            else:
                r = self._establish(interop_pb2.CLIENT, client_conf)
                if not self._check_response(r, "ESTABLISH client"):
                    return False
                if not self._check_hrr_assertion(r, client_conf, "ESTABLISH client"):
                    return False

            return self._run_post_establish_round_trip(
                tcp_host=tcp_host, tcp_port=tcp_port, ver=ver)
        finally:
            self._cleanup()


def _run_driver_test_timed(
    driver: InteropDriver, server_conf: interop_pb2.TlsConfig,
    client_conf: interop_pb2.TlsConfig, *, tcp_host: str, tcp_port: int,
    cell_timeout_s: float, verbose: bool) -> tuple[bool | None, bool, Exception | None]:
    """Returns ``(ok, timed_out, worker_exception)``; ``ok`` is None on timeout."""
    holder: dict[str, Any] = {"ok": None, "exc": None}

    def _worker() -> None:
        try:
            holder["ok"] = driver.run_test_with_configs(
                server_conf, client_conf, tcp_host=tcp_host, tcp_port=tcp_port)
        except Exception as e:
            holder["exc"] = e

    thread = threading.Thread(target=_worker, name="interop-cell", daemon=True)
    thread.start()
    deadline = time.monotonic() + max(0.1, cell_timeout_s)
    while thread.is_alive() and time.monotonic() < deadline:
        thread.join(timeout=CELL_TIMEOUT_POLL_S)
    if not thread.is_alive():
        return holder["ok"], False, holder["exc"]

    if verbose:
        print(f"[Driver] cell timeout ({cell_timeout_s}s): sending CLOSE to wrappers")
    driver.emergency_cleanup()
    thread.join(timeout=CELL_TIMEOUT_CLEANUP_WAIT_S)
    if thread.is_alive() and verbose:
        print("[Driver] worker still running after emergency cleanup; continuing matrix")
    return None, True, holder["exc"]


def execute_matrix_cell(
    cell: dict[str, str], session: WrapperSession, *, verbose: bool,
    debug_logs: DebugRunLogs | None = None,
    cell_timeout_s: float = DEFAULT_CELL_TIMEOUT_S,
    console_lock: threading.Lock | None = None) -> int:
    """Build configs and run one ``InteropDriver`` cell with timeout + debug logs."""
    server = (cell.get("server") or "").strip().lower()
    client = (cell.get("client") or "").strip().lower()
    repo = session.repo
    wroot = wrapper_filesystem_root(session)
    driver: InteropDriver | None = None

    def _save_debug(kind: str, *, extra: str = "") -> None:
        if debug_logs is None or driver is None:
            return
        log_path = debug_logs.write_fail_log(
            repo=repo, server=server, client=client, driver=driver,
            cell=cell, extra=extra, kind=kind)
        rel = log_path.relative_to(repo) if log_path.is_relative_to(repo) else log_path
        tag = "TIMEOUT!" if kind == "TIMEOUT" else "FAIL!"
        _console_print(console_lock, f"{tag} Details saved to: {rel}")

    _console_print(console_lock, f"========== {server}x{client} ==========")
    server_conf = tls_config_from_cell(cell, interop_pb2.SERVER, repo=repo)
    client_conf = tls_config_from_cell(cell, interop_pb2.CLIENT, repo=repo)
    server_conf.repo_root = wroot
    client_conf.repo_root = wroot
    tcp_host, tcp_port = apply_matrix_tls_endpoints(
        server, client, server_conf, client_conf, repo=repo, cell=cell, session=session)
    try:
        driver = InteropDriver(
            session.grpc_addr(server), session.grpc_addr(client), verbose=verbose)
        driver._last_skip_reason = None
        driver._last_failure = None
        driver._fail_log.clear()
        ok, timed_out, worker_exc = _run_driver_test_timed(
            driver, server_conf, client_conf, tcp_host=tcp_host, tcp_port=tcp_port,
            cell_timeout_s=cell_timeout_s, verbose=verbose)

        if timed_out:
            summary = (
                f"cell exceeded {cell_timeout_s}s wall-clock limit "
                "(CLOSE sent, CLI processes killed)")
            driver._last_failure = ("cell_timeout", summary)
            _save_debug("TIMEOUT")
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
            _save_debug("FAIL")
            if verbose:
                return 1
            detail = ""
            if driver._last_failure:
                detail = (
                    (driver._last_failure[1] or "").replace("\n", " ").strip()[:220])
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
            driver._last_failure = ("grpc", str(e))
        else:
            driver._last_failure = driver._last_failure or ("grpc", str(e))
        _save_debug("FAIL", extra=str(e))
        if verbose:
            _console_print(console_lock, f"[Driver] exception: {e}")
        else:
            _console_print(
                console_lock,
                f"FAIL  ({str(e).replace(chr(10), ' ').strip()[:220]})")
        return 1
    finally:
        remove_tls_session_artifact_files(wroot)

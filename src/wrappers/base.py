"""Shared gRPC servicer and subprocess helpers for TLS library wrappers in containers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from concurrent import futures
import fcntl
import os
import re
import shlex
import socket
import subprocess
import time
from typing import Any, Literal, Mapping, MutableMapping, Sequence, Tuple, Type

import grpc
from grpc import ServicerContext

from core.catalog import catalog_parameter_conflicts, metadata_from_capabilities, tls_mode_from_version
from core.identity import catalog_identity_pem_paths_for_config, repeated_config_tokens
from proto import interop_pb2
from proto import interop_pb2_grpc

FAIL_LOG_TAIL: int = 600


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


TlsModeLiteral = Literal["1.2", "1.3"]


def test_feature_enabled_in_config(config: Any, feature: str) -> bool:
    """True when ``test_features`` enabled this feature (mirrored in ``psk_modes``)."""
    return feature.strip().lower() in repeated_config_tokens(config, "psk_modes")


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


class WrapperSetupError(Exception):
    """Argv/launch failure before a server or client process is running."""


class WrapperRuntimeError(Exception):
    """Runtime failure after start (for example handshake or I/O expectations)."""


class WrapperSkipError(Exception):
    """Requested ``TlsConfig`` cannot be represented by backend CLI switches."""


def _exc_message(phase: str, exc: BaseException) -> str:
    return f"[{phase}] {type(exc).__name__}: {exc}"


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
    wrapper_cls: Type[BaseTemplateWrapper],
    display_name: str,
) -> None:
    """Starts the gRPC ``TlsInteropWrapper`` service without TLS (port from ``GRPC_PORT``)."""
    port = int(os.environ.get("GRPC_PORT", "50051"))
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    interop_pb2_grpc.add_TlsInteropWrapperServicer_to_server(wrapper_cls(), server)
    server.add_insecure_port(f"0.0.0.0:{port}")
    server.start()
    print(f"{display_name} wrapper listening on {port}...")
    server.wait_for_termination()


class BaseTemplateWrapper(interop_pb2_grpc.TlsInteropWrapperServicer, ABC):
    """Dispatches gRPC ops; subclasses implement backend-specific argv and ``Popen`` setup."""

    @staticmethod
    def wait_tcp_connect(
        host: str,
        port: int,
        *,
        timeout_s: float = 30.0,
        poll_s: float = 0.05,
        proc: subprocess.Popen[bytes] | None = None,
    ) -> tuple[bool, str]:
        """Polls until ``host:port`` accepts TCP or timeout; aborts early if ``proc`` exits."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        last_err = ""
        while time.monotonic() < deadline:
            if proc is not None and proc.poll() is not None:
                return False, "subprocess exited before TCP became ready"
            try:
                with socket.create_connection((host, port), timeout=0.25):
                    return True, ""
            except OSError as e:
                last_err = str(e)
            time.sleep(poll_s)
        return False, last_err or "timeout"

    def __init__(self) -> None:
        self.server_proc: subprocess.Popen[bytes] | None = None
        self.client_proc: subprocess.Popen[bytes] | None = None
        self._used_ephemeral_pem: bool = False

    @property
    @abstractmethod
    def _component_name(self) -> str:
        """Library label for ``GetMetadata``."""

    @abstractmethod
    def _version_command(self) -> list[str]:
        """Argv for version detection."""

    @abstractmethod
    def _start_server(
        self,
        config: interop_pb2.TlsConfig,
    ) -> Tuple[subprocess.Popen[bytes], str, str]:
        """Starts the server; returns ``(popen, logs, human message)``."""

    @abstractmethod
    def _start_client(
        self,
        config: interop_pb2.TlsConfig,
    ) -> Tuple[subprocess.Popen[bytes], str, str]:
        """Starts the client; returns ``(popen, logs, human message)``."""

    @property
    def _ephemeral_pem_paths(self) -> tuple[str, str]:
        """Paths for inline-generated PEM files (override to avoid backend clashes)."""
        return ("/tmp/interop_tls_cert.pem", "/tmp/interop_tls_key.pem")

    def _ensure_cert_paths(self, config: interop_pb2.TlsConfig) -> tuple[str, str]:
        """Resolves cert/key paths from config, cwd, or a short-lived ``openssl req`` run."""
        cert_b = getattr(config, "certificate", None) or b""
        key_b = getattr(config, "private_key", None) or b""
        eph_cert, eph_key = self._ephemeral_pem_paths

        if cert_b.strip() and key_b.strip():
            self._used_ephemeral_pem = True
            with open(eph_cert, "wb") as f:
                f.write(cert_b)
            with open(eph_key, "wb") as f:
                f.write(key_b)
            try:
                os.chmod(eph_key, 0o600)
            except OSError:
                pass
            return eph_cert, eph_key

        if self._used_ephemeral_pem:
            for path in (eph_cert, eph_key):
                try:
                    os.remove(path)
                except OSError:
                    pass
            self._used_ephemeral_pem = False

        sel_cert, sel_key = catalog_identity_pem_paths_for_config(config)
        if sel_cert and sel_key:
            return sel_cert, sel_key

        cwd = os.getcwd()
        cwd_cert = os.path.join(cwd, "cert.pem")
        cwd_key = os.path.join(cwd, "key.pem")
        if os.path.isfile(cwd_cert) and os.path.isfile(cwd_key):
            return "cert.pem", "key.pem"

        raise WrapperSetupError(
            "No identity PEM for this test (set certificate/private_key, use certs/ "
            "from scripts/gen_interop_certs.sh, or cert.pem/key.pem in cwd)"
        )

    def _popen_env(self, config: interop_pb2.TlsConfig) -> dict[str, str] | None:
        """Environment with ``SSLKEYLOGFILE`` when ``TlsConfig.keylog_file`` is set."""
        path = (getattr(config, "keylog_file", None) or "").strip()
        if not path:
            return None
        env = dict(os.environ)
        env["SSLKEYLOGFILE"] = path
        return env

    def _terminate_process_hard(
        self,
        proc: subprocess.Popen[bytes] | None,
        *,
        wait_s: float = 3.0,
    ) -> None:
        """SIGTERM then SIGKILL (best-effort)."""
        if proc is None or proc.poll() is not None:
            return
        try:
            proc.terminate()
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=max(0.1, wait_s))
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            proc.kill()
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            pass

    def _tail_merged_output(
        self,
        proc: subprocess.Popen[bytes] | None,
        limit: int = FAIL_LOG_TAIL,
    ) -> str:
        if proc is None or proc.stdout is None:
            return ""
        try:
            raw = (proc.stdout.read() or b"").decode(errors="replace")[-limit:]
            return raw.strip().replace("\n", " ")
        except OSError:
            return ""

    def _peek_merged_output(
        self,
        proc: subprocess.Popen[bytes] | None,
        limit: int = 65536,
    ) -> str:
        """Best-effort read of early merged stdout (handshake lines) without draining forever."""
        if proc is None or proc.stdout is None:
            return ""
        try:
            chunks: list[bytes] = []
            total = 0
            while total < limit:
                try:
                    piece = proc.stdout.read(4096)
                except (BlockingIOError, OSError):
                    break
                if not piece:
                    break
                chunks.append(piece)
                total += len(piece)
                if len(piece) < 4096:
                    break
            raw = b"".join(chunks)[:limit].decode(errors="replace")
            return raw
        except OSError:
            return ""

    @abstractmethod
    def _parse_negotiated_params(self, stdout: str) -> dict[str, str]:
        """
        Extract negotiated TLS details from merged CLI output (regex per backend).

        Keys (optional, empty if unknown): ``protocol_version``, ``cipher_suite``,
        ``named_group``.
        """

    def _format_client_connect_failure(
        self,
        proc: subprocess.Popen[bytes] | None,
        base: str = "Client process exited (connection failed)",
    ) -> str:
        detail = self._tail_merged_output(proc)
        return f"{base} | {detail}" if detail else base

    def _transmit_payload_bytes(self, payload: bytes, role: int) -> bytes:
        data = payload + b"\n"
        if role == interop_pb2.CLIENT:
            data = b"POST / HTTP/1.0\r\n\r\n" + data
        return data

    def _read_transmit_stdout(
        self,
        proc: subprocess.Popen[bytes],
        role: int,
        *,
        server_poll: bool = False,
    ) -> bytes:
        try:
            if server_poll and role == interop_pb2.SERVER:
                time.sleep(0.8)
                out_data = b""
                for _ in range(25):
                    try:
                        chunk = proc.stdout.read() if proc.stdout else None
                        if chunk:
                            out_data += chunk
                    except (BlockingIOError, OSError):
                        pass
                    time.sleep(0.1)
                return out_data
            if proc.stdout is None:
                return b""
            return proc.stdout.read() or b""
        except OSError:
            return b""

    def _post_establish_pause_seconds(self) -> float:
        return 1.0

    def _server_transmit_poll(self) -> bool:
        return False

    def _extra_cleanup(self) -> None:
        if self._used_ephemeral_pem:
            for path in self._ephemeral_pem_paths:
                try:
                    os.remove(path)
                except OSError:
                    pass
            self._used_ephemeral_pem = False

    def _server_listen_host(self, config: interop_pb2.TlsConfig) -> str:
        return "127.0.0.1"

    def _client_peer_host(self, config: interop_pb2.TlsConfig) -> str:
        return (getattr(config, "server_hostname", None) or "localhost").strip() or "localhost"

    def _server_tcp_ready_timeout_seconds(self) -> float:
        return 30.0

    def _client_tcp_ready_timeout_seconds(self) -> float:
        return 30.0

    def _micro_pause_after_ready(self) -> float:
        post = self._post_establish_pause_seconds()
        return post * 0.15 if post else 0.0

    def _sleep_after_tcp_ready(self) -> None:
        delay = self._micro_pause_after_ready()
        if delay > 0:
            time.sleep(delay)

    def _build_library_metadata(self, version: str) -> interop_pb2.LibraryMetadata:
        caps = getattr(self.__class__, "CAPABILITIES", None)
        return standard_library_metadata(
            self._component_name, version, capabilities=caps
        )

    def _validate_config_supported(self, config: interop_pb2.TlsConfig, *, role: int) -> None:
        backend = (self._component_name or "").strip().lower()
        caps = getattr(self.__class__, "CAPABILITIES", None) or {}
        unsupported = list(
            catalog_parameter_conflicts(config, backend, role=role, capabilities=caps)
        )
        if unsupported:
            details = ", ".join(unsupported)
            raise WrapperSkipError(
                f"⏭ SKIPPED: {backend} cannot apply requested parameter(s): {details}"
            )

    def GetMetadata(
        self,
        request: interop_pb2.Empty,
        context: ServicerContext,
    ) -> interop_pb2.LibraryMetadata:
        version = run_cli_version(self._version_command())
        return self._build_library_metadata(version)

    def _build_negotiated(
        self, proc: subprocess.Popen[bytes] | None
    ) -> interop_pb2.NegotiatedTlsParameters | None:
        if proc is None:
            return None
        text = self._peek_merged_output(proc)
        d = self._parse_negotiated_params(text)
        pv = (d.get("protocol_version") or "").strip()
        cs = (d.get("cipher_suite") or "").strip()
        ng = (d.get("named_group") or "").strip()
        if not (pv or cs or ng):
            return None
        return interop_pb2.NegotiatedTlsParameters(
            protocol_version=pv,
            cipher_suite=cs,
            named_group=ng,
        )

    def ExecuteOperation(
        self,
        request: interop_pb2.OperationRequest,
        context: ServicerContext,
    ) -> interop_pb2.OperationResponse:
        status = interop_pb2.OperationResponse.SUCCESS
        msg = ""
        logs = ""
        out_data = b""
        negotiated: interop_pb2.NegotiatedTlsParameters | None = None

        try:
            if request.type == interop_pb2.OperationRequest.ESTABLISH:
                self._validate_config_supported(request.config, role=request.role)
                if request.role == interop_pb2.SERVER:
                    proc, logs, msg = self._start_server(request.config)
                    self.server_proc = proc
                    if proc is None:
                        raise WrapperSetupError("server subprocess was not started")
                    if proc.poll() is not None:
                        raise WrapperSetupError(
                            self._tail_merged_output(proc) or "server process exited immediately"
                        )
                    port = int(getattr(request.config, "port", None) or 0)
                    if port <= 0:
                        raise WrapperSetupError(
                            "TlsConfig.port is missing or invalid for server ESTABLISH"
                        )
                    ok_listen, tcp_err = type(self).wait_tcp_connect(
                        self._server_listen_host(request.config),
                        port,
                        timeout_s=self._server_tcp_ready_timeout_seconds(),
                        proc=proc,
                    )
                    if not ok_listen:
                        detail = self._tail_merged_output(proc)
                        raise WrapperRuntimeError(
                            f"server did not listen on port {port} ({tcp_err})"
                            + (f" | {detail}" if detail else "")
                        )
                    self._sleep_after_tcp_ready()
                    negotiated = self._build_negotiated(self.server_proc)
                else:
                    proc, logs, msg = self._start_client(request.config)
                    self.client_proc = proc
                    if proc is None:
                        raise WrapperSetupError("client subprocess was not started")
                    port = int(getattr(request.config, "port", None) or 0)
                    if port <= 0:
                        raise WrapperSetupError(
                            "TlsConfig.port is missing or invalid for client ESTABLISH"
                        )
                    if proc.poll() is not None:
                        status = interop_pb2.OperationResponse.FAILURE
                        msg = self._format_client_connect_failure(self.client_proc)
                    else:
                        host = self._client_peer_host(request.config)
                        ok_peer, tcp_err = type(self).wait_tcp_connect(
                            host,
                            port,
                            timeout_s=self._client_tcp_ready_timeout_seconds(),
                            proc=proc,
                        )
                        if not ok_peer:
                            detail = self._tail_merged_output(proc)
                            raise WrapperRuntimeError(
                                f"no TCP route to peer {host}:{port} ({tcp_err})"
                                + (f" | {detail}" if detail else "")
                            )
                        self._sleep_after_tcp_ready()
                        if self.client_proc and self.client_proc.poll() is not None:
                            status = interop_pb2.OperationResponse.FAILURE
                            msg = self._format_client_connect_failure(self.client_proc)
                        else:
                            negotiated = self._build_negotiated(self.client_proc)

            elif request.type == interop_pb2.OperationRequest.TRANSMIT:
                target = self.server_proc if request.role == interop_pb2.SERVER else self.client_proc
                if not target:
                    status = interop_pb2.OperationResponse.FAILURE
                    msg = "[TRANSMIT] Process not found (ESTABLISH missing?)"
                elif target.poll() is not None:
                    status = interop_pb2.OperationResponse.FAILURE
                    msg = "[TRANSMIT] Process already exited"
                else:
                    if request.payload:
                        data = self._transmit_payload_bytes(request.payload, request.role)
                        try:
                            if target.stdin:
                                target.stdin.write(data)
                                target.stdin.flush()
                            time.sleep(0.5)
                        except BrokenPipeError:
                            status = interop_pb2.OperationResponse.ERROR
                            msg = "[TRANSMIT] Broken pipe (process may have exited)"
                    if status == interop_pb2.OperationResponse.SUCCESS:
                        out_data = self._read_transmit_stdout(
                            target,
                            request.role,
                            server_poll=(
                                request.role == interop_pb2.SERVER
                                and self._server_transmit_poll()
                            ),
                        )

            elif request.type == interop_pb2.OperationRequest.CLOSE:
                self._cleanup()
                msg = "Cleanup successful"

            else:
                status = interop_pb2.OperationResponse.ERROR
                msg = f"Unsupported OpType: {request.type}"

        except WrapperSetupError as e:
            status = interop_pb2.OperationResponse.ERROR
            msg = _exc_message("ESTABLISH/setup", e)
        except WrapperSkipError as e:
            status = interop_pb2.OperationResponse.SUCCESS
            msg = f"SKIP: {e}"
        except WrapperRuntimeError as e:
            status = interop_pb2.OperationResponse.FAILURE
            msg = _exc_message("ESTABLISH/runtime", e)
        except Exception as e:
            status = interop_pb2.OperationResponse.ERROR
            msg = _exc_message("ExecuteOperation/unexpected", e)

        resp = interop_pb2.OperationResponse(
            status=status,
            message=msg,
            logs=logs,
            output_data=out_data,
        )
        if negotiated is not None:
            resp.negotiated.CopyFrom(negotiated)
        return resp

    def _cleanup(self) -> None:
        self._terminate_process_hard(self.server_proc)
        self._terminate_process_hard(self.client_proc)
        self.server_proc = self.client_proc = None
        self._extra_cleanup()


def wait_tcp_connect(
    host: str,
    port: int,
    *,
    timeout_s: float = 30.0,
    poll_s: float = 0.05,
    proc: subprocess.Popen[bytes] | None = None,
) -> tuple[bool, str]:
    """Module alias for :meth:`BaseTemplateWrapper.wait_tcp_connect` (driver and tools)."""
    return BaseTemplateWrapper.wait_tcp_connect(
        host, port, timeout_s=timeout_s, poll_s=poll_s, proc=proc
    )

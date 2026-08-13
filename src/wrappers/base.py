"""Shared gRPC servicer and subprocess helpers for TLS library wrappers in containers."""

from __future__ import annotations

from abc import ABC, abstractmethod
import os
import socket
import subprocess
import time
from typing import Tuple

from grpc import ServicerContext

from core.catalog import catalog_parameter_conflicts
from core.identity import catalog_identity_pem_paths_for_config
from proto import interop_pb2
from proto import interop_pb2_grpc
from wrappers.utils import(capability, format_cli_debug_logs, format_executed_command, is_server_role,
    parse_version_line, popen_stdio_merged, read_nonblocking_stdout, run_cli_version, serve_insecure,
    split_asymmetric_csv, standard_library_metadata, test_feature_enabled_in_config, tls_mode_12_or_13)

FAIL_LOG_TAIL: int = 65536

__all__ = [
    "BaseTemplateWrapper",
    "FAIL_LOG_TAIL",
    "WrapperRuntimeError",
    "WrapperSetupError",
    "WrapperSkipError",
    "capability",
    "format_cli_debug_logs",
    "format_executed_command",
    "is_server_role",
    "parse_version_line",
    "popen_stdio_merged",
    "serve_insecure",
    "split_asymmetric_csv",
    "standard_library_metadata",
    "test_feature_enabled_in_config",
    "tls_mode_12_or_13",
    "wait_tcp_connect",
]


class WrapperSetupError(Exception):
    """Argv/launch failure before a server or client process is running."""


class WrapperRuntimeError(Exception):
    """Runtime failure after start (for example handshake or I/O expectations)."""


class WrapperSkipError(Exception):
    """Requested ``TlsConfig`` cannot be represented by backend CLI switches."""


def _exc_message(phase: str, exc: BaseException) -> str:
    return f"[{phase}] {type(exc).__name__}: {exc}"


class BaseTemplateWrapper(interop_pb2_grpc.TlsInteropWrapperServicer, ABC):
    """Dispatches gRPC ops; subclasses implement backend-specific argv and ``Popen`` setup."""

    @staticmethod
    def wait_tcp_connect(host: str, port: int, *, timeout_s: float = 30.0,
        poll_s: float = 0.05, proc: subprocess.Popen[bytes] | None = None) -> tuple[bool, str]:
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
        self._session_artifact_repo_root: str = ""
        self._last_server_cmd: str = ""
        self._last_client_cmd: str = ""
        self._last_server_output: str = ""
        self._last_client_output: str = ""

    @property
    @abstractmethod
    def _component_name(self) -> str:
        """Library label for ``GetMetadata``."""

    @abstractmethod
    def _version_command(self) -> list[str]:
        """Argv for version detection."""

    @abstractmethod
    def _start_server(self, config: interop_pb2.TlsConfig) -> Tuple[subprocess.Popen[bytes], str, str]:
        """Starts the server; returns ``(popen, logs, human message)``."""

    @abstractmethod
    def _start_client(self, config: interop_pb2.TlsConfig) -> Tuple[subprocess.Popen[bytes], str, str]:
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

        raise WrapperSetupError("No identity PEM for this test (set certificate/private_key, use certs/ "
            "from scripts/gen_interop_certs.sh, or cert.pem/key.pem in cwd)")

    def _terminate_process_hard(self, proc: subprocess.Popen[bytes] | None, *, wait_s: float = 3.0) -> None:
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

    def _tail_merged_output(self, proc: subprocess.Popen[bytes] | None, limit: int = FAIL_LOG_TAIL) -> str:
        if proc is None or proc.stdout is None:
            return ""
        try:
            raw = (proc.stdout.read() or b"").decode(errors="replace")[-limit:]
            return raw.strip()
        except OSError:
            return ""

    def _peek_merged_output(self, proc: subprocess.Popen[bytes] | None, limit: int = 65536) -> str:
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

    def _drain_process_output(self, proc: subprocess.Popen[bytes] | None, *, limit: int = FAIL_LOG_TAIL) -> str:
        """Read remaining merged stdout/stderr; prefer full text over a single-line tail."""
        peeked = self._peek_merged_output(proc, limit=limit)
        if peeked.strip():
            return peeked
        return self._tail_merged_output(proc, limit=limit)

    def _build_cli_debug_logs(self, *, role: int, cmd: str = "",
        proc: subprocess.Popen[bytes] | None = None, output: str | None = None) -> str:
        """Assemble CMD / exit / stdout / stderr for ``OperationResponse.logs``."""
        if role == interop_pb2.SERVER:
            cmd_s = (cmd or self._last_server_cmd or "").strip()
            target = proc if proc is not None else self.server_proc
            cached = self._last_server_output
        else:
            cmd_s = (cmd or self._last_client_cmd or "").strip()
            target = proc if proc is not None else self.client_proc
            cached = self._last_client_output
        if output is None:
            drained = self._drain_process_output(target) if target is not None else ""
            out_text = "\n".join(x for x in (cached, drained) if x.strip()).strip()
        else:
            out_text = output
        exit_code = target.returncode if target is not None and target.poll() is not None else None
        return format_cli_debug_logs(cmd=cmd_s, exit_code=exit_code, stdout=out_text, stderr="")

    def _remember_role_cli(self, role: int, cmd: str, output: str = "") -> None:
        if role == interop_pb2.SERVER:
            self._last_server_cmd = cmd
            if output:
                self._last_server_output = output
        else:
            self._last_client_cmd = cmd
            if output:
                self._last_client_output = output

    @abstractmethod
    def _parse_negotiated_params(self, stdout: str) -> dict[str, str]:
        """
        Extract negotiated TLS details from merged CLI output (regex per backend).

        Keys (optional, empty if unknown): ``protocol_version``, ``cipher_suite``,
        ``named_group``.
        """

    def _format_client_connect_failure(self, proc: subprocess.Popen[bytes] | None,
        base: str = "Client process exited (connection failed)", *, detail: str | None = None) -> str:
        text = detail if detail is not None else self._drain_process_output(proc)
        if not text:
            return base
        short = text.replace("\n", " ").strip()[:400]
        return f"{base} | {short}"

    def _transmit_payload_bytes(self, payload: bytes, role: int) -> bytes:
        data = payload + b"\n"
        if role == interop_pb2.CLIENT:
            data = b"POST / HTTP/1.0\r\n\r\n" + data
        return data

    def _transmit_read_timeout_seconds(self, *, role: int, server_poll: bool) -> float:
        """Hook: max time to collect TRANSMIT response bytes from merged stdout."""
        if server_poll and role == interop_pb2.SERVER:
            return self._transmit_server_read_timeout_seconds()
        return self._transmit_client_read_timeout_seconds()

    def _transmit_client_read_timeout_seconds(self) -> float:
        return 1.0

    def _transmit_server_read_timeout_seconds(self) -> float:
        return 2.5

    def _transmit_post_write_pause_seconds(self) -> float:
        return 0.5

    def _read_transmit_stdout(self, proc: subprocess.Popen[bytes], role: int, *, server_poll: bool = False) -> bytes:
        timeout_s = self._transmit_read_timeout_seconds(role=role, server_poll=server_poll)
        return read_nonblocking_stdout(proc, timeout_s=timeout_s)

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
        if self._session_artifact_repo_root:
            from wrappers.utils import remove_tls_session_artifact_files

            remove_tls_session_artifact_files(self._session_artifact_repo_root)

    def _release_server_aux(self) -> None:
        """Hook: release server-side proxy/aux processes without touching the client role."""

    def _release_server_before_establish(self) -> None:
        """Stop a prior server ESTABLISH only (same wrapper may still run the client)."""
        self._terminate_process_hard(self.server_proc)
        self.server_proc = None
        self._release_server_aux()

    def _release_client_before_establish(self) -> None:
        """Stop a prior client ESTABLISH only (leave an active server intact)."""
        self._terminate_process_hard(self.client_proc)
        self.client_proc = None

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
        return standard_library_metadata(self._component_name, version, capabilities=caps)

    def _validate_config_supported(self, config: interop_pb2.TlsConfig, *, role: int) -> None:
        backend = (self._component_name or "").strip().lower()
        caps = getattr(self.__class__, "CAPABILITIES", None) or {}
        unsupported = list(catalog_parameter_conflicts(config, backend, role=role, capabilities=caps))
        if unsupported:
            details = ", ".join(unsupported)
            raise WrapperSkipError(f"⏭ SKIPPED: {backend} cannot apply requested parameter(s): {details}")

    def GetMetadata(self, request: interop_pb2.Empty, context: ServicerContext) -> interop_pb2.LibraryMetadata:
        version = run_cli_version(self._version_command())
        return self._build_library_metadata(version)

    def _build_negotiated(self, proc: subprocess.Popen[bytes] | None,
        text: str | None = None) -> interop_pb2.NegotiatedTlsParameters | None:
        if text is None:
            if proc is None:
                return None
            text = self._peek_merged_output(proc)
        d = self._parse_negotiated_params(text or "")
        pv = (d.get("protocol_version") or "").strip()
        cs = (d.get("cipher_suite") or "").strip()
        ng = (d.get("named_group") or "").strip()
        if not (pv or cs or ng):
            return None
        return interop_pb2.NegotiatedTlsParameters(protocol_version=pv, cipher_suite=cs, named_group=ng)

    def _handle_establish(self,
        request: interop_pb2.OperationRequest) -> tuple[int, str, str, bytes, interop_pb2.NegotiatedTlsParameters | None]:
        if request.role == interop_pb2.SERVER:
            self._release_server_before_establish()
        else:
            self._release_client_before_establish()
        self._validate_config_supported(request.config, role=request.role)
        repo_root = (getattr(request.config, "repo_root", None) or "").strip()
        if repo_root:
            self._session_artifact_repo_root = repo_root
        status = interop_pb2.OperationResponse.SUCCESS
        msg = ""
        logs = ""
        negotiated: interop_pb2.NegotiatedTlsParameters | None = None

        if request.role == interop_pb2.SERVER:
            proc, cmd_logs, msg = self._start_server(request.config)
            self.server_proc = proc
            self._remember_role_cli(interop_pb2.SERVER, cmd_logs)
            if proc is None:
                raise WrapperSetupError("server subprocess was not started")
            if proc.poll() is not None:
                out = self._drain_process_output(proc)
                self._remember_role_cli(interop_pb2.SERVER, cmd_logs, out)
                raise WrapperSetupError("server process exited immediately")
            port = int(getattr(request.config, "port", None) or 0)
            if port <= 0:
                raise WrapperSetupError("TlsConfig.port is missing or invalid for server ESTABLISH")
            ok_listen, tcp_err = type(self).wait_tcp_connect(self._server_listen_host(request.config), port,
                timeout_s=self._server_tcp_ready_timeout_seconds(), proc=proc)
            if not ok_listen:
                detail = self._drain_process_output(proc)
                self._remember_role_cli(interop_pb2.SERVER, cmd_logs, detail)
                raise WrapperRuntimeError(f"server did not listen on port {port} ({tcp_err})")
            self._sleep_after_tcp_ready()
            early = self._peek_merged_output(self.server_proc)
            self._remember_role_cli(interop_pb2.SERVER, cmd_logs, early)
            negotiated = self._build_negotiated(self.server_proc, early)
            logs = self._build_cli_debug_logs(role=interop_pb2.SERVER, cmd=cmd_logs, proc=self.server_proc,
                output=early)
        else:
            proc, cmd_logs, msg = self._start_client(request.config)
            self.client_proc = proc
            self._remember_role_cli(interop_pb2.CLIENT, cmd_logs)
            if proc is None:
                raise WrapperSetupError("client subprocess was not started")
            port = int(getattr(request.config, "port", None) or 0)
            if port <= 0:
                raise WrapperSetupError("TlsConfig.port is missing or invalid for client ESTABLISH")
            if proc.poll() is not None:
                status = interop_pb2.OperationResponse.FAILURE
                out = self._drain_process_output(self.client_proc)
                self._remember_role_cli(interop_pb2.CLIENT, cmd_logs, out)
                msg = "Client process exited (connection failed)"
                logs = self._build_cli_debug_logs(role=interop_pb2.CLIENT, cmd=cmd_logs, proc=self.client_proc,
                    output=out)
            else:
                host = self._client_peer_host(request.config)
                ok_peer, tcp_err = type(self).wait_tcp_connect(host, port,
                    timeout_s=self._client_tcp_ready_timeout_seconds(), proc=proc)
                if not ok_peer:
                    detail = self._drain_process_output(proc)
                    self._remember_role_cli(interop_pb2.CLIENT, cmd_logs, detail)
                    raise WrapperRuntimeError(f"no TCP route to peer {host}:{port} ({tcp_err})")
                self._sleep_after_tcp_ready()
                if self.client_proc and self.client_proc.poll() is not None:
                    status = interop_pb2.OperationResponse.FAILURE
                    out = self._drain_process_output(self.client_proc)
                    self._remember_role_cli(interop_pb2.CLIENT, cmd_logs, out)
                    msg = "Client process exited (connection failed)"
                    logs = self._build_cli_debug_logs(role=interop_pb2.CLIENT, cmd=cmd_logs, proc=self.client_proc,
                        output=out)
                else:
                    early = self._peek_merged_output(self.client_proc)
                    self._remember_role_cli(interop_pb2.CLIENT, cmd_logs, early)
                    negotiated = self._build_negotiated(self.client_proc, early)
                    logs = self._build_cli_debug_logs(role=interop_pb2.CLIENT, cmd=cmd_logs, proc=self.client_proc,
                        output=early)

        return status, msg, logs, b"", negotiated

    def _handle_transmit(self,
        request: interop_pb2.OperationRequest) -> tuple[int, str, str, bytes, interop_pb2.NegotiatedTlsParameters | None]:
        status = interop_pb2.OperationResponse.SUCCESS
        msg = ""
        logs = ""
        out_data = b""
        role = request.role
        target = self.server_proc if role == interop_pb2.SERVER else self.client_proc
        if not target:
            status = interop_pb2.OperationResponse.FAILURE
            msg = "[TRANSMIT] Process not found (ESTABLISH missing?)"
            logs = self._build_cli_debug_logs(role=role)
        elif target.poll() is not None:
            status = interop_pb2.OperationResponse.FAILURE
            msg = "[TRANSMIT] Process already exited"
            out = self._drain_process_output(target)
            logs = self._build_cli_debug_logs(role=role, proc=target, output=out)
        else:
            if request.payload:
                data = self._transmit_payload_bytes(request.payload, request.role)
                try:
                    if target.stdin:
                        target.stdin.write(data)
                        target.stdin.flush()
                    pause = self._transmit_post_write_pause_seconds()
                    if pause > 0:
                        time.sleep(pause)
                except BrokenPipeError:
                    status = interop_pb2.OperationResponse.ERROR
                    msg = "[TRANSMIT] Broken pipe (process may have exited)"
                    out = self._drain_process_output(target)
                    logs = self._build_cli_debug_logs(role=role, proc=target, output=out)
            if status == interop_pb2.OperationResponse.SUCCESS:
                server_poll = request.role == interop_pb2.SERVER and self._server_transmit_poll()
                out_data = self._read_transmit_stdout(target, request.role, server_poll=server_poll)
                logs = self._build_cli_debug_logs(role=role, proc=target,
                    output=out_data.decode(errors="replace") if out_data else "")
        return status, msg, logs, out_data, None

    def _handle_close(self,
        request: interop_pb2.OperationRequest) -> tuple[int, str, str, bytes, interop_pb2.NegotiatedTlsParameters | None]:
        del request
        self._cleanup()
        return interop_pb2.OperationResponse.SUCCESS, "Cleanup successful", "", b"", None

    def ExecuteOperation(self, request: interop_pb2.OperationRequest,
        context: ServicerContext) -> interop_pb2.OperationResponse:
        status = interop_pb2.OperationResponse.SUCCESS
        msg = ""
        logs = ""
        out_data = b""
        negotiated: interop_pb2.NegotiatedTlsParameters | None = None

        try:
            if request.type == interop_pb2.OperationRequest.ESTABLISH:
                status, msg, logs, out_data, negotiated = self._handle_establish(request)
            elif request.type == interop_pb2.OperationRequest.TRANSMIT:
                status, msg, logs, out_data, negotiated = self._handle_transmit(request)
            elif request.type == interop_pb2.OperationRequest.CLOSE:
                status, msg, logs, out_data, negotiated = self._handle_close(request)
            else:
                status = interop_pb2.OperationResponse.ERROR
                msg = f"Unsupported OpType: {request.type}"

        except WrapperSetupError as e:
            status = interop_pb2.OperationResponse.ERROR
            msg = _exc_message("ESTABLISH/setup", e)
            if not logs:
                logs = self._build_cli_debug_logs(role=request.role)
        except WrapperSkipError as e:
            status = interop_pb2.OperationResponse.SUCCESS
            msg = f"SKIP: {e}"
        except WrapperRuntimeError as e:
            status = interop_pb2.OperationResponse.FAILURE
            msg = _exc_message("ESTABLISH/runtime", e)
            if not logs:
                logs = self._build_cli_debug_logs(role=request.role)
        except Exception as e:
            status = interop_pb2.OperationResponse.ERROR
            msg = _exc_message("ExecuteOperation/unexpected", e)
            if not logs:
                logs = self._build_cli_debug_logs(role=request.role)

        resp = interop_pb2.OperationResponse(status=status, message=msg, logs=logs, output_data=out_data)
        if negotiated is not None:
            resp.negotiated.CopyFrom(negotiated)
        return resp

    def _cleanup(self) -> None:
        self._terminate_process_hard(self.server_proc)
        self._terminate_process_hard(self.client_proc)
        self.server_proc = self.client_proc = None
        self._extra_cleanup()


def wait_tcp_connect(host: str, port: int, *, timeout_s: float = 30.0,
    poll_s: float = 0.05, proc: subprocess.Popen[bytes] | None = None) -> tuple[bool, str]:
    """Module alias for :meth:`BaseTemplateWrapper.wait_tcp_connect` (driver and tools)."""
    return BaseTemplateWrapper.wait_tcp_connect(host, port, timeout_s=timeout_s, poll_s=poll_s, proc=proc)

"""Shared gRPC servicer for TLS library wrappers (subprocess CLI, not containers)."""

from __future__ import annotations

from abc import ABC, abstractmethod
import os
import socket
import subprocess
import time
from typing import Tuple

from grpc import ServicerContext

from core.catalog import catalog_parameter_conflicts
from core.identity import catalog_identity_pem_paths_for_prefix, get_cert_prefix_for_config
from interop_proto import interop_pb2, interop_pb2_grpc
from wrappers.utils import (
    format_cli_debug_logs, hrr_detected_in_cli_output, read_nonblocking_stdout,
    run_cli_version, standard_library_metadata)

FAIL_LOG_TAIL = 65536
TCP_READY_TIMEOUT_S = 30.0
POST_ESTABLISH_PAUSE_S = 1.0
TRANSMIT_CLIENT_READ_S = 1.0
TRANSMIT_SERVER_READ_S = 2.5
TRANSMIT_POST_WRITE_PAUSE_S = 0.5


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

    def _version_command(self) -> list[str]:
        """Argv for ``GetMetadata`` CLI version. Unused when GetMetadata is overridden."""
        return []

    @abstractmethod
    def _start_server(
        self, config: interop_pb2.TlsConfig
    ) -> Tuple[subprocess.Popen[bytes], str, str]:
        """Starts the server; returns ``(popen, logs, human message)``."""

    @abstractmethod
    def _start_client(
        self, config: interop_pb2.TlsConfig
    ) -> Tuple[subprocess.Popen[bytes], str, str]:
        """Starts the client; returns ``(popen, logs, human message)``."""

    @property
    def _ephemeral_pem_paths(self) -> tuple[str, str]:
        """Paths for inline-generated PEM files (override to avoid backend clashes)."""
        return ("/tmp/interop_tls_cert.pem", "/tmp/interop_tls_key.pem")

    def _write_inline_cert_key(self, cert_b: bytes, key_b: bytes) -> tuple[str, str]:
        self._used_ephemeral_pem = True
        eph_cert, eph_key = self._ephemeral_pem_paths
        with open(eph_cert, "wb") as f:
            f.write(cert_b)
        with open(eph_key, "wb") as f:
            f.write(key_b)
        try:
            os.chmod(eph_key, 0o600)
        except OSError:
            pass
        return eph_cert, eph_key

    def _cleanup_ephemeral_pem_if_needed(self) -> None:
        if not self._used_ephemeral_pem:
            return
        eph_cert, eph_key = self._ephemeral_pem_paths
        for path in (eph_cert, eph_key):
            try:
                os.remove(path)
            except OSError:
                pass
        self._used_ephemeral_pem = False

    def _resolve_existing_pem_paths(self, config: interop_pb2.TlsConfig) -> tuple[str, str]:
        sel_cert, sel_key = catalog_identity_pem_paths_for_prefix(
            get_cert_prefix_for_config(config))
        if sel_cert and sel_key:
            return sel_cert, sel_key
        return "", ""

    def _ensure_cert_paths(self, config: interop_pb2.TlsConfig) -> tuple[str, str]:
        """Resolves cert/key from inline TlsConfig bytes or catalog ``certs/`` PEMs."""
        cert_b = getattr(config, "certificate", None) or b""
        key_b = getattr(config, "private_key", None) or b""
        if cert_b.strip() and key_b.strip():
            return self._write_inline_cert_key(cert_b, key_b)

        self._cleanup_ephemeral_pem_if_needed()
        cert, key = self._resolve_existing_pem_paths(config)
        if cert and key:
            return cert, key
        raise WrapperSetupError(
            "No identity PEM for this test (set certificate/private_key, or use certs/ "
            "from core/gen_interop_certs.sh)")

    def _terminate_process_hard(
        self, proc: subprocess.Popen[bytes] | None, *, wait_s: float = 3.0
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

    def _drain_process_output(
        self, proc: subprocess.Popen[bytes] | None, *, limit: int = FAIL_LOG_TAIL) -> str:
        if proc is None:
            return ""
        raw = read_nonblocking_stdout(
            proc, timeout_s=0.2, idle_s=0.05, max_bytes=limit)
        return raw.decode(errors="replace").strip()

    def _get_role_cli_state(
        self, role: int, cmd: str, proc: subprocess.Popen[bytes] | None
    ) -> tuple[str, subprocess.Popen[bytes] | None, str]:
        if role == interop_pb2.SERVER:
            cmd_s = (cmd or self._last_server_cmd or "").strip()
            target = proc if proc is not None else self.server_proc
            return cmd_s, target, self._last_server_output
        cmd_s = (cmd or self._last_client_cmd or "").strip()
        target = proc if proc is not None else self.client_proc
        return cmd_s, target, self._last_client_output

    def _build_cli_debug_logs(
        self,
        *,
        role: int,
        cmd: str = "",
        proc: subprocess.Popen[bytes] | None = None,
        output: str | None = None,
    ) -> str:
        """Assemble CMD / exit / stdout / stderr for ``OperationResponse.logs``."""
        cmd_s, target, cached = self._get_role_cli_state(role, cmd, proc)
        if output is None:
            drained = self._drain_process_output(target) if target is not None else ""
            out_text = "\n".join(x for x in (cached, drained) if x.strip()).strip()
        else:
            out_text = output
        exit_code = target.returncode if target is not None and target.poll() is not None else None
        return format_cli_debug_logs(
            cmd=cmd_s, exit_code=exit_code, stdout=out_text, stderr=""
        )

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
        """Extract negotiated TLS details from merged CLI output (regex per backend)."""

    def _infer_hrr_from_negotiation(
        self, config: interop_pb2.TlsConfig, text: str
    ) -> bool:
        """Optional fallback when CLI logs lack explicit HRR markers."""
        return False

    def _client_establish_output_indicates_failure(self, text: str) -> str | None:
        """Hook: return a short reason when merged client ESTABLISH output shows handshake failure."""
        return None

    def _transmit_payload_bytes(self, payload: bytes, role: int) -> bytes:
        data = payload + b"\n"
        if role == interop_pb2.CLIENT:
            data = b"POST / HTTP/1.0\r\n\r\n" + data
        return data

    def _pre_transmit_pause_seconds(self, role: int) -> float:
        """Settle time before TRANSMIT write. NSS overrides this."""
        return 0.0

    def _read_transmit_stdout(
        self, proc: subprocess.Popen[bytes], role: int, *, server_poll: bool = False) -> bytes:
        timeout_s = TRANSMIT_SERVER_READ_S if (
            server_poll and role == interop_pb2.SERVER) else TRANSMIT_CLIENT_READ_S
        return read_nonblocking_stdout(proc, timeout_s=timeout_s)

    def _server_transmit_poll(self) -> bool:
        return False

    def _extra_cleanup(self) -> None:
        self._cleanup_ephemeral_pem_if_needed()
        if self._session_artifact_repo_root:
            from wrappers.utils import remove_tls_session_artifact_files
            remove_tls_session_artifact_files(self._session_artifact_repo_root)

    def _release_server_before_establish(self) -> None:
        """Stop a prior server ESTABLISH only (same wrapper may still run the client)."""
        self._terminate_process_hard(self.server_proc)
        self.server_proc = None

    def _release_client_before_establish(self) -> None:
        """Stop a prior client ESTABLISH only (leave an active server intact)."""
        self._terminate_process_hard(self.client_proc)
        self.client_proc = None


    def _validate_config_supported(
        self, config: interop_pb2.TlsConfig, *, role: int
    ) -> None:
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
        self, request: interop_pb2.Empty, context: ServicerContext) -> interop_pb2.LibraryMetadata:
        version = run_cli_version(self._version_command())
        return standard_library_metadata(self._component_name, version)

    def _build_negotiated(
        self, proc: subprocess.Popen[bytes] | None, text: str | None = None
    ) -> interop_pb2.NegotiatedTlsParameters | None:
        raw_text = text if text is not None else self._drain_process_output(proc)
        d = self._parse_negotiated_params(raw_text or "")
        pv = (d.get("protocol_version") or "").strip()
        cs = (d.get("cipher_suite") or "").strip()
        ng = (d.get("named_group") or "").strip()
        hrr = hrr_detected_in_cli_output(raw_text or "")
        if not any((pv, cs, ng, hrr)):
            return None
        return interop_pb2.NegotiatedTlsParameters(
            protocol_version=pv, cipher_suite=cs, named_group=ng, hrr_occurred=hrr)


    def _establish_server(
        self, request: interop_pb2.OperationRequest
    ) -> tuple[int, str, str, bytes, interop_pb2.NegotiatedTlsParameters | None]:
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

        ok_listen, tcp_err = wait_tcp_connect(
            "127.0.0.1", port, timeout_s=TCP_READY_TIMEOUT_S, proc=proc)
        if not ok_listen:
            detail = self._drain_process_output(proc)
            self._remember_role_cli(interop_pb2.SERVER, cmd_logs, detail)
            raise WrapperRuntimeError(f"server did not listen on port {port} ({tcp_err})")

        delay = POST_ESTABLISH_PAUSE_S * 0.15
        if delay > 0:
            time.sleep(delay)
        early = self._drain_process_output(self.server_proc)
        self._remember_role_cli(interop_pb2.SERVER, cmd_logs, early)
        negotiated = self._build_negotiated(self.server_proc, early)
        logs = self._build_cli_debug_logs(
            role=interop_pb2.SERVER, cmd=cmd_logs, proc=self.server_proc, output=early)
        return interop_pb2.OperationResponse.SUCCESS, msg, logs, b"", negotiated

    def _collect_client_merged_output(self, early: str) -> str:
        if POST_ESTABLISH_PAUSE_S > 0:
            time.sleep(POST_ESTABLISH_PAUSE_S)
        server_chunks = self._last_server_output
        if self.server_proc is not None:
            server_extra = read_nonblocking_stdout(
                self.server_proc, timeout_s=2.0).decode(errors="replace")
            server_out = "\n".join(x for x in (server_chunks, server_extra) if x.strip()).strip()
        else:
            server_out = server_chunks

        client_extra = (
            read_nonblocking_stdout(self.client_proc, timeout_s=1.0).decode(errors="replace")
            if self.client_proc else "")
        client_out = "\n".join(x for x in (early, client_extra) if x.strip()).strip()
        return f"{server_out}\n{client_out}" if server_out.strip() else client_out

    def _client_fail(
        self, cmd_logs: str, output: str, message: str,
        negotiated: interop_pb2.NegotiatedTlsParameters | None = None
    ) -> tuple[int, str, str, bytes, interop_pb2.NegotiatedTlsParameters | None]:
        self._remember_role_cli(interop_pb2.CLIENT, cmd_logs, output)
        logs = self._build_cli_debug_logs(
            role=interop_pb2.CLIENT, cmd=cmd_logs, proc=self.client_proc, output=output)
        return interop_pb2.OperationResponse.FAILURE, message, logs, b"", negotiated

    def _wait_client_peer(self, request: interop_pb2.OperationRequest, cmd_logs: str, port: int) -> None:
        host = (getattr(request.config, "server_hostname", None) or "localhost").strip() or "localhost"
        ok_peer, tcp_err = wait_tcp_connect(
            host, port, timeout_s=TCP_READY_TIMEOUT_S, proc=self.client_proc)
        if not ok_peer:
            detail = self._drain_process_output(self.client_proc)
            self._remember_role_cli(interop_pb2.CLIENT, cmd_logs, detail)
            raise WrapperRuntimeError(f"no TCP route to peer {host}:{port} ({tcp_err})")
        delay = POST_ESTABLISH_PAUSE_S * 0.15
        if delay > 0:
            time.sleep(delay)

    def _finish_client_establish(
        self, request: interop_pb2.OperationRequest, cmd_logs: str, merged: str
    ) -> tuple[int, str, str, bytes, interop_pb2.NegotiatedTlsParameters | None]:
        negotiated = self._build_negotiated(self.client_proc, merged)
        if negotiated is not None and not negotiated.hrr_occurred:
            if self._infer_hrr_from_negotiation(request.config, merged):
                negotiated.hrr_occurred = True
        logs = self._build_cli_debug_logs(
            role=interop_pb2.CLIENT, cmd=cmd_logs, proc=self.client_proc, output=merged)
        if self.client_proc and self.client_proc.poll() is not None:
            return (
                interop_pb2.OperationResponse.FAILURE,
                "Client process exited after handshake", logs, b"", negotiated)
        establish_err = self._client_establish_output_indicates_failure(merged)
        if establish_err:
            return (
                interop_pb2.OperationResponse.FAILURE,
                f"Client handshake failed ({establish_err})", logs, b"", negotiated)
        return interop_pb2.OperationResponse.SUCCESS, "Client connected", logs, b"", negotiated

    def _establish_client_active(
        self, request: interop_pb2.OperationRequest, cmd_logs: str, port: int
    ) -> tuple[int, str, str, bytes, interop_pb2.NegotiatedTlsParameters | None]:
        self._wait_client_peer(request, cmd_logs, port)
        if self.client_proc and self.client_proc.poll() is not None:
            out = self._drain_process_output(self.client_proc)
            return self._client_fail(cmd_logs, out, "Client process exited (connection failed)")
        early = self._drain_process_output(self.client_proc)
        merged = self._collect_client_merged_output(early)
        self._remember_role_cli(interop_pb2.CLIENT, cmd_logs, merged)
        return self._finish_client_establish(request, cmd_logs, merged)

    def _establish_client(
        self, request: interop_pb2.OperationRequest
    ) -> tuple[int, str, str, bytes, interop_pb2.NegotiatedTlsParameters | None]:
        proc, cmd_logs, _ = self._start_client(request.config)
        self.client_proc = proc
        self._remember_role_cli(interop_pb2.CLIENT, cmd_logs)
        if proc is None:
            raise WrapperSetupError("client subprocess was not started")
        port = int(getattr(request.config, "port", None) or 0)
        if port <= 0:
            raise WrapperSetupError("TlsConfig.port is missing or invalid for client ESTABLISH")

        if proc.poll() is not None:
            out = self._drain_process_output(self.client_proc)
            self._remember_role_cli(interop_pb2.CLIENT, cmd_logs, out)
            logs = self._build_cli_debug_logs(role=interop_pb2.CLIENT, cmd=cmd_logs, proc=self.client_proc, output=out)
            return interop_pb2.OperationResponse.FAILURE, "Client process exited (connection failed)", logs, b"", None

        return self._establish_client_active(request, cmd_logs, port)

    def _handle_establish(
        self, request: interop_pb2.OperationRequest
    ) -> tuple[int, str, str, bytes, interop_pb2.NegotiatedTlsParameters | None]:
        if request.role == interop_pb2.SERVER:
            self._release_server_before_establish()
        else:
            self._release_client_before_establish()

        self._validate_config_supported(request.config, role=request.role)
        repo_root = (getattr(request.config, "repo_root", None) or "").strip()
        if repo_root:
            self._session_artifact_repo_root = repo_root

        if request.role == interop_pb2.SERVER:
            return self._establish_server(request)
        return self._establish_client(request)

    def _write_transmit_payload(
        self, target: subprocess.Popen[bytes], payload: bytes, role: int
    ) -> tuple[bool, str]:
        settle = self._pre_transmit_pause_seconds(role)
        if settle > 0:
            time.sleep(settle)
        data = self._transmit_payload_bytes(payload, role)
        try:
            if target.stdin:
                target.stdin.write(data)
                target.stdin.flush()
            pause = TRANSMIT_POST_WRITE_PAUSE_S
            if pause > 0:
                time.sleep(pause)
        except BrokenPipeError:
            return False, "[TRANSMIT] Broken pipe (process may have exited)"
        return True, ""

    def _handle_transmit(
        self, request: interop_pb2.OperationRequest
    ) -> tuple[int, str, str, bytes, interop_pb2.NegotiatedTlsParameters | None]:
        role = request.role
        target = self.server_proc if role == interop_pb2.SERVER else self.client_proc
        if not target:
            logs = self._build_cli_debug_logs(role=role)
            return interop_pb2.OperationResponse.FAILURE, "[TRANSMIT] Process not found (ESTABLISH missing?)", logs, b"", None

        if target.poll() is not None:
            out = self._drain_process_output(target)
            logs = self._build_cli_debug_logs(role=role, proc=target, output=out)
            return interop_pb2.OperationResponse.FAILURE, "[TRANSMIT] Process already exited", logs, b"", None

        if request.payload:
            ok, err = self._write_transmit_payload(target, request.payload, role)
            if not ok:
                out = self._drain_process_output(target)
                logs = self._build_cli_debug_logs(role=role, proc=target, output=out)
                return interop_pb2.OperationResponse.ERROR, err, logs, b"", None

        server_poll = (role == interop_pb2.SERVER and self._server_transmit_poll())
        out_data = self._read_transmit_stdout(target, role, server_poll=server_poll)
        logs = self._build_cli_debug_logs(
            role=role, proc=target, output=out_data.decode(errors="replace") if out_data else ""
        )
        return interop_pb2.OperationResponse.SUCCESS, "", logs, out_data, None

    def _handle_close(
        self, request: interop_pb2.OperationRequest
    ) -> tuple[int, str, str, bytes, interop_pb2.NegotiatedTlsParameters | None]:
        del request
        self._cleanup()
        return (
            interop_pb2.OperationResponse.SUCCESS,
            "Cleanup successful",
            "",
            b"",
            None,
        )

    def _dispatch_op(
        self, request: interop_pb2.OperationRequest
    ) -> tuple[int, str, str, bytes, interop_pb2.NegotiatedTlsParameters | None]:
        if request.type == interop_pb2.OperationRequest.ESTABLISH:
            return self._handle_establish(request)
        if request.type == interop_pb2.OperationRequest.TRANSMIT:
            return self._handle_transmit(request)
        if request.type == interop_pb2.OperationRequest.CLOSE:
            return self._handle_close(request)
        return interop_pb2.OperationResponse.ERROR, f"Unsupported OpType: {request.type}", "", b"", None

    def _format_op_error(
        self, exc: Exception, phase: str, default_status: int, role: int, logs: str
    ) -> tuple[int, str, str]:
        msg = _exc_message(phase, exc)
        err_logs = logs if logs else self._build_cli_debug_logs(role=role)
        return default_status, msg, err_logs

    def ExecuteOperation(
        self, request: interop_pb2.OperationRequest, context: ServicerContext
    ) -> interop_pb2.OperationResponse:
        status = interop_pb2.OperationResponse.SUCCESS
        msg = ""
        logs = ""
        out_data = b""
        negotiated: interop_pb2.NegotiatedTlsParameters | None = None

        try:
            status, msg, logs, out_data, negotiated = self._dispatch_op(request)
        except WrapperSetupError as e:
            status, msg, logs = self._format_op_error(
                e, "ESTABLISH/setup", interop_pb2.OperationResponse.ERROR, request.role, logs
            )
        except WrapperSkipError as e:
            status = interop_pb2.OperationResponse.SUCCESS
            msg = f"SKIP: {e}"
        except WrapperRuntimeError as e:
            status, msg, logs = self._format_op_error(
                e, "ESTABLISH/runtime", interop_pb2.OperationResponse.FAILURE, request.role, logs
            )
        except Exception as e:
            status, msg, logs = self._format_op_error(
                e, "ExecuteOperation/unexpected", interop_pb2.OperationResponse.ERROR, request.role, logs
            )

        resp = interop_pb2.OperationResponse(
            status=status, message=msg, logs=logs, output_data=out_data
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
    host: str, port: int, *, timeout_s: float = 30.0, poll_s: float = 0.05,
    proc: subprocess.Popen[bytes] | None = None) -> tuple[bool, str]:
    """Poll until ``host:port`` accepts TCP, or timeout; abort early if ``proc`` exits."""
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

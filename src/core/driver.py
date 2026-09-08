"""gRPC interop driver: matrix cell execution and round-trip orchestration."""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any, Mapping

import grpc

from core.cell_config import (
    copy_tls_config,
    tls_config_from_cell,
    tls_config_resumption_or_0rtt_active,
    wrapper_filesystem_root,
)
from core.debug_logs import (
    DebugRunLogs,
    OpTrace,
    format_output_data,
    write_cell_debug_log,
    write_fail_debug_log,
)
from core.matrix_cell import MatrixCell
from core.session_manager import BaseExecutionSession, apply_matrix_tls_endpoints
from core.utils import norm_token
from core.validation import tls_version_to_capability_name

from interop_proto import interop_pb2, interop_pb2_grpc
from wrappers.base import wait_tcp_connect
from wrappers.utils import remove_tls_session_artifact_files

logger = logging.getLogger(__name__)

EXIT_SKIP = 77
EXIT_TIMEOUT = 78

_DEFAULT_CELL_TIMEOUT_S = 45.0
_CELL_TIMEOUT_POLL_S = 0.25
_CELL_TIMEOUT_CLEANUP_WAIT_S = 15.0
_EMERGENCY_CLOSE_GRPC_S = 10.0

SUCCESS = interop_pb2.OperationResponse.SUCCESS
FAILURE = interop_pb2.OperationResponse.FAILURE

_TCP_AFTER_ESTABLISH_S = 20.0
_TRANSMIT_GAP_S = 1.0
_NSS_RESUMPTION_PRE_TRANSMIT_S = 0.5
_TEST_PAYLOAD = b"PAYLOAD"


def _run_driver_test_timed(
    driver: InteropDriver,
    server_conf: interop_pb2.TlsConfig,
    client_conf: interop_pb2.TlsConfig,
    *,
    tcp_host: str,
    tcp_port: int,
    client_wrapper: str,
    cell_timeout_s: float,
) -> tuple[bool | None, bool, Exception | None]:
    """
    Run one cell in a worker thread. Returns ``(ok, timed_out, worker_exception)``.
    ``ok`` is None when ``timed_out`` is True.
    """
    holder: dict[str, Any] = {"ok": None, "exc": None}

    def _worker() -> None:
        try:
            holder["ok"] = driver.run_test_with_configs(
                server_conf,
                client_conf,
                tcp_host=tcp_host,
                tcp_port=tcp_port,
                client_wrapper=client_wrapper,
            )
        except Exception as e:
            holder["exc"] = e

    thread = threading.Thread(target=_worker, name="interop-cell", daemon=True)
    thread.start()
    deadline = time.monotonic() + max(0.1, cell_timeout_s)
    while thread.is_alive() and time.monotonic() < deadline:
        thread.join(timeout=_CELL_TIMEOUT_POLL_S)
    if not thread.is_alive():
        return holder["ok"], False, holder["exc"]

    logger.debug(
        "[Driver] cell timeout (%.0fs): sending CLOSE to wrappers", cell_timeout_s
    )
    driver.emergency_cleanup()
    thread.join(timeout=_CELL_TIMEOUT_CLEANUP_WAIT_S)
    if thread.is_alive():
        logger.debug(
            "[Driver] worker still running after emergency cleanup; continuing matrix"
        )
    return None, True, holder["exc"]


def run_matrix_cell_grpc(
    cell: MatrixCell,
    session: BaseExecutionSession,
    *,
    verbose: bool,
    debug_logs: DebugRunLogs | None = None,
    cell_timeout_s: float = _DEFAULT_CELL_TIMEOUT_S,
) -> int:
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
    tcp_host, tcp_port = apply_matrix_tls_endpoints(
        server,
        client,
        server_conf,
        client_conf,
        repo=session.repo,
        cell=cell,
        session=session,
    )
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
        ok, timed_out, worker_exc = _run_driver_test_timed(
            driver,
            server_conf,
            client_conf,
            tcp_host=tcp_host,
            tcp_port=tcp_port,
            client_wrapper=client,
            cell_timeout_s=cell_timeout_s,
        )

        if timed_out:
            summary = f"cell exceeded {cell_timeout_s}s wall-clock limit (CLOSE sent, CLI processes killed)"
            driver._last_failure = ("cell_timeout", FAILURE, summary)
            if debug_logs is not None:
                log_path = write_cell_debug_log(
                    repo,
                    server=server,
                    client=client,
                    server_conf=server_conf,
                    client_conf=client_conf,
                    driver=driver,
                    debug_logs=debug_logs,
                    cell=cell,
                    tcp_host=tcp_host,
                    tcp_port=tcp_port,
                    result_kind="TIMEOUT",
                )
                rel = (
                    log_path.relative_to(repo)
                    if log_path.is_relative_to(repo)
                    else log_path
                )
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
                log_path = write_fail_debug_log(
                    repo,
                    server=server,
                    client=client,
                    server_conf=server_conf,
                    client_conf=client_conf,
                    driver=driver,
                    debug_logs=debug_logs,
                    cell=cell,
                    tcp_host=tcp_host,
                    tcp_port=tcp_port,
                )
                rel = (
                    log_path.relative_to(repo)
                    if log_path.is_relative_to(repo)
                    else log_path
                )
                logger.error("TEST FAILED! Details saved to: %s", rel)
            if verbose:
                return 1
            detail = ""
            if driver._last_failure:
                detail = (
                    (driver._last_failure[2] or "").replace("\n", " ").strip()[:220]
                )
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
            log_path = write_fail_debug_log(
                repo,
                server=server,
                client=client,
                server_conf=server_conf,
                client_conf=client_conf,
                driver=driver,
                debug_logs=debug_logs,
                cell=cell,
                tcp_host=tcp_host,
                tcp_port=tcp_port,
                extra_error=str(e),
            )
            rel = (
                log_path.relative_to(repo)
                if log_path.is_relative_to(repo)
                else log_path
            )
            logger.error("TEST FAILED! Details saved to: %s", rel)
        if verbose:
            logger.debug("[Driver] exception: %s", e)
        else:
            logger.info("FAIL  interop  (%s)", str(e).replace("\n", " ").strip()[:220])
        return 1
    finally:
        remove_tls_session_artifact_files(wroot)


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

    def _record_response(
        self, resp: interop_pb2.OperationResponse, label: str
    ) -> OpTrace:
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
            label=label,
            status=resp.status,
            message=(resp.message or "").strip(),
            logs=(resp.logs or "").strip(),
            negotiated=neg,
            output_data=bytes(resp.output_data or b""),
        )
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
        logger.debug(
            "[Driver] %s: %s %s", label, metadata.component_name, metadata.version
        )
        logger.debug("         roles=%s", roles_str)
        versions = [c.name for c in metadata.supported_versions]
        suf = "..." if len(versions) > 5 else ""
        logger.debug("         supported_versions=%s%s", versions[:5], suf)

    def _metadata_can_negotiate_version(
        self,
        metadata: interop_pb2.LibraryMetadata | None,
        capability_name: str,
        role: int,
    ) -> bool:
        if metadata is None:
            return True
        if metadata.roles and role not in metadata.roles:
            return False
        caps = list(metadata.supported_versions)
        if not caps:
            return True
        return any(
            c.name == capability_name and interop_pb2.NEGOTIATE in c.flags for c in caps
        )

    def scenario_skip_reason_for_configs(
        self, server_conf: interop_pb2.TlsConfig, client_conf: interop_pb2.TlsConfig
    ) -> str | None:
        """Skip run if peer metadata disagrees with role ``TlsConfig`` values."""
        if self.server_metadata is None or self.client_metadata is None:
            return None
        srv = server_conf
        cli = client_conf
        return self._scenario_skip_reason_impl(srv, cli)

    def _scenario_skip_reason_impl(
        self, srv: interop_pb2.TlsConfig, cli: interop_pb2.TlsConfig
    ) -> str | None:
        cap_srv = tls_version_to_capability_name(srv.version)
        cap_cli = tls_version_to_capability_name(cli.version)
        if not self._metadata_can_negotiate_version(
            self.server_metadata, cap_srv, interop_pb2.SERVER
        ):
            cn = self.server_metadata.component_name
            return f"server ({cn}) cannot negotiate {cap_srv} per GetMetadata"
        if not self._metadata_can_negotiate_version(
            self.client_metadata, cap_cli, interop_pb2.CLIENT
        ):
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

    def _metadata_supports_cipher(
        self, metadata: interop_pb2.LibraryMetadata | None, catalog_cipher: str
    ) -> bool:
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

    def _metadata_supports_groups(
        self, metadata: interop_pb2.LibraryMetadata | None, group_tokens: list[str]
    ) -> bool:
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
                msg[5:].strip() or "wrapper reported unsupported option"
            )
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

    def _check_hrr_assertion(
        self,
        resp: interop_pb2.OperationResponse,
        client_conf: interop_pb2.TlsConfig,
        label: str,
        *,
        client_wrapper: str = "",
    ) -> bool:
        if not getattr(client_conf, "expect_hrr", False):
            return True
        cw = (client_wrapper or "").strip().lower()
        if cw == "nss":
            logger.debug(
                "[Driver] %s: HRR assertion skipped (NSS client cannot provoke HRR reliably)",
                label,
            )
            return True
        if resp.negotiated.hrr_occurred:
            logger.debug("[Driver] %s: HRR assertion OK", label)
            return True
        summary = "expected Hello Retry Request (expect_hrr=true) but negotiated.hrr_occurred is false"
        self._last_failure = (label, FAILURE, summary)
        logger.debug("[Driver] %s: FAILURE - %s", label, summary)
        return False

    def _operation_request(
        self,
        op_type: int,
        *,
        role: int = 0,
        payload: bytes = b"",
        config: interop_pb2.TlsConfig | None = None,
    ) -> interop_pb2.OperationRequest:
        req = interop_pb2.OperationRequest(type=op_type, session_id=self.session_id)
        if role:
            req.role = role
        if payload:
            req.payload = payload
        if config is not None:
            req.config.CopyFrom(config)
        return req

    def _execute_establish(
        self,
        stub: interop_pb2_grpc.TlsInteropWrapperStub,
        role: int,
        cfg: interop_pb2.TlsConfig,
    ) -> interop_pb2.OperationResponse:
        return stub.ExecuteOperation(
            self._operation_request(
                interop_pb2.OperationRequest.ESTABLISH, role=role, config=cfg
            )
        )

    def _cleanup(self) -> None:
        logger.debug("[Driver] Cleaning up...")
        close_req = self._operation_request(interop_pb2.OperationRequest.CLOSE)
        for stub, role in [(self.server_stub, "server"), (self.client_stub, "client")]:
            try:
                self._check_response(stub.ExecuteOperation(close_req), f"CLOSE {role}")
            except Exception as e:
                logger.info("FAIL  CLOSE %s: %s", role, e)

    def emergency_cleanup(
        self, *, grpc_timeout_s: float = _EMERGENCY_CLOSE_GRPC_S
    ) -> None:
        """On cell timeout: CLOSE both roles with a short gRPC deadline (kills wrapper CLI procs)."""
        close_req = self._operation_request(interop_pb2.OperationRequest.CLOSE)
        for stub, role in [(self.server_stub, "server"), (self.client_stub, "client")]:
            try:
                resp = stub.ExecuteOperation(
                    close_req, timeout=max(0.5, grpc_timeout_s)
                )
                self._record_response(resp, f"CLOSE {role} (timeout watchdog)")
            except Exception as e:
                trace = OpTrace(
                    label=f"CLOSE {role} (timeout watchdog)",
                    status=interop_pb2.OperationResponse.ERROR,
                    message=str(e),
                    logs="",
                    negotiated=None,
                    output_data=b"",
                )
                self._op_traces.append(trace)
                logger.debug("[Driver] emergency CLOSE %s: %s", role, e)

    def _run_post_establish_round_trip(
        self,
        *,
        server_conf: interop_pb2.TlsConfig,
        client_conf: interop_pb2.TlsConfig,
        tcp_host: str,
        tcp_port: int,
        ver: str,
        client_wrapper: str = "",
    ) -> bool:
        """Host TCP check, TRANSMIT client→server, verify echoed payload."""
        ok_peer, tcp_err = wait_tcp_connect(
            tcp_host, int(tcp_port), timeout_s=_TCP_AFTER_ESTABLISH_S
        )
        if not ok_peer:
            logger.debug("[Driver] Timeout waiting for TCP %s:%s", tcp_host, tcp_port)
            summary = (
                f"TCP {tcp_host}:{tcp_port} not accepting after ESTABLISH ({tcp_err})"
            )
            establish_hints: list[str] = []
            for trace in self._op_traces:
                if trace.label.startswith("ESTABLISH"):
                    establish_hints.append(f"{trace.label}: {trace.message or 'ok'}")
            if establish_hints:
                summary += "\nPrior ESTABLISH: " + "; ".join(establish_hints)
            self._last_failure = ("wait_tcp", FAILURE, summary)
            return False

        if (
            client_wrapper or ""
        ).strip().lower() == "nss" and tls_config_resumption_or_0rtt_active(
            client_conf
        ):
            time.sleep(_NSS_RESUMPTION_PRE_TRANSMIT_S)

        logger.debug("[Driver] Transmitting: %s", _TEST_PAYLOAD.decode())
        r_tx = self.client_stub.ExecuteOperation(
            self._operation_request(
                interop_pb2.OperationRequest.TRANSMIT,
                role=interop_pb2.CLIENT,
                payload=_TEST_PAYLOAD,
            )
        )
        if not self._check_response(r_tx, "TRANSMIT client"):
            return False

        time.sleep(_TRANSMIT_GAP_S)
        r_srv = self.server_stub.ExecuteOperation(
            self._operation_request(
                interop_pb2.OperationRequest.TRANSMIT, role=interop_pb2.SERVER
            )
        )
        if not self._check_response(r_srv, "TRANSMIT server"):
            return False

        if _TEST_PAYLOAD in r_srv.output_data:
            logger.debug(">>> PASSED: payload echoed (TLS %s) <<<", ver)
            return True
        logger.debug(">>> FAILED: echo mismatch <<<")
        summary = "server output did not contain echoed payload"
        summary += "\nexpected payload: " + _TEST_PAYLOAD.decode(errors="replace")
        summary += "\nTRANSMIT client output_data:\n" + format_output_data(
            self._last_transmit_client_data
        )
        summary += "\nTRANSMIT server output_data:\n" + format_output_data(
            self._last_transmit_server_data
        )
        self._last_failure = ("verify", FAILURE, summary)
        return False

    def _run_resumption_or_0rtt_test(
        self,
        server_conf: interop_pb2.TlsConfig,
        client_conf: interop_pb2.TlsConfig,
        *,
        tcp_host: str,
        tcp_port: int,
        client_wrapper: str = "",
    ) -> bool:
        """Server stays up; client save handshake then resume (final result + logs from resume)."""
        ver = (server_conf.version or "").strip() or "default"
        try:
            logger.debug("[Driver] Resumption/0-RTT round-trip (TLS %s)", ver)
            logger.debug("[Driver] Establishing server (persistent)...")
            r = self._execute_establish(
                self.server_stub, interop_pb2.SERVER, server_conf
            )
            if not self._check_response(r, "ESTABLISH server"):
                return False

            save_conf = copy_tls_config(client_conf)
            save_conf.resumption_step = "save"
            logger.debug("[Driver] Resumption step 1: save session ticket...")
            r = self._execute_establish(self.client_stub, interop_pb2.CLIENT, save_conf)
            if not self._check_response(r, "ESTABLISH client (resumption save)"):
                return False
            if not self._check_hrr_assertion(
                r,
                client_conf,
                "ESTABLISH client (resumption save)",
                client_wrapper=client_wrapper,
            ):
                return False

            resume_conf = copy_tls_config(client_conf)
            resume_conf.resumption_step = "resume"
            logger.debug("[Driver] Resumption step 2: resume session...")
            r = self._execute_establish(
                self.client_stub, interop_pb2.CLIENT, resume_conf
            )
            if not self._check_response(r, "ESTABLISH client (resumption resume)"):
                return False

            return self._run_post_establish_round_trip(
                server_conf=server_conf,
                client_conf=client_conf,
                tcp_host=tcp_host,
                tcp_port=tcp_port,
                ver=ver,
                client_wrapper=client_wrapper,
            )
        finally:
            self._cleanup()

    def run_test_with_configs(
        self,
        server_conf: interop_pb2.TlsConfig,
        client_conf: interop_pb2.TlsConfig,
        *,
        tcp_host: str,
        tcp_port: int,
        client_wrapper: str = "",
    ) -> bool:
        """ESTABLISH server → client → host TCP check → TRANSMIT → CLOSE (wrapper idle)."""
        self._last_skip_reason = None
        if tls_config_resumption_or_0rtt_active(client_conf):
            return self._run_resumption_or_0rtt_test(
                server_conf,
                client_conf,
                tcp_host=tcp_host,
                tcp_port=tcp_port,
                client_wrapper=client_wrapper,
            )
        ver = (server_conf.version or "").strip() or "default"
        try:
            logger.debug("[Driver] Round-trip (TLS %s)", ver)
            logger.debug("[Driver] Establishing connection...")
            r = self._execute_establish(
                self.server_stub, interop_pb2.SERVER, server_conf
            )
            if not self._check_response(r, "ESTABLISH server"):
                return False
            r = self._execute_establish(
                self.client_stub, interop_pb2.CLIENT, client_conf
            )
            if not self._check_response(r, "ESTABLISH client"):
                return False
            if not self._check_hrr_assertion(
                r, client_conf, "ESTABLISH client", client_wrapper=client_wrapper
            ):
                return False

            return self._run_post_establish_round_trip(
                server_conf=server_conf,
                client_conf=client_conf,
                tcp_host=tcp_host,
                tcp_port=tcp_port,
                ver=ver,
                client_wrapper=client_wrapper,
            )
        finally:
            self._cleanup()

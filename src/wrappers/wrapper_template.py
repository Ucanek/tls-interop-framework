"""
Generic wrapper template for TLS interop backends.

Goal:
- keep the gRPC request/response flow in one reusable place
- implement only backend-specific ESTABLISH details in concrete wrappers

Usage pattern for a new wrapper:
1) subclass `BaseTemplateWrapper`
2) implement `_component_name`, `_version_command`, `_start_server`, `_start_client`
3) call `serve_insecure(YourWrapper, "Name")` in `if __name__ == "__main__":`
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from concurrent import futures
import os
import subprocess
from typing import Tuple

import grpc
from proto import interop_pb2, interop_pb2_grpc
from wrapper_utils import (
    format_client_connect_failure,
    parse_version_line,
    read_transmit_stdout,
    transmit_payload_bytes,
)


def capability(name, *flags):
    return interop_pb2.Capability(name=name, flags=list(flags))


def standard_library_metadata(component_name, version):
    """Identical capability advertisement for all stacks in this matrix."""
    cap = capability
    r, n = interop_pb2.READ, interop_pb2.NEGOTIATE
    s = interop_pb2.SET
    return interop_pb2.LibraryMetadata(
        component_name=component_name,
        version=version,
        roles=[interop_pb2.CLIENT, interop_pb2.SERVER],
        supported_versions=[
            cap("TLS1.2", r, n),
            cap("TLS1.3", r, s, n),
        ],
        cipher_suites=[
            cap("TLS_AES_256_GCM_SHA384", r, n),
            cap("TLS_CHACHA20_POLY1305_SHA256", r, n),
            cap("TLS_AES_128_GCM_SHA256", r, n),
        ],
        groups=[
            cap("X25519", r, n),
            cap("P-256", r, n),
            cap("P-384", r, n),
        ],
    )


def run_cli_version(argv, timeout=5):
    """Run a --version style command; return parsed version or 'unknown'."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0:
            return parse_version_line(r.stdout or r.stderr)
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def serve_insecure(wrapper_cls, display_name):
    """Start gRPC TlsInteropWrapper on GRPC_PORT (default 50051)."""
    port = int(os.environ.get("GRPC_PORT", "50051"))
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    interop_pb2_grpc.add_TlsInteropWrapperServicer_to_server(wrapper_cls(), server)
    server.add_insecure_port(f"0.0.0.0:{port}")
    server.start()
    print(f"{display_name} wrapper listening on {port}...")
    server.wait_for_termination()


class BaseTemplateWrapper(interop_pb2_grpc.TlsInteropWrapperServicer, ABC):
    """
    Generic request dispatcher for wrappers.

    Concrete subclasses only provide backend-specific process startup.
    """

    def __init__(self):
        self.server_proc = None
        self.client_proc = None

    @property
    @abstractmethod
    def _component_name(self) -> str:
        """Human-readable library name used in GetMetadata()."""

    @abstractmethod
    def _version_command(self) -> list[str]:
        """CLI command used to detect backend version."""

    @abstractmethod
    def _start_server(self, config) -> Tuple[object, str, str]:
        """
        Start backend server process.

        Returns: (process, logs, message)
        """

    @abstractmethod
    def _start_client(self, config) -> Tuple[object, str, str]:
        """
        Start backend client process.

        Returns: (process, logs, message)
        """

    def _client_connect_wait_seconds(self) -> float:
        return 2.5

    def _post_establish_pause_seconds(self) -> float:
        return 1.0

    def _server_transmit_poll(self) -> bool:
        return False

    def _extra_cleanup(self) -> None:
        """Optional backend-specific cleanup hook."""
        return

    def GetMetadata(self, request, context):
        version = run_cli_version(self._version_command())
        return standard_library_metadata(self._component_name, version)

    def ExecuteOperation(self, request, context):
        status = interop_pb2.OperationResponse.SUCCESS
        msg = ""
        logs = ""
        out_data = b""

        try:
            if request.type == interop_pb2.OperationRequest.ESTABLISH:
                if request.role == interop_pb2.SERVER:
                    proc, logs, msg = self._start_server(request.config)
                    self.server_proc = proc
                    if status == interop_pb2.OperationResponse.SUCCESS:
                        import time

                        time.sleep(self._post_establish_pause_seconds())
                else:
                    proc, logs, msg = self._start_client(request.config)
                    self.client_proc = proc
                    if status == interop_pb2.OperationResponse.SUCCESS:
                        # Keep timing behavior compatible with current wrappers.
                        import time

                        time.sleep(self._client_connect_wait_seconds())
                        if self.client_proc and self.client_proc.poll() is not None:
                            status = interop_pb2.OperationResponse.FAILURE
                            msg = format_client_connect_failure(self.client_proc)
                        else:
                            time.sleep(self._post_establish_pause_seconds())

            elif request.type == interop_pb2.OperationRequest.TRANSMIT:
                target = self.server_proc if request.role == interop_pb2.SERVER else self.client_proc
                if not target:
                    status = interop_pb2.OperationResponse.FAILURE
                    msg = "Process not found"
                elif target.poll() is not None:
                    status = interop_pb2.OperationResponse.FAILURE
                    msg = "Process already exited"
                else:
                    if request.payload:
                        import time

                        data = transmit_payload_bytes(request.payload, request.role)
                        try:
                            target.stdin.write(data)
                            target.stdin.flush()
                            time.sleep(0.5)
                        except BrokenPipeError:
                            status = interop_pb2.OperationResponse.ERROR
                            msg = "Broken pipe (process may have exited)"
                    if status == interop_pb2.OperationResponse.SUCCESS:
                        out_data = read_transmit_stdout(
                            target,
                            request.role,
                            server_poll=(
                                request.role == interop_pb2.SERVER and self._server_transmit_poll()
                            ),
                        )

            elif request.type == interop_pb2.OperationRequest.CLOSE:
                self._cleanup()
                msg = "Cleanup successful"

            else:
                status = interop_pb2.OperationResponse.ERROR
                msg = f"Unsupported OpType: {request.type}"

        except Exception as e:
            status = interop_pb2.OperationResponse.ERROR
            msg = str(e)

        return interop_pb2.OperationResponse(
            status=status,
            message=msg,
            logs=logs,
            output_data=out_data,
        )

    def _cleanup(self):
        if self.server_proc:
            self.server_proc.terminate()
        if self.client_proc:
            self.client_proc.terminate()
        self.server_proc = self.client_proc = None
        self._extra_cleanup()


class WrapperTemplate(BaseTemplateWrapper):
    """
    Copy this class to start a new backend implementation.
    """

    @property
    def _component_name(self) -> str:
        return "TEMPLATE"

    def _version_command(self) -> list[str]:
        return ["echo", "template-0.0"]

    def _start_server(self, config) -> Tuple[object, str, str]:
        raise NotImplementedError("Implement _start_server in your concrete wrapper.")

    def _start_client(self, config) -> Tuple[object, str, str]:
        raise NotImplementedError("Implement _start_client in your concrete wrapper.")

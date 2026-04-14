"""
GnuTLS wrapper: gnutls-serv / gnutls-cli for the TLS interop matrix.

Client uses --disable-sni to avoid DISALLOWED_NAME when the peer is an IP or Docker
service name; priorities pin TLS 1.2 vs 1.3 per TlsConfig.version.
"""
import os
import time

import wrapper_common
from proto import interop_pb2, interop_pb2_grpc
from wrapper_common import (
    format_client_connect_failure,
    popen_stdio_merged,
    read_transmit_stdout,
    run_cli_version,
    serve_insecure,
    standard_library_metadata,
    tls_mode_12_or_13,
    transmit_payload_bytes,
)


class GnuTLSWrapper(interop_pb2_grpc.TlsInteropWrapperServicer):
    def __init__(self):
        self.server_proc = None
        self.client_proc = None

    def GetMetadata(self, request, context):
        version = run_cli_version(["gnutls-cli", "--version"])
        return standard_library_metadata("GnuTLS", version)

    def ExecuteOperation(self, request, context):
        status = interop_pb2.OperationResponse.SUCCESS
        msg = ""
        logs = ""
        out_data = b""

        try:
            if request.type == interop_pb2.OperationRequest.ESTABLISH:
                if request.role == interop_pb2.SERVER:
                    cmd = [
                        "gnutls-serv",
                        "-p",
                        str(request.config.port),
                        "-a",
                        "--x509certfile",
                        "cert.pem",
                        "--x509keyfile",
                        "key.pem",
                        "--priority",
                        "NORMAL:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1",
                        "-q",
                        "--echo",
                    ]
                    self.server_proc = popen_stdio_merged(cmd, cwd=os.getcwd())
                    msg = "GnuTLS Server started"
                else:
                    host = request.config.server_hostname or "localhost"
                    if tls_mode_12_or_13(request.config) == "1.2":
                        prio = "NORMAL:-VERS-ALL:+VERS-TLS1.2"
                    else:
                        prio = "NORMAL:-VERS-ALL:+VERS-TLS1.3"
                    cmd = [
                        "gnutls-cli",
                        "-p",
                        str(request.config.port),
                        "--disable-sni",
                        "--verify-hostname",
                        host,
                        "--x509cafile",
                        "cert.pem",
                        "--priority",
                        prio,
                        host,
                    ]
                    self.client_proc = popen_stdio_merged(cmd, cwd=os.getcwd())
                    time.sleep(2.5)
                    if self.client_proc.poll() is not None:
                        status = interop_pb2.OperationResponse.FAILURE
                        msg = format_client_connect_failure(self.client_proc)
                    else:
                        msg = "GnuTLS Client connected"
                time.sleep(1)

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
                            server_poll=request.role == interop_pb2.SERVER,
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


if __name__ == "__main__":
    serve_insecure(GnuTLSWrapper, "GnuTLS")

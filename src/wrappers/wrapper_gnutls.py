import os
import re
import sys
import fcntl
import subprocess
import time
from concurrent import futures

import grpc

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from proto import interop_pb2
from proto import interop_pb2_grpc


def _parse_version(out):
    """Extract a short version string (e.g. '3.8.6') from CLI output."""
    text = (out or "").strip()
    first_line = text.split("\n")[0].strip() if text else ""
    match = re.search(r"\d+\.\d+(?:\.\d+)?", first_line)
    return match.group(0) if match else (first_line[:40] if first_line else "unknown")


def _cap(name, *flags):
    return interop_pb2.Capability(name=name, flags=list(flags))


def _tls_mode(config):
    if config is None:
        return "1.3"
    v = (config.version or "").strip().lower()
    if v in ("1.2", "1.2.0", "tls1.2", "tls1_2"):
        return "1.2"
    return "1.3"


class GnuTLSWrapper(interop_pb2_grpc.TlsInteropWrapperServicer):
    def __init__(self):
        self.server_proc = None
        self.client_proc = None

    def GetMetadata(self, request, context):
        version = "unknown"
        try:
            r = subprocess.run(
                ["gnutls-cli", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if r.returncode == 0:
                version = _parse_version(r.stdout or r.stderr)
        except Exception:
            pass
        return interop_pb2.LibraryMetadata(
            component_name="GnuTLS",
            version=version,
            roles=[interop_pb2.CLIENT, interop_pb2.SERVER],
            supported_versions=[
                _cap("TLS1.2", interop_pb2.READ, interop_pb2.NEGOTIATE),
                _cap("TLS1.3", interop_pb2.READ, interop_pb2.SET, interop_pb2.NEGOTIATE),
            ],
            cipher_suites=[
                _cap("TLS_AES_256_GCM_SHA384", interop_pb2.READ, interop_pb2.NEGOTIATE),
                _cap("TLS_CHACHA20_POLY1305_SHA256", interop_pb2.READ, interop_pb2.NEGOTIATE),
                _cap("TLS_AES_128_GCM_SHA256", interop_pb2.READ, interop_pb2.NEGOTIATE),
            ],
            groups=[
                _cap("X25519", interop_pb2.READ, interop_pb2.NEGOTIATE),
                _cap("P-256", interop_pb2.READ, interop_pb2.NEGOTIATE),
                _cap("P-384", interop_pb2.READ, interop_pb2.NEGOTIATE),
            ],
        )

    def _make_non_blocking(self, fd):
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    def ExecuteOperation(self, request, context):
        status = interop_pb2.OperationResponse.SUCCESS
        msg = ""
        logs = ""
        out_data = b""

        try:
            if request.type == interop_pb2.OperationRequest.ESTABLISH:
                if request.role == interop_pb2.SERVER:
                    # %COMPAT helps some peers; -a = do not request client certificate.
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
                    self.server_proc = subprocess.Popen(
                        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
                    )
                    self._make_non_blocking(self.server_proc.stdout)
                    msg = "GnuTLS Server started"
                else:
                    # Docker resolves hostname to IP; GnuTLS 3.8+ rejects SNI vs peer-IP (DISALLOWED_NAME).
                    host = request.config.server_hostname or "localhost"
                    if _tls_mode(request.config) == "1.2":
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
                    self.client_proc = subprocess.Popen(
                        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
                    )
                    self._make_non_blocking(self.client_proc.stdout)
                    time.sleep(2.5)
                    if self.client_proc.poll() is not None:
                        status = interop_pb2.OperationResponse.FAILURE
                        msg = "Client process exited (connection failed)"
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
                        data = request.payload + b"\n"
                        if request.role == interop_pb2.CLIENT:
                            data = b"POST / HTTP/1.0\r\n\r\n" + data  # NSS selfserv expects HTTP-like POST
                        try:
                            target.stdin.write(data)
                            target.stdin.flush()
                            time.sleep(0.5)
                        except BrokenPipeError:
                            status = interop_pb2.OperationResponse.ERROR
                            msg = "Broken pipe (process may have exited)"
                    if status == interop_pb2.OperationResponse.SUCCESS:
                        try:
                            out_data = target.stdout.read() or b""
                        except IOError:
                            out_data = b""

            elif request.type == interop_pb2.OperationRequest.CLOSE:
                self._cleanup()
                msg = "Cleanup successful"

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


def serve(port=None):
    port = port or int(os.environ.get("GRPC_PORT", "50051"))
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    interop_pb2_grpc.add_TlsInteropWrapperServicer_to_server(GnuTLSWrapper(), server)
    server.add_insecure_port(f"0.0.0.0:{port}")
    server.start()
    print(f"GnuTLS wrapper listening on {port}...")
    server.wait_for_termination()


if __name__ == "__main__":
    serve()

import os
import sys
import fcntl
import subprocess
import time
from concurrent import futures

import grpc

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import interop_pb2
import interop_pb2_grpc

class OpenSSLWrapper(interop_pb2_grpc.TlsInteropWrapperServicer):
    def __init__(self):
        self.server_proc = None
        self.client_proc = None

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
                    cmd = [
                        "openssl", "s_server", "-accept", f"0.0.0.0:{request.config.port}",
                        "-cert", "cert.pem", "-key", "key.pem", "-tls1_3", "-quiet",
                    ]
                    self.server_proc = subprocess.Popen(
                        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
                    )
                    self._make_non_blocking(self.server_proc.stdout)
                    msg = "Server started"
                else:
                    cmd = [
                        "openssl", "s_client",
                        "-connect", f"{request.config.server_hostname}:{request.config.port}",
                        "-tls1_3", "-quiet",
                    ]
                    self.client_proc = subprocess.Popen(
                        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
                    )
                    self._make_non_blocking(self.client_proc.stdout)
                    msg = "Client connected"
                time.sleep(1)

            elif request.type == interop_pb2.OperationRequest.TRANSMIT:
                target = self.server_proc if request.role == interop_pb2.SERVER else self.client_proc
                if target:
                    if request.payload:
                        target.stdin.write(request.payload + b"\n")
                        target.stdin.flush()
                        time.sleep(0.5)
                    try:
                        out_data = target.stdout.read() or b""
                    except IOError:
                        out_data = b""
                else:
                    status = interop_pb2.OperationResponse.FAILURE
                    msg = "Process not found"

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
    interop_pb2_grpc.add_TlsInteropWrapperServicer_to_server(OpenSSLWrapper(), server)
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    print(f"OpenSSL wrapper listening on {port}...")
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
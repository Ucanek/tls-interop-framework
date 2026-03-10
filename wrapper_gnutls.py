import grpc
from concurrent import futures
import subprocess
import time
import os
import fcntl
import interop_pb2
import interop_pb2_grpc

class OpenSSLWrapper(interop_pb2_grpc.TlsInteropWrapperServicer):
    def __init__(self):
        self.server_proc = None
        self.client_proc = None

    def _make_non_blocking(self, fd):
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    def ExecuteOperation(self, request):
        if request.role == interop_pb2.SERVER:
            # GnuTLS server command
            cmd = [
                "gnutls-serv", "-p", str(request.config.port),
                "--x509certfile", "cert.pem", 
                "--x509keyfile", "key.pem",
                "--priority", "NORMAL:-VERS-ALL:+VERS-TLS1.3", # Force TLS 1.3
                "--echo" # Simple echo mode for testing transmit
            ]
            self.server_proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self._make_non_blocking(self.server_proc.stdout)
            time.sleep(1)
            return interop_pb2.OperationResponse(status=0, message="GnuTLS Server started")
        else:
            # GnuTLS client command
            cmd = [
                "gnutls-cli", "-p", str(request.config.port),
                request.config.server_hostname,
                "--x509cafile", "cert.pem",
                "--priority", "NORMAL:-VERS-ALL:+VERS-TLS1.3"
            ]
            self.client_proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self._make_non_blocking(self.client_proc.stdout)
            time.sleep(1)
            return interop_pb2.OperationResponse(status=0, message="GnuTLS Client connected")

    def _cleanup(self):
        if self.server_proc: self.server_proc.terminate()
        if self.client_proc: self.client_proc.terminate()
        self.server_proc = self.client_proc = None

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    interop_pb2_grpc.add_TlsInteropWrapperServicer_to_server(OpenSSLWrapper(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    print("Wrapper listening on 50051...")
    server.wait_for_termination()

if __name__ == '__main__':
    serve()
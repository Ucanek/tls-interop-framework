"""
NSS (Network Security Services) wrapper. Uses selfserv (server) and tstclnt (client).
Requires: nss-tools (Fedora) / libnss3-tools (Debian), NSS DB created by scripts/setup_nssdb.sh.
Env: NSSDB (default ./nssdb), GRPC_PORT (default 50051), CERT_NICKNAME (default interop).
Matrix workarounds: see matrix_env.py (GnuTLS×NSS Docker).
"""
import os
import re
import shutil
import sys
import fcntl
import subprocess
import time
from concurrent import futures

import grpc

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import interop_pb2
import interop_pb2_grpc

from matrix_env import tstclnt_host_and_extra_argv

# NSS tools may live in unsupported-tools on Fedora (not in PATH)
def _nss_tool(name):
    if shutil.which(name):
        return name
    for prefix in ("/usr/lib64/nss/unsupported-tools", "/usr/lib/nss/unsupported-tools"):
        path = os.path.join(prefix, name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return name


def _parse_version(out):
    text = (out or "").strip()
    first_line = text.split("\n")[0].strip() if text else ""
    match = re.search(r"\d+\.\d+(?:\.\d+)?", first_line)
    return match.group(0) if match else (first_line[:40] if first_line else "unknown")


def _cap(name, *flags):
    return interop_pb2.Capability(name=name, flags=list(flags))


class NSSWrapper(interop_pb2_grpc.TlsInteropWrapperServicer):
    def __init__(self):
        self.server_proc = None
        self.client_proc = None
        self._socat_proc = None  # TCP proxy: selfserv only listens on loopback
        self._nssdb = os.environ.get("NSSDB", "nssdb")
        self._nick = os.environ.get("CERT_NICKNAME", "interop")
        self._selfserv = _nss_tool("selfserv")
        self._tstclnt = _nss_tool("tstclnt")

    def GetMetadata(self, request, context):
        version = "NSS"
        try:
            r = subprocess.run(
                [self._tstclnt, "-V"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if r.returncode == 0:
                version = _parse_version(r.stdout or r.stderr) or version
        except Exception:
            pass
        return interop_pb2.LibraryMetadata(
            component_name="NSS",
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
        db_spec = f"sql:{os.path.abspath(self._nssdb)}"

        try:
            if request.type == interop_pb2.OperationRequest.ESTABLISH:
                if request.role == interop_pb2.SERVER:
                    # selfserv binds to loopback only; other containers need 0.0.0.0.
                    ext_port = int(request.config.port)
                    inner_port = ext_port + 10000
                    self._socat_proc = subprocess.Popen(
                        [
                            "socat",
                            f"TCP-LISTEN:{ext_port},bind=0.0.0.0,fork,reuseaddr",
                            f"TCP:127.0.0.1:{inner_port}",
                        ],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    time.sleep(0.4)
                    # stdbuf -o 0: unbuffered stdout so fwrite() in selfserv reaches pipe immediately
                    cmd = [
                        "stdbuf",
                        "-o0",
                        self._selfserv,
                        "-d",
                        db_spec,
                        "-n",
                        self._nick,
                        "-p",
                        str(inner_port),
                        "-V",
                        "tls1.2:tls1.3",
                        "-v",
                        "-v",  # verbose>1 so received app data is written to stdout (driver checks it)
                    ]
                    self.server_proc = subprocess.Popen(
                        cmd,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        cwd=os.getcwd(),
                    )
                    self._make_non_blocking(self.server_proc.stdout)
                    msg = "NSS Server started"
                else:
                    host = request.config.server_hostname or "localhost"
                    port = int(request.config.port)
                    peer, extra = tstclnt_host_and_extra_argv(host, port)
                    cmd = [
                        self._tstclnt,
                        "-d",
                        db_spec,
                        "-h",
                        peer,
                        "-p",
                        str(port),
                        *extra,
                        "-V",
                        "tls1.2:tls1.3",
                        "-o",  # override cert validation for testing
                    ]
                    self.client_proc = subprocess.Popen(
                        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=os.getcwd()
                    )
                    self._make_non_blocking(self.client_proc.stdout)
                    time.sleep(3.5)  # NSS↔GnuTLS handshake can be slow
                    if self.client_proc.poll() is not None:
                        status = interop_pb2.OperationResponse.FAILURE
                        try:
                            err = (self.client_proc.stdout.read() or b"").decode(errors="replace")[-600:]
                        except Exception:
                            err = ""
                        msg = "Client process exited (connection failed)"
                        if err.strip():
                            msg += " | " + err.strip().replace("\n", " ")
                    else:
                        msg = "NSS Client connected"
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
                            # Server (selfserv) may buffer stdout; non-blocking read can be empty.
                            # Wait and collect output in small reads so we get the echoed POST body.
                            out_data = b""
                            if request.role == interop_pb2.SERVER:
                                time.sleep(0.8)
                                for _ in range(25):
                                    try:
                                        chunk = target.stdout.read()
                                        if chunk:
                                            out_data += chunk
                                    except (BlockingIOError, OSError):
                                        pass
                                    time.sleep(0.1)
                            else:
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
        if self._socat_proc:
            self._socat_proc.terminate()
            try:
                self._socat_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._socat_proc.kill()
        self.server_proc = self.client_proc = None
        self._socat_proc = None


def serve(port=None):
    port = port or int(os.environ.get("GRPC_PORT", "50051"))
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    interop_pb2_grpc.add_TlsInteropWrapperServicer_to_server(NSSWrapper(), server)
    server.add_insecure_port(f"0.0.0.0:{port}")
    server.start()
    print(f"NSS wrapper listening on {port}...")
    server.wait_for_termination()


if __name__ == "__main__":
    serve()

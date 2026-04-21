"""
NSS (Network Security Services) wrapper. Uses selfserv (server) and tstclnt (client).
Requires: nss-tools (Fedora) / libnss3-tools (Debian), NSS DB from scripts/setup_nssdb.sh.
Env: NSSDB (default ./nssdb), GRPC_PORT (default 50051), CERT_NICKNAME (default interop).
INTEROP_GNUTLS_NSS_PAIR: see README (GnuTLS server × NSS client); tstclnt argv helpers below.
"""
import os
import shutil
import socket
import subprocess
import time

import wrapper_common
from proto import interop_pb2, interop_pb2_grpc
from wrapper_common import (
    format_client_connect_failure,
    format_executed_command,
    parse_version_line,
    popen_stdio_merged,
    read_transmit_stdout,
    serve_insecure,
    standard_library_metadata,
    transmit_payload_bytes,
)

# Must match deploy/matrix.yaml and scripts/run.sh (export_matrix_env_for_pair).
_GNUTLS_NSS_PAIR_ENV = "INTEROP_GNUTLS_NSS_PAIR"
_TRUTHY_ENV = frozenset({"1", "true", "yes", "on"})


def _gnutls_nss_pair_enabled():
    """True when Docker matrix sets INTEROP_GNUTLS_NSS_PAIR for gnutls×nss."""
    return os.environ.get(_GNUTLS_NSS_PAIR_ENV, "0").strip().lower() in _TRUTHY_ENV


def nss_tstclnt_host_and_extra_argv(hostname, port):
    """(tstclnt -h value, extra argv after -p). See README (GnuTLS server × NSS client)."""
    h = hostname or "localhost"
    p = int(port)
    if not _gnutls_nss_pair_enabled():
        return h, ["-a", h]
    try:
        for fam in (socket.AF_INET, socket.AF_INET6):
            infos = socket.getaddrinfo(h, p, family=fam, type=socket.SOCK_STREAM)
            if infos:
                return str(infos[0][4][0]), []
    except OSError:
        pass
    return h, ["-a", h]


def _nss_tool(name):
    if shutil.which(name):
        return name
    for prefix in ("/usr/lib64/nss/unsupported-tools", "/usr/lib/nss/unsupported-tools"):
        path = os.path.join(prefix, name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return name


def _nss_library_version():
    try:
        if shutil.which("rpm"):
            r = subprocess.run(
                ["rpm", "-q", "nss-softokn"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if r.returncode == 0 and (r.stdout or "").strip():
                return parse_version_line(r.stdout) or ""
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        if shutil.which("dpkg-query"):
            r = subprocess.run(
                ["dpkg-query", "-W", "-f=${Version}\n", "libnss3"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if r.returncode == 0 and (r.stdout or "").strip():
                return parse_version_line(r.stdout) or ""
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def _tls_version_range(config):
    if config is None:
        return "tls1.2:tls1.3"
    v = (config.version or "").strip().lower()
    if v in ("1.2", "1.2.0", "tls1.2", "tls1_2"):
        return "tls1.2:tls1.2"
    if v in ("1.3", "1.3.0", "tls1.3", "tls1_3"):
        return "tls1.3:tls1.3"
    return "tls1.2:tls1.3"


class NSSWrapper(interop_pb2_grpc.TlsInteropWrapperServicer):
    def __init__(self):
        self.server_proc = None
        self.client_proc = None
        self._socat_proc = None
        self._nssdb = os.environ.get("NSSDB", "nssdb")
        self._nick = os.environ.get("CERT_NICKNAME", "interop")
        self._selfserv = _nss_tool("selfserv")
        self._tstclnt = _nss_tool("tstclnt")

    def GetMetadata(self, request, context):
        version = _nss_library_version() or "unknown"
        return standard_library_metadata("NSS", version)

    def ExecuteOperation(self, request, context):
        status = interop_pb2.OperationResponse.SUCCESS
        msg = ""
        logs = ""
        out_data = b""
        db_spec = f"sql:{os.path.abspath(self._nssdb)}"

        try:
            if request.type == interop_pb2.OperationRequest.ESTABLISH:
                nss_ver = _tls_version_range(request.config)
                if request.role == interop_pb2.SERVER:
                    ext_port = int(request.config.port)
                    inner_port = ext_port + 10000
                    cwd = os.getcwd()
                    socat_cmd = [
                        "socat",
                        f"TCP-LISTEN:{ext_port},bind=0.0.0.0,fork,reuseaddr",
                        f"TCP:127.0.0.1:{inner_port}",
                    ]
                    self._socat_proc = subprocess.Popen(
                        socat_cmd,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    time.sleep(0.4)
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
                        nss_ver,
                        "-v",
                        "-v",
                    ]
                    self.server_proc = popen_stdio_merged(cmd, cwd=cwd)
                    logs = "\n".join(
                        (
                            format_executed_command(socat_cmd, cwd),
                            format_executed_command(cmd, cwd),
                        )
                    )
                    msg = "NSS Server started"
                else:
                    host = request.config.server_hostname or "localhost"
                    port = int(request.config.port)
                    peer, extra = nss_tstclnt_host_and_extra_argv(host, port)
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
                        nss_ver,
                        "-o",
                    ]
                    cwd = os.getcwd()
                    self.client_proc = popen_stdio_merged(cmd, cwd=cwd)
                    logs = format_executed_command(cmd, cwd)
                    time.sleep(3.5)
                    if self.client_proc.poll() is not None:
                        status = interop_pb2.OperationResponse.FAILURE
                        msg = format_client_connect_failure(self.client_proc)
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
        if self._socat_proc:
            self._socat_proc.terminate()
            try:
                self._socat_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._socat_proc.kill()
        self.server_proc = self.client_proc = None
        self._socat_proc = None


if __name__ == "__main__":
    serve_insecure(NSSWrapper, "NSS")

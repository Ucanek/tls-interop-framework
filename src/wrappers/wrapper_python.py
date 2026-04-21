"""
Python stdlib ``ssl`` wrapper: in-process TLS echo server/client for the interop matrix.

Uses ``cert.pem`` / ``key.pem`` in the working directory. TLS version bounds follow
``TlsConfig.version`` (TLS 1.2 vs 1.3). Echo semantics match OpenSSL ``s_server`` /
``transmit_payload_bytes`` (client sends optional HTTP-like prefix).
"""
import os
import socket
import ssl
import sys
import threading
import time

import wrapper_common
from proto import interop_pb2, interop_pb2_grpc
from wrapper_common import (
    format_executed_command,
    serve_insecure,
    standard_library_metadata,
    tls_mode_12_or_13,
    transmit_payload_bytes,
)


def _ssl_version_tag():
    tag = getattr(ssl, "OPENSSL_VERSION", None)
    if tag:
        return (tag or "").strip()
    return "unknown"


def _python_ssl_metadata_version():
    py = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    return f"Python {py}; {_ssl_version_tag()}"


def _apply_tls_version_bounds(ctx, config):
    mode = tls_mode_12_or_13(config)
    if mode == "1.2":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3


def _server_context(config):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    _apply_tls_version_bounds(ctx, config)
    ctx.load_cert_chain("cert.pem", "key.pem")
    return ctx


def _client_context(config):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    _apply_tls_version_bounds(ctx, config)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile="cert.pem")
    return ctx


class PythonSSLWrapper(interop_pb2_grpc.TlsInteropWrapperServicer):
    def __init__(self):
        self._lock = threading.Lock()
        self._listener = None
        self._server_thread = None
        self._srv_ssl = None
        self._cli_ssl = None
        self._srv_received = bytearray()

    def GetMetadata(self, request, context):
        return standard_library_metadata("Python ssl", _python_ssl_metadata_version())

    def _close_quietly(self, obj):
        if obj is None:
            return
        try:
            obj.close()
        except OSError:
            pass

    def _server_worker(self, ctx):
        try:
            raw, _ = self._listener.accept()
        except OSError:
            return
        try:
            ssl_sock = ctx.wrap_socket(raw, server_side=True)
        except (OSError, ssl.SSLError):
            self._close_quietly(raw)
            return
        with self._lock:
            self._srv_ssl = ssl_sock
        try:
            while True:
                try:
                    data = ssl_sock.recv(65536)
                except ssl.SSLError:
                    break
                if not data:
                    break
                with self._lock:
                    self._srv_received.extend(data)
                try:
                    ssl_sock.sendall(data)
                except OSError:
                    break
        finally:
            self._close_quietly(ssl_sock)
            with self._lock:
                if self._srv_ssl is ssl_sock:
                    self._srv_ssl = None

    def ExecuteOperation(self, request, context):
        status = interop_pb2.OperationResponse.SUCCESS
        msg = ""
        logs = ""
        out_data = b""

        try:
            if request.type == interop_pb2.OperationRequest.ESTABLISH:
                if request.role == interop_pb2.SERVER:
                    port = int(request.config.port)
                    ctx = _server_context(request.config)
                    self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    cwd = os.getcwd()
                    self._listener.bind(("0.0.0.0", port))
                    self._listener.listen(1)
                    self._server_thread = threading.Thread(
                        target=self._server_worker,
                        args=(ctx,),
                        daemon=True,
                    )
                    self._server_thread.start()
                    logs = format_executed_command(
                        [
                            "python",
                            "ssl",
                            "TLS_SERVER",
                            f"0.0.0.0:{port}",
                            tls_mode_12_or_13(request.config),
                        ],
                        cwd,
                    )
                    msg = "Python ssl server listening"
                else:
                    host = request.config.server_hostname or "localhost"
                    port = int(request.config.port)
                    ctx = _client_context(request.config)
                    last_err = None
                    raw = None
                    for _ in range(80):
                        try:
                            raw = socket.create_connection((host, port), timeout=2.0)
                            break
                        except OSError as e:
                            last_err = e
                            time.sleep(0.1)
                    cwd = os.getcwd()
                    logs = format_executed_command(
                        [
                            "python",
                            "ssl",
                            "TLS_CLIENT",
                            f"{host}:{port}",
                            tls_mode_12_or_13(request.config),
                        ],
                        cwd,
                    )
                    if raw is None:
                        status = interop_pb2.OperationResponse.FAILURE
                        msg = f"connect failed: {last_err}"
                    else:
                        raw.settimeout(None)
                        try:
                            self._cli_ssl = ctx.wrap_socket(
                                raw, server_hostname=host
                            )
                        except ssl.SSLError as e:
                            self._close_quietly(raw)
                            self._cli_ssl = None
                            status = interop_pb2.OperationResponse.FAILURE
                            msg = str(e)
                        else:
                            msg = "Python ssl client connected"
                time.sleep(0.5)

            elif request.type == interop_pb2.OperationRequest.TRANSMIT:
                if request.role == interop_pb2.CLIENT:
                    if not self._cli_ssl:
                        status = interop_pb2.OperationResponse.FAILURE
                        msg = "Client TLS socket not found"
                    elif self._cli_ssl.fileno() == -1:
                        status = interop_pb2.OperationResponse.FAILURE
                        msg = "Client socket closed"
                    else:
                        if request.payload:
                            data = transmit_payload_bytes(
                                request.payload, request.role
                            )
                            try:
                                self._cli_ssl.sendall(data)
                                time.sleep(0.2)
                                # Driver only checks server TRANSMIT output; some peers do not
                                # echo application data. Never block indefinitely on recv.
                                prev_timeout = self._cli_ssl.gettimeout()
                                self._cli_ssl.settimeout(1.0)
                                try:
                                    out_data = self._cli_ssl.recv(65536) or b""
                                except (socket.timeout, TimeoutError):
                                    out_data = b""
                                finally:
                                    self._cli_ssl.settimeout(prev_timeout)
                            except (BrokenPipeError, ssl.SSLError, OSError) as e:
                                status = interop_pb2.OperationResponse.ERROR
                                msg = str(e)
                else:
                    with self._lock:
                        out_data = bytes(self._srv_received)
                        self._srv_received.clear()
                    if not out_data:
                        status = interop_pb2.OperationResponse.FAILURE
                        msg = "No application data received on server side"

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
        self._close_quietly(self._cli_ssl)
        self._cli_ssl = None
        self._close_quietly(self._srv_ssl)
        self._srv_ssl = None
        if self._listener is not None:
            try:
                self._listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._close_quietly(self._listener)
            self._listener = None
        if self._server_thread is not None:
            self._server_thread.join(timeout=4.0)
            self._server_thread = None
        with self._lock:
            self._srv_received.clear()


if __name__ == "__main__":
    serve_insecure(PythonSSLWrapper, "Python ssl")

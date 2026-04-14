"""
Shared helpers for TLS interop wrappers (OpenSSL, GnuTLS, NSS).
Sets up repo root on sys.path (dev: ``src/wrappers``; Docker: flat ``/app``).
"""
import fcntl
import os
import re
import socket
import subprocess
import sys
import time
from concurrent import futures

import grpc

def _discover_repo_root():
    here = os.path.dirname(os.path.abspath(__file__))
    for root in (
        os.path.abspath(os.path.join(here, "..", "..")),
        here,
    ):
        if os.path.isdir(os.path.join(root, "proto")):
            return root
    return os.path.abspath(os.path.join(here, "..", ".."))


_REPO_ROOT = _discover_repo_root()
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from proto import interop_pb2
from proto import interop_pb2_grpc

FAIL_LOG_TAIL = 600

# Must match deploy/matrix.yaml and scripts/run.sh (export_matrix_env_for_pair).
GNUTLS_NSS_PAIR_ENV = "INTEROP_GNUTLS_NSS_PAIR"
_TRUTHY_ENV = frozenset({"1", "true", "yes", "on"})


def parse_version_line(out):
    """Extract a short version string (e.g. '3.0.2') from CLI stdout/stderr."""
    text = (out or "").strip()
    first_line = text.split("\n")[0].strip() if text else ""
    match = re.search(r"\d+\.\d+(?:\.\d+)?", first_line)
    return match.group(0) if match else (first_line[:40] if first_line else "unknown")


def capability(name, *flags):
    return interop_pb2.Capability(name=name, flags=list(flags))


def tls_mode_12_or_13(config):
    """Map TlsConfig.version to '1.2' or '1.3' (aligned with driver aliases)."""
    if config is None:
        return "1.3"
    v = (config.version or "").strip().lower()
    if v in ("1.2", "1.2.0", "tls1.2", "tls1_2"):
        return "1.2"
    if v in ("1.3", "1.3.0", "tls1.3", "tls1_3"):
        return "1.3"
    upper = (config.version or "").strip().upper().replace(" ", "")
    if upper == "TLS1.2":
        return "1.2"
    if upper == "TLS1.3":
        return "1.3"
    return "1.3"


def make_non_blocking(fd):
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


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


def popen_stdio_merged(cmd, *, cwd=None):
    p = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=cwd,
    )
    if p.stdout:
        make_non_blocking(p.stdout)
    return p


def tail_merged_output(proc, limit=FAIL_LOG_TAIL):
    """Last ``limit`` chars of merged stdout/stderr for failure diagnostics."""
    if proc is None or proc.stdout is None:
        return ""
    try:
        raw = (proc.stdout.read() or b"").decode(errors="replace")[-limit:]
        return raw.strip().replace("\n", " ")
    except OSError:
        return ""


def format_client_connect_failure(
    proc,
    base="Client process exited (connection failed)",
):
    detail = tail_merged_output(proc)
    return f"{base} | {detail}" if detail else base


def transmit_payload_bytes(payload, role):
    """Newline suffix; HTTP-like POST prefix when the client sends (matrix / NSS selfserv)."""
    data = payload + b"\n"
    if role == interop_pb2.CLIENT:
        data = b"POST / HTTP/1.0\r\n\r\n" + data
    return data


def read_transmit_stdout(proc, role, *, server_poll=False):
    """
    Read echoed data after TRANSMIT.
    ``server_poll=True``: short polling loop (buffered server tools, e.g. NSS selfserv).
    """
    try:
        if server_poll and role == interop_pb2.SERVER:
            time.sleep(0.8)
            out_data = b""
            for _ in range(25):
                try:
                    chunk = proc.stdout.read()
                    if chunk:
                        out_data += chunk
                except (BlockingIOError, OSError):
                    pass
                time.sleep(0.1)
            return out_data
        return proc.stdout.read() or b""
    except OSError:
        return b""


def gnutls_nss_pair_enabled():
    """True when Docker matrix sets INTEROP_GNUTLS_NSS_PAIR for gnutls×nss."""
    return os.environ.get(GNUTLS_NSS_PAIR_ENV, "0").strip().lower() in _TRUTHY_ENV


def nss_tstclnt_host_and_extra_argv(hostname, port):
    """(tstclnt -h value, extra argv after -p). See README (GnuTLS server × NSS client)."""
    h = hostname or "localhost"
    p = int(port)
    if not gnutls_nss_pair_enabled():
        return h, ["-a", h]
    try:
        for fam in (socket.AF_INET, socket.AF_INET6):
            infos = socket.getaddrinfo(h, p, family=fam, type=socket.SOCK_STREAM)
            if infos:
                return str(infos[0][4][0]), []
    except OSError:
        pass
    return h, ["-a", h]


def serve_insecure(wrapper_cls, display_name):
    """Start gRPC TlsInteropWrapper on GRPC_PORT (default 50051)."""
    port = int(os.environ.get("GRPC_PORT", "50051"))
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    interop_pb2_grpc.add_TlsInteropWrapperServicer_to_server(wrapper_cls(), server)
    server.add_insecure_port(f"0.0.0.0:{port}")
    server.start()
    print(f"{display_name} wrapper listening on {port}...")
    server.wait_for_termination()

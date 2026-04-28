"""
NSS (Network Security Services) wrapper. Uses selfserv (server) and tstclnt (client).
Requires: nss-tools (Fedora) / libnss3-tools (Debian). NSS DB is initialized lazily.
Env: NSSDB (default ./nssdb), GRPC_PORT (default 50051), CERT_NICKNAME (default interop).
INTEROP_GNUTLS_NSS_PAIR: see README (GnuTLS server × NSS client); tstclnt argv helpers below.
"""
import os
import shutil
import socket
import subprocess
import time
import fcntl

from wrapper_utils import (
    format_executed_command,
    parse_version_line,
    popen_stdio_merged,
)
from wrapper_template import BaseTemplateWrapper, serve_insecure, standard_library_metadata

# Must match deploy/compose.yaml environment wiring.
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


def _ensure_tool_exists(path, name):
    if not path or not shutil.which(path):
        raise RuntimeError(f"NSS setup: required tool not found: {name}")
    return path


def _run_checked(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        detail = (r.stderr or r.stdout or "").strip()
        raise RuntimeError(f"NSS setup failed: {' '.join(cmd)} | {detail}")
    return r


def _nss_db_has_nickname(certutil, db_spec, nickname):
    r = subprocess.run(
        [certutil, "-L", "-d", db_spec, "-n", nickname],
        capture_output=True,
        text=True,
    )
    return r.returncode == 0


def _ensure_nss_db_ready(nssdb_path, cert_nickname):
    """
    Ensure NSS DB exists and contains `cert_nickname`.
    Idempotent: if DB already contains the cert, do nothing.
    """
    certutil = _ensure_tool_exists(_nss_tool("certutil"), "certutil")
    pk12util = _ensure_tool_exists(_nss_tool("pk12util"), "pk12util")
    openssl = _ensure_tool_exists(shutil.which("openssl"), "openssl")
    db_abs = os.path.abspath(nssdb_path)
    db_spec = f"sql:{db_abs}"
    lock_path = os.path.join(db_abs + ".lock")

    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    with open(lock_path, "w", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if _nss_db_has_nickname(certutil, db_spec, cert_nickname):
            return

        if not (os.path.isfile("cert.pem") and os.path.isfile("key.pem")):
            raise RuntimeError(
                "NSS setup: cert.pem/key.pem not found in current working directory"
            )

        if os.path.isdir(db_abs):
            shutil.rmtree(db_abs)
        os.makedirs(db_abs, exist_ok=True)

        _run_checked([certutil, "-N", "-d", db_spec, "--empty-password"])

        p12_path = os.path.join(db_abs, "cert.p12")
        _run_checked(
            [
                openssl,
                "pkcs12",
                "-export",
                "-in",
                "cert.pem",
                "-inkey",
                "key.pem",
                "-out",
                p12_path,
                "-passout",
                "pass:",
                "-nodes",
                "-name",
                cert_nickname,
            ]
        )
        try:
            _run_checked([pk12util, "-d", db_spec, "-i", p12_path, "-W", "", "-K", ""])
            _run_checked([certutil, "-M", "-d", db_spec, "-n", cert_nickname, "-t", "u,u,u"])
        finally:
            if os.path.isfile(p12_path):
                os.remove(p12_path)


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


class NSSWrapper(BaseTemplateWrapper):
    def __init__(self):
        super().__init__()
        self._socat_proc = None
        self._nssdb = os.environ.get("NSSDB", "nssdb")
        self._nick = os.environ.get("CERT_NICKNAME", "interop")
        self._selfserv = _nss_tool("selfserv")
        self._tstclnt = _nss_tool("tstclnt")
        _ensure_nss_db_ready(self._nssdb, self._nick)

    @property
    def _component_name(self) -> str:
        return "NSS"

    def _version_command(self) -> list[str]:
        # Not used: NSS version comes from package metadata in GetMetadata().
        return ["echo", "nss"]

    def GetMetadata(self, request, context):
        version = _nss_library_version() or "unknown"
        return standard_library_metadata(self._component_name, version)

    def _db_spec(self) -> str:
        return f"sql:{os.path.abspath(self._nssdb)}"

    def _start_server(self, config):
        nss_ver = _tls_version_range(config)
        ext_port = int(config.port)
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
            self._db_spec(),
            "-n",
            self._nick,
            "-p",
            str(inner_port),
            "-V",
            nss_ver,
            "-v",
            "-v",
        ]
        logs = "\n".join(
            (
                format_executed_command(socat_cmd, cwd),
                format_executed_command(cmd, cwd),
            )
        )
        return popen_stdio_merged(cmd, cwd=cwd), logs, "NSS Server started"

    def _start_client(self, config):
        nss_ver = _tls_version_range(config)
        host = config.server_hostname or "localhost"
        port = int(config.port)
        peer, extra = nss_tstclnt_host_and_extra_argv(host, port)
        cmd = [
            self._tstclnt,
            "-d",
            self._db_spec(),
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
        return (
            popen_stdio_merged(cmd, cwd=cwd),
            format_executed_command(cmd, cwd),
            "NSS Client connected",
        )

    def _client_connect_wait_seconds(self) -> float:
        return 3.5

    def _server_transmit_poll(self) -> bool:
        return True

    def _extra_cleanup(self) -> None:
        if self._socat_proc:
            self._socat_proc.terminate()
            try:
                self._socat_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._socat_proc.kill()
        self._socat_proc = None


if __name__ == "__main__":
    serve_insecure(NSSWrapper, "NSS")

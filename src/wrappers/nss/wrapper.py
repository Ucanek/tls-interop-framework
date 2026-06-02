"""NSS-backed interop wrapper (``selfserv`` / ``tstclnt``).

The SQLite NSS DB under ``NSSDB`` is populated on first gRPC use (not in ``__init__``)
so the wrapper process can bind :50051 before heavy ``pk12util`` imports. Bundles
under ``/app/certs/`` (RSA, ECDSA, Ed25519, Ed448) use distinct nicknames. Set
``INTEROP_GNUTLS_NSS_PAIR`` when the NSS client peers into a Docker
network where symbolic hostnames resolve to RFC 1918 addresses (see README).
"""
import os
import shutil
import socket
import subprocess
import threading
import time
import fcntl
from pathlib import Path

from core.catalog import (
    TranslationResult,
    cipher_catalog_id_requires_anon,
    cipher_catalog_id_requires_psk,
    cipher_maps_from_capabilities,
    load_local_capabilities,
    norm_catalog_token,
    psk_material_from_capabilities,
)
from core.identity import (
    identity_kind_from_signature_schemes,
    repeated_config_tokens,
    server_trust_signature_schemes_tokens,
)
from wrappers.nss.nss_db import (
    nss_interop_identity_import_rows,
    nss_server_nickname_for_config,
)
from wrappers.base import (
    BaseTemplateWrapper,
    WrapperSkipError,
    format_executed_command,
    parse_version_line,
    popen_stdio_merged,
    serve_insecure,
    standard_library_metadata,
    test_feature_enabled_in_config,
    tls_mode_12_or_13,
)

CAPABILITIES = load_local_capabilities(__file__)


def _nss_repo_root(nssdb_path: str) -> Path:
    """Interop repo root (``NSSDB`` is ``<repo>/nssdb/<backend>``)."""
    return Path(nssdb_path).resolve().parent.parent


def _nss_anon_argv(config) -> list[str]:
    """
    Anonymous suites (``test_features: anonymous``).

    ``-H 1`` enables DHE for ``dh-anon-*``; ``-H 2`` prefers RFC 7919 DH groups where needed.
    """
    if not test_feature_enabled_in_config(config, "anonymous"):
        return []
    raw_cipher = (getattr(config, "cipher_suite", None) or "").strip()
    if not raw_cipher or not cipher_catalog_id_requires_anon(raw_cipher):
        return []
    key = norm_catalog_token(raw_cipher)
    if key.startswith("dh-anon"):
        return ["-H", "1"]
    if key.startswith("ecdh-anon"):
        return ["-H", "2"]
    return ["-H", "1"]


def _nss_psk_z_argv(config, caps: dict) -> list[str]:
    """
    ``-z 0x<hex>[:identity]`` — NSS TLS 1.3 External PSK (selfserv/tstclnt).

    TLS 1.2 static PSK suites (``ecdhe-psk-*``, ``psk-*``, …) are not implemented
  in NSS; see ``nss_tls12_static_psk_skip_reason`` in catalog.py.
    """
    if not test_feature_enabled_in_config(config, "psk"):
        return []
    if tls_mode_12_or_13(config) != "1.3":
        return []
    raw_cipher = (getattr(config, "cipher_suite", None) or "").strip()
    cipher_for_psk = (
        raw_cipher
        if raw_cipher and cipher_catalog_id_requires_psk(raw_cipher)
        else "psk-aes-128-gcm-sha256"
    )
    mat = psk_material_from_capabilities(caps, cipher_for_psk)
    if not mat:
        return []
    identity, secret_hex = mat
    return ["-z", f"0x{secret_hex}:{identity}"]


def _build_tls_argv(
    config,
    *,
    role=None,
    capabilities=None,
) -> TranslationResult:
    del role
    caps = capabilities if capabilities is not None else CAPABILITIES
    argv: list[str] = []
    unsupported: list[str] = []
    mode = tls_mode_12_or_13(config)
    cap13, cap12 = cipher_maps_from_capabilities(caps)

    raw_cipher = (getattr(config, "cipher_suite", None) or "").strip()
    if raw_cipher:
        key = norm_catalog_token(raw_cipher)
        cap_sel = cap13 if mode == "1.3" else cap12
        if key in cap_sel:
            argv.extend(["-c", cap_sel[key]])
        else:
            unsupported.append(f"cipher_suite:{raw_cipher!r} (no NSS -c mapping)")

    if mode == "1.3":
        for field, csv_flag in (
            ("supported_groups", "-I"),
            ("signature_schemes", "-J"),
        ):
            items = repeated_config_tokens(config, field)
            if not items:
                continue
            block = caps.get(field)
            if not isinstance(block, dict):
                continue
            parts: list[str] = []
            for it in items:
                k = norm_catalog_token(it)
                v = block.get(k) or block.get(it)
                if not v:
                    unsupported.append(
                        f"{field}:{it!r} (unsupported for NSS mapping)"
                    )
                    continue
                parts.append(str(v))
            if parts:
                argv.extend([csv_flag, ",".join(parts)])

    argv.extend(_nss_anon_argv(config))
    argv.extend(_nss_psk_z_argv(config, caps))

    return TranslationResult(tuple(argv), tuple(unsupported))


def tls_argv_for_config(
    config,
    *,
    role=None,
    capabilities=None,
) -> TranslationResult:
    return _build_tls_argv(config, role=role, capabilities=capabilities)

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


def resolve_cli_tool(name: str) -> str | None:
    """Plugin hook: resolve NSS CLI binaries (including Fedora unsupported-tools path)."""
    found = shutil.which(name)
    if found:
        return found
    for prefix in ("/usr/lib64/nss/unsupported-tools", "/usr/lib/nss/unsupported-tools"):
        path = os.path.join(prefix, name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def orchestration_env(active_backends: frozenset[str] | set[str]) -> dict[str, str]:
    """Plugin hook: GnuTLS server × NSS client SNI workaround."""
    if "gnutls" in active_backends and "nss" in active_backends:
        return {"INTEROP_GNUTLS_NSS_PAIR": "1"}
    return {"INTEROP_GNUTLS_NSS_PAIR": "0"}


def local_wrapper_env(
    repo: Path,
    backend_id: str,
    active_backends: frozenset[str] | set[str],
) -> dict[str, str]:
    """Plugin hook: per-backend NSS DB directory."""
    del active_backends
    return {"NSSDB": str(repo / "nssdb" / backend_id)}


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


def _ensure_nss_db_identities(nssdb_path: str, identities: list[tuple[str, str, str]]) -> None:
    """
    Ensure NSS DB exists and contains every ``(nickname, cert_pem, key_pem)``.

    Idempotent when all nicknames are already present.
    """
    if not identities:
        raise RuntimeError("NSS setup: no identity bundles to import")

    certutil = _ensure_tool_exists(_nss_tool("certutil"), "certutil")
    pk12util = _ensure_tool_exists(_nss_tool("pk12util"), "pk12util")
    openssl = _ensure_tool_exists(shutil.which("openssl"), "openssl")
    db_abs = os.path.abspath(nssdb_path)
    db_spec = f"sql:{db_abs}"
    lock_path = db_abs + ".lock"
    lock_parent = os.path.dirname(os.path.abspath(lock_path))
    if lock_parent:
        os.makedirs(lock_parent, exist_ok=True)
    with open(lock_path, "w", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if all(_nss_db_has_nickname(certutil, db_spec, nick) for nick, _, _ in identities):
            return

        if os.path.isdir(db_abs):
            shutil.rmtree(db_abs)
        os.makedirs(db_abs, exist_ok=True)

        _run_checked([certutil, "-N", "-d", db_spec, "--empty-password"])

        for nickname, cert_pem, key_pem in identities:
            if not (os.path.isfile(cert_pem) and os.path.isfile(key_pem)):
                raise RuntimeError(
                    f"NSS setup: missing PEM for {nickname}: {cert_pem!r} / {key_pem!r}"
                )
            p12_path = os.path.join(db_abs, f"{nickname}.p12")
            _run_checked(
                [
                    openssl,
                    "pkcs12",
                    "-export",
                    "-in",
                    cert_pem,
                    "-inkey",
                    key_pem,
                    "-out",
                    p12_path,
                    "-passout",
                    "pass:",
                    "-nodes",
                    "-name",
                    nickname,
                ]
            )
            try:
                _run_checked([pk12util, "-d", db_spec, "-i", p12_path, "-W", "", "-K", ""])
                _run_checked([certutil, "-M", "-d", db_spec, "-n", nickname, "-t", "u,u,u"])
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
    CAPABILITIES = CAPABILITIES

    def __init__(self):
        super().__init__()
        self._socat_proc = None
        self._nssdb = os.environ.get("NSSDB", "nssdb")
        self._selfserv = _nss_tool("selfserv")
        self._tstclnt = _nss_tool("tstclnt")
        self._nss_db_ready = False
        self._nss_db_lock = threading.Lock()

    def _ensure_nss_db_ready(self) -> None:
        """Populate NSS DB once; deferred so gRPC can listen before pk12util work."""
        if self._nss_db_ready:
            return
        with self._nss_db_lock:
            if self._nss_db_ready:
                return
            repo = _nss_repo_root(self._nssdb)
            _ensure_nss_db_identities(
                self._nssdb,
                nss_interop_identity_import_rows(repo=repo),
            )
            self._nss_db_ready = True

    def _cleanup_nss_db(self) -> None:
        """Drop local NSS DB dir so each test starts from a clean state."""
        try:
            shutil.rmtree(os.path.abspath(self._nssdb), ignore_errors=True)
        finally:
            self._nss_db_ready = False

    @property
    def _component_name(self) -> str:
        return "NSS"

    def _version_command(self) -> list[str]:
        # Not used: NSS version comes from package metadata in GetMetadata().
        return ["echo", "nss"]

    def GetMetadata(self, request, context):
        self._ensure_nss_db_ready()
        version = _nss_library_version() or "unknown"
        return standard_library_metadata(
            self._component_name, version, capabilities=CAPABILITIES
        )

    def _parse_negotiated_params(self, stdout: str) -> dict[str, str]:
        import re

        text = stdout or ""
        out: dict[str, str] = {}
        m = re.search(
            r"(?:TLS\s+Version|Version)\s*:\s*(\S+)",
            text,
            re.IGNORECASE,
        )
        if m:
            out["protocol_version"] = m.group(1).strip()
        m2 = re.search(r"Cipher\s*Suite\s*:\s*(\S+)", text, re.IGNORECASE)
        if m2:
            out["cipher_suite"] = m2.group(1).strip()
        m3 = re.search(
            r"(?:Negotiated\s+ECC|Named\s+Curve|Group)\s*[:=]\s*(\S+)",
            text,
            re.IGNORECASE,
        )
        if m3:
            out["named_group"] = m3.group(1).strip()
        return out

    def _db_spec(self) -> str:
        return f"sql:{os.path.abspath(self._nssdb)}"

    def _session_ticket_args(self, config):
        return ["-u"] if bool(getattr(config, "session_tickets_enabled", False)) else []

    def _nss_tls_argv(self, config) -> list[str]:
        return list(_build_tls_argv(config).argv)

    def _nss_repo(self) -> Path:
        return _nss_repo_root(self._nssdb)

    def _nss_server_nickname(self, config) -> str:
        return nss_server_nickname_for_config(config, repo=self._nss_repo())

    def _skip_if_nss_eddsa_unsupported(self, config, *, server: bool) -> None:
        schemes = (
            server_trust_signature_schemes_tokens(config)
            if server
            else repeated_config_tokens(config, "signature_schemes")
        )
        if identity_kind_from_signature_schemes(schemes) in ("ed25519", "ed448"):
            raise WrapperSkipError(
                "NSS pk12util cannot import OpenSSL Ed25519/Ed448 PKCS#12 private keys "
                "(Mozilla NSS bug 1993638). Use openssl or gnutls for EdDSA in this matrix."
            )

    def _start_server(self, config):
        self._ensure_nss_db_ready()
        self._skip_if_nss_eddsa_unsupported(config, server=True)
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
            self._nss_server_nickname(config),
            "-p",
            str(inner_port),
            "-V",
            nss_ver,
            *self._nss_tls_argv(config),
            *self._session_ticket_args(config),
        ]
        # selfserv ``-Q``: enables built-in HTTP/1.1 ALPN (no custom ALPN list in NSS tooling).
        if repeated_config_tokens(config, "alpn_protocols"):
            cmd.append("-Q")
        cmd.extend(
            [
                "-v",
                "-v",
            ]
        )
        logs = "\n".join(
            (
                format_executed_command(socat_cmd, cwd),
                format_executed_command(cmd, cwd),
            )
        )
        return popen_stdio_merged(cmd, cwd=cwd), logs, "NSS Server started"

    def _start_client(self, config):
        self._ensure_nss_db_ready()
        self._skip_if_nss_eddsa_unsupported(config, server=False)
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
            *self._nss_tls_argv(config),
            "-o",
        ]
        cmd.extend(
            [
                "-p",
                str(port),
                *extra,
                "-V",
                nss_ver,
                *self._session_ticket_args(config),
            ]
        )
        cwd = os.getcwd()
        return (
            popen_stdio_merged(cmd, cwd=cwd),
            format_executed_command(cmd, cwd),
            "NSS Client connected",
        )

    def _server_transmit_poll(self) -> bool:
        return True

    def _extra_cleanup(self) -> None:
        super()._extra_cleanup()
        if self._socat_proc:
            self._socat_proc.terminate()
            try:
                self._socat_proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._socat_proc.kill()
        self._socat_proc = None
        self._cleanup_nss_db()


if __name__ == "__main__":
    serve_insecure(NSSWrapper, "NSS")

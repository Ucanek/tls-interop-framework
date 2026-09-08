"""NSS-backed interop wrapper (``selfserv`` / ``tstclnt``).

The SQLite NSS DB under ``NSSDB`` (default ``wrappers/nss/nssdb/<backend>``) is populated on first gRPC use (not in ``__init__``)
so the wrapper process can bind :50051 before heavy ``pk12util`` imports. Bundles
under ``certs/`` (RSA, ECDSA, Ed25519, Ed448) use distinct nicknames. Set
``INTEROP_GNUTLS_NSS_PAIR`` when the NSS client peers into a Docker
network where symbolic hostnames resolve to RFC 1918 addresses (see README).
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import socket
import subprocess
import threading
from pathlib import Path
from typing import Any

from core.constants import TlsFeature
from core.orchestration_context import active_orchestration_context
from core.capabilities import(TranslationResult, cipher_catalog_id_requires_anon, cipher_catalog_id_requires_psk,
    cipher_maps_from_capabilities, load_local_capabilities, psk_material_from_capabilities, repository_root)
from core.registry import wrappers_plugin_dir
from core.identity import repeated_config_tokens
from core.tls_config_view import RoleLike, TlsConfigLike
from core.utils import norm_catalog_token
from interop_proto import interop_pb2
from wrappers.base import(BaseTemplateWrapper, WrapperSessionState,
    format_executed_command, popen_stdio_merged, serve_insecure)
from wrappers.nss.nss_db import(_ensure_nss_db_identities, get_nss_library_version,
    nss_interop_identity_import_rows, nss_server_nickname_for_config, resolve_cli_tool as nss_resolve_cli_tool)
from wrappers.utils import(standard_library_metadata, test_feature_enabled_in_config, tls_mode_12_or_13)

CAPABILITIES = load_local_capabilities(__file__)

logger = logging.getLogger(__name__)

# Must match ``orchestration_env`` wiring when GnuTLS and NSS run together.
_GNUTLS_NSS_PAIR_ENV = "INTEROP_GNUTLS_NSS_PAIR"
_TRUTHY_ENV = frozenset({"1", "true", "yes", "on"})


def nss_db_directory(repo: Path, backend_id: str = "nss") -> Path:
    """Per-backend NSS SQL DB path: ``<repo>/src/wrappers/nss/nssdb/<backend_id>``."""
    return wrappers_plugin_dir(repo) / "nss" / "nssdb" / backend_id


def _nss_repo_root(_nssdb_path: str) -> Path:
    """Interop repo root (for ``certs/`` and identity import rows)."""
    return repository_root()


def _nss_anon_argv(config: TlsConfigLike) -> list[str]:
    """
    Anonymous suites (``test_features: anonymous``).

    ``-H 1`` enables DHE for ``dh-anon-*``; ``-H 2`` prefers RFC 7919 DH groups where needed.
    """
    if not test_feature_enabled_in_config(config, TlsFeature.ANONYMOUS):
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


def _nss_psk_z_argv(config: TlsConfigLike, caps: dict[str, Any]) -> list[str]:
    """
    ``-z 0x<hex>[:identity]`` — NSS TLS 1.3 External PSK (selfserv/tstclnt).

    TLS 1.2 static PSK suites are omitted from NSS ``capabilities.json`` ``tls12``;
    use TLS 1.3 + ``test_features: psk`` for NSS PSK interop.
    """
    if not test_feature_enabled_in_config(config, TlsFeature.PSK):
        return []
    if tls_mode_12_or_13(config) != "1.3":
        return []
    raw_cipher = (getattr(config, "cipher_suite", None) or "").strip()
    cipher_for_psk = (raw_cipher if raw_cipher and cipher_catalog_id_requires_psk(raw_cipher)
        else "psk-aes-128-gcm-sha256")
    mat = psk_material_from_capabilities(caps, cipher_for_psk)
    if not mat:
        return []
    identity, secret_hex = mat
    return ["-z", f"0x{secret_hex}:{identity}"]


def _build_tls_argv(config: TlsConfigLike, *, role: RoleLike | None = None,
    capabilities: dict[str, Any] | None = None) -> TranslationResult:
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
        for field, csv_flag in (("supported_groups", "-I"), ("signature_schemes", "-J")):
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
                    unsupported.append(f"{field}:{it!r} (unsupported for NSS mapping)")
                    continue
                parts.append(str(v))
            if parts:
                argv.extend([csv_flag, ",".join(parts)])

    argv.extend(_nss_anon_argv(config))
    argv.extend(_nss_psk_z_argv(config, caps))

    return TranslationResult(tuple(argv), tuple(unsupported))


def _gnutls_nss_pair_enabled() -> bool:
    """True when Docker matrix sets INTEROP_GNUTLS_NSS_PAIR for gnutls×nss."""
    if active_orchestration_context().gnutls_nss_pair:
        return True
    return os.environ.get(_GNUTLS_NSS_PAIR_ENV, "0").strip().lower() in _TRUTHY_ENV


def nss_tstclnt_sni_name(hostname: str) -> str:
    """SNI / tstclnt ``-a`` name matching generated leaf certs (``CN=server_node``)."""
    h = (hostname or "").strip()
    if not h:
        return "server_node"
    if h in ("127.0.0.1", "localhost", "::1"):
        return "server_node"
    if h.startswith("[") and h.endswith("]"):
        inner = h[1:-1]
        if ":" in inner:
            return "server_node"
    return h


def nss_tstclnt_host_and_extra_argv(hostname, port):
    """(tstclnt -h value, extra argv after -p). See README (GnuTLS server × NSS client)."""
    h = hostname or "localhost"
    p = int(port)
    sni = nss_tstclnt_sni_name(h)
    if not _gnutls_nss_pair_enabled():
        return h, ["-a", sni]
    try:
        for fam in (socket.AF_INET, socket.AF_INET6):
            infos = socket.getaddrinfo(h, p, family=fam, type=socket.SOCK_STREAM)
            if infos:
                return str(infos[0][4][0]), ["-a", sni]
    except OSError:
        pass
    return h, ["-a", sni]


def _tls_version_range(config: interop_pb2.TlsConfig | None) -> str:
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

    @classmethod
    def tls_argv_for_config(cls, config: Any, *, role: Any | None = None,
        capabilities: dict[str, Any] | None = None) -> TranslationResult:
        return _build_tls_argv(config, role=role, capabilities=capabilities)

    @classmethod
    def resolve_cli_tool(cls, exe: str) -> str | None:
        return nss_resolve_cli_tool(exe)

    @classmethod
    def orchestration_env(cls, active_backends: frozenset[str] | set[str]) -> dict[str, str]:
        if "gnutls" in active_backends and "nss" in active_backends:
            return {_GNUTLS_NSS_PAIR_ENV: "1"}
        return {_GNUTLS_NSS_PAIR_ENV: "0"}

    @classmethod
    def local_wrapper_env(cls, repo: Path, backend_id: str,
        active_backends: frozenset[str] | set[str]) -> dict[str, str]:
        del active_backends
        return {"NSSDB": str(nss_db_directory(repo, backend_id))}

    def __init__(self) -> None:
        super().__init__()
        self._nssdb = os.environ.get("NSSDB", str(nss_db_directory(repository_root(), "nss")))
        self._selfserv = type(self).resolve_cli_tool("selfserv") or "selfserv"
        self._tstclnt = type(self).resolve_cli_tool("tstclnt") or "tstclnt"
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
            _ensure_nss_db_identities(self._nssdb, nss_interop_identity_import_rows(repo=repo))
            self._nss_db_ready = True

    def _cleanup_nss_db(self) -> None:
        """Drop local NSS DB dir so each test starts from a clean state."""
        path = os.path.abspath(self._nssdb)
        try:
            shutil.rmtree(path)
        except Exception as e:
            logger.warning("Failed to remove directory %s: %s", path, e)
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
        version = get_nss_library_version() or "unknown"
        return standard_library_metadata(self._component_name, version, capabilities=CAPABILITIES)

    def _parse_negotiated_params(self, stdout: str) -> dict[str, str]:
        text = stdout or ""
        out: dict[str, str] = {}
        m = re.search(r"(?:TLS\s+Version|Version)\s*:\s*(\S+)", text, re.IGNORECASE)
        if m:
            out["protocol_version"] = m.group(1).strip()
        if m2 := re.search(r"Cipher\s*Suite\s*:\s*(\S+)", text, re.IGNORECASE):
            out["cipher_suite"] = m2.group(1).strip()
        if m3 := re.search(r"(?:Negotiated\s+ECC|Named\s+Curve|Group)\s*[:=]\s*(\S+)", text, re.IGNORECASE):
            out["named_group"] = m3.group(1).strip()
        return out

    def _client_establish_output_indicates_failure(self, text: str) -> str | None:
        blob = (text or "").strip()
        if not blob:
            return None
        markers = (
            "SSL_ERROR_NO_CYPHER_OVERLAP",
            "read from socket failed",
            "Cannot communicate securely with peer",
            "Handshake failed",
        )
        for m in markers:
            if m in blob:
                return m
        return None

    def _db_spec(self) -> str:
        return f"sql:{os.path.abspath(self._nssdb)}"

    def _session_ticket_args(self, config: interop_pb2.TlsConfig) -> list[str]:
        return ["-u"] if bool(getattr(config, "session_tickets_enabled", False)) else []

    def _nss_tls_argv(self, config: interop_pb2.TlsConfig) -> list[str]:
        return list(self.tls_argv_for_config(config).argv)

    def _nss_repo(self) -> Path:
        return _nss_repo_root(self._nssdb)

    def _nss_server_nickname(self, config: interop_pb2.TlsConfig) -> str:
        return nss_server_nickname_for_config(config, repo=self._nss_repo())

    def _nss_prepare(self, config: interop_pb2.TlsConfig) -> str:
        self._ensure_nss_db_ready()
        return _tls_version_range(config)

    def _build_common_args(self, config: interop_pb2.TlsConfig, *, for_server: bool) -> list[str]:
        args = list(self._nss_tls_argv(config))
        if for_server:
            if test_feature_enabled_in_config(config, "mtls"):
                args.append("-r")
            args.extend(["-v", "-v"])
        else:
            args.append("-o")
            if test_feature_enabled_in_config(config, "mtls"):
                args.extend(["-n", "interop_rsa_default"])
        return args

    def _nss_version_args(self, nss_ver: str) -> list[str]:
        return ["-V", nss_ver]

    def _popen_merged_cmd(self, cmd: list[str]) -> tuple[subprocess.Popen[bytes], str]:
        cwd = os.getcwd()
        return popen_stdio_merged(cmd, cwd=cwd), format_executed_command(cmd, cwd)

    def _start_server(self, config: interop_pb2.TlsConfig, state: WrapperSessionState):
        nss_ver = self._nss_prepare(config)
        port = int(config.port)
        cmd = ["stdbuf", "-o0", self._selfserv, "-d", self._db_spec(), "-n", self._nss_server_nickname(config),
            "-p", str(port), *self._nss_version_args(nss_ver), *self._build_common_args(config, for_server=True)]
        proc, logs = self._popen_merged_cmd(cmd)
        return proc, logs, "NSS Server started"

    def _start_client(self, config: interop_pb2.TlsConfig, state: WrapperSessionState):
        has_resumption = test_feature_enabled_in_config(config, "resumption")
        has_0rtt = test_feature_enabled_in_config(config, "0rtt")
        step = (getattr(config, "resumption_step", None) or "").strip()

        nss_ver = self._nss_prepare(config)
        host = config.server_hostname or "localhost"
        port = int(config.port)
        peer, extra = nss_tstclnt_host_and_extra_argv(host, port)
        cmd = [self._tstclnt, "-d", self._db_spec(), "-h", peer,
            *self._build_common_args(config, for_server=False)]
        if (has_resumption or has_0rtt) and step == "resume":
            cmd.append("-R")
        cmd.extend(["-p", str(port), *extra, *self._nss_version_args(nss_ver),
            *self._session_ticket_args(config)])
        proc, logs = self._popen_merged_cmd(cmd)
        return proc, logs, "NSS Client connected"

    def _server_transmit_poll(self) -> bool:
        return True

    def _after_session_removed(self, session_id: str) -> None:
        del session_id
        if not self._sessions:
            self._cleanup_nss_db()


def create_servicer() -> NSSWrapper:
    return NSSWrapper()


if __name__ == "__main__":
    serve_insecure(create_servicer, "NSS")

WRAPPER_CLASS = NSSWrapper

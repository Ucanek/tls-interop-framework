"""NSS-backed interop wrapper (``selfserv`` / ``tstclnt``).

The SQLite NSS DB under ``NSSDB`` (default ``wrappers/nss/nssdb/<backend>``) is populated on first gRPC use (not in ``__init__``)
so the wrapper process can bind :50051 before heavy ``pk12util`` imports. Bundles
under ``/app/certs/`` (RSA, ECDSA, Ed25519, Ed448) use distinct nicknames. Set
``INTEROP_GNUTLS_NSS_PAIR`` when the NSS client peers into a Docker
network where symbolic hostnames resolve to RFC 1918 addresses (see README).
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import threading
from pathlib import Path

from core.catalog import(TranslationResult, cipher_catalog_id_requires_anon, cipher_catalog_id_requires_psk,
    cipher_maps_from_capabilities, load_local_capabilities, norm_catalog_token, psk_material_from_capabilities)
from core.identity import repeated_config_tokens
from wrappers.base import(BaseTemplateWrapper,
    format_executed_command, popen_stdio_merged, serve_insecure)
from wrappers.nss.nss_db import(_ensure_nss_db_identities, get_nss_library_version,
    nss_interop_identity_import_rows, nss_server_nickname_for_config, resolve_cli_tool)
from wrappers.utils import(standard_library_metadata, test_feature_enabled_in_config, tls_mode_12_or_13)

CAPABILITIES = load_local_capabilities(__file__)

# Must match deploy/compose.yaml environment wiring.
_GNUTLS_NSS_PAIR_ENV = "INTEROP_GNUTLS_NSS_PAIR"
_TRUTHY_ENV = frozenset({"1", "true", "yes", "on"})


def nss_db_directory(repo: Path, backend_id: str = "nss") -> Path:
    """Per-backend NSS SQL DB path: ``<repo>/src/wrappers/nss/nssdb/<backend_id>`` (or ``/app/wrappers/...`` in images)."""
    from core.catalog import wrappers_plugin_dir

    return wrappers_plugin_dir(repo) / "nss" / "nssdb" / backend_id


def _nss_repo_root(_nssdb_path: str) -> Path:
    """Interop repo root (for ``certs/`` and identity import rows)."""
    from core.catalog import repository_root

    return repository_root()


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

    TLS 1.2 static PSK suites are omitted from NSS ``capabilities.json`` ``tls12``;
    use TLS 1.3 + ``test_features: psk`` for NSS PSK interop.
    """
    if not test_feature_enabled_in_config(config, "psk"):
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


def _build_tls_argv(config, *, role=None, capabilities=None) -> TranslationResult:
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


def tls_argv_for_config(config, *, role=None, capabilities=None) -> TranslationResult:
    return _build_tls_argv(config, role=role, capabilities=capabilities)


def _gnutls_nss_pair_enabled() -> bool:
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


def orchestration_env(active_backends: frozenset[str] | set[str]) -> dict[str, str]:
    """Plugin hook: GnuTLS server × NSS client SNI workaround."""
    if "gnutls" in active_backends and "nss" in active_backends:
        return {"INTEROP_GNUTLS_NSS_PAIR": "1"}
    return {"INTEROP_GNUTLS_NSS_PAIR": "0"}


def local_wrapper_env(repo: Path, backend_id: str, active_backends: frozenset[str] | set[str]) -> dict[str, str]:
    """Plugin hook: per-backend NSS DB directory."""
    del active_backends
    return {"NSSDB": str(nss_db_directory(repo, backend_id))}


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

    def __init__(self) -> None:
        super().__init__()
        from core.catalog import repository_root

        self._nssdb = os.environ.get("NSSDB", str(nss_db_directory(repository_root(), "nss")))
        self._selfserv = resolve_cli_tool("selfserv") or "selfserv"
        self._tstclnt = resolve_cli_tool("tstclnt") or "tstclnt"
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

    def _start_server(self, config):
        self._ensure_nss_db_ready()
        nss_ver = _tls_version_range(config)
        port = int(config.port)
        cwd = os.getcwd()
        cmd = ["stdbuf", "-o0", self._selfserv, "-d", self._db_spec(), "-n", self._nss_server_nickname(config),
            "-p", str(port), "-V", nss_ver, *self._nss_tls_argv(config)]
        if test_feature_enabled_in_config(config, "mtls"):
            cmd.append("-r")
        cmd.extend(["-v", "-v"])
        logs = format_executed_command(cmd, cwd)
        return popen_stdio_merged(cmd, cwd=cwd), logs, "NSS Server started"

    def _start_client(self, config):
        has_resumption = test_feature_enabled_in_config(config, "resumption")
        has_0rtt = test_feature_enabled_in_config(config, "0rtt")
        step = (getattr(config, "resumption_step", None) or "").strip()

        self._ensure_nss_db_ready()
        nss_ver = _tls_version_range(config)
        host = config.server_hostname or "localhost"
        port = int(config.port)
        peer, extra = nss_tstclnt_host_and_extra_argv(host, port)
        cmd = [self._tstclnt, "-d", self._db_spec(), "-h", peer, *self._nss_tls_argv(config), "-o"]
        if (has_resumption or has_0rtt) and step == "resume":
            cmd.append("-R")
        if test_feature_enabled_in_config(config, "mtls"):
            cmd.extend(["-n", "interop_rsa_default"])
        cmd.extend(["-p", str(port), *extra, "-V", nss_ver, *self._session_ticket_args(config)])
        cwd = os.getcwd()
        return (popen_stdio_merged(cmd, cwd=cwd), format_executed_command(cmd, cwd),
            "NSS Client connected")

    def _server_transmit_poll(self) -> bool:
        return True

    def _extra_cleanup(self) -> None:
        super()._extra_cleanup()
        self._cleanup_nss_db()


if __name__ == "__main__":
    serve_insecure(NSSWrapper, "NSS")

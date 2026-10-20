"""NSS-backed interop wrapper (``selfserv`` / ``tstclnt``).

SQLite NSS DB under ``NSSDB`` is populated on first gRPC use so the process can
bind before ``pk12util``. Identity nicknames come from ``certs/`` bundles.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import threading
from pathlib import Path

from core.catalog import (
    BackendCapabilities, TranslationResult, load_local_capabilities,
    norm_catalog_token, repository_root)
from core.features import cipher_catalog_id_requires_anon, cipher_catalog_id_requires_psk
from core.identity import repeated_config_tokens
from interop_proto import interop_pb2
from wrappers.base import BaseTemplateWrapper
from wrappers.nss.nss_db import (
    _ensure_nss_db_identities, get_nss_library_version, nss_interop_identity_import_rows,
    nss_server_nickname_for_config, resolve_cli_tool)
from wrappers.utils import (
    format_executed_command, popen_stdio_merged, resumption_or_0rtt_enabled,
    serve_insecure, standard_library_metadata, test_feature_enabled_in_config,
    tls_mode_12_or_13)

CAPABILITIES = load_local_capabilities(__file__)
_CLIENT_FAIL_MARKERS = (
    "SSL_ERROR_NO_CYPHER_OVERLAP",
    "read from socket failed",
    "Cannot communicate securely with peer",
    "Handshake failed")


def _nss_anon_argv(config) -> list[str]:
    if not test_feature_enabled_in_config(config, "anonymous"):
        return []
    raw_cipher = (getattr(config, "cipher_suite", None) or "").strip()
    if not raw_cipher or not cipher_catalog_id_requires_anon(raw_cipher):
        return []
    key = norm_catalog_token(raw_cipher)
    return ["-H", "2"] if key.startswith("ecdh-anon") else ["-H", "1"]


def _nss_psk_z_argv(config, caps: dict) -> list[str]:
    if not test_feature_enabled_in_config(config, "psk") or tls_mode_12_or_13(config) != "1.3":
        return []
    raw_cipher = (getattr(config, "cipher_suite", None) or "").strip()
    cipher_for_psk = (
        raw_cipher if raw_cipher and cipher_catalog_id_requires_psk(raw_cipher)
        else "psk-aes-128-gcm-sha256")
    mat = BackendCapabilities(caps).psk_material(cipher_for_psk)
    if not mat:
        return []
    identity, secret_hex = mat
    return ["-z", f"0x{secret_hex}:{identity}"]


def _mapped_csv_argv(config, caps: dict, field: str, flag: str) -> tuple[list[str], list[str]]:
    items = repeated_config_tokens(config, field)
    block = caps.get(field)
    if not items or not isinstance(block, dict):
        return [], []
    parts: list[str] = []
    unsupported: list[str] = []
    for it in items:
        k = norm_catalog_token(it)
        v = block.get(k) or block.get(it)
        if not v:
            unsupported.append(f"{field}:{it!r} (unsupported for NSS mapping)")
            continue
        parts.append(str(v))
    return ([flag, ",".join(parts)] if parts else []), unsupported


def tls_argv_for_config(config, *, role=None, capabilities=None) -> TranslationResult:
    del role
    caps = capabilities if capabilities is not None else CAPABILITIES
    argv: list[str] = []
    unsupported: list[str] = []
    mode = tls_mode_12_or_13(config)
    cap13, cap12 = BackendCapabilities(caps).cipher_maps()
    raw_cipher = (getattr(config, "cipher_suite", None) or "").strip()
    if raw_cipher:
        key = norm_catalog_token(raw_cipher)
        cap_sel = cap13 if mode == "1.3" else cap12
        if key in cap_sel:
            argv.extend(["-c", cap_sel[key]])
        else:
            unsupported.append(f"cipher_suite:{raw_cipher!r} (no NSS -c mapping)")
    if mode == "1.3":
        for field, flag in (("supported_groups", "-I"), ("signature_schemes", "-J")):
            extra, bad = _mapped_csv_argv(config, caps, field, flag)
            argv.extend(extra)
            unsupported.extend(bad)
    argv.extend(_nss_anon_argv(config))
    argv.extend(_nss_psk_z_argv(config, caps))
    return TranslationResult(tuple(argv), tuple(unsupported))


def nss_tstclnt_sni_name(hostname: str) -> str:
    """SNI / tstclnt ``-a`` matching generated leaves (``CN=server-node``)."""
    h = (hostname or "").strip()
    if not h or h in ("127.0.0.1", "localhost", "::1"):
        return "server-node"
    if h.startswith("[") and h.endswith("]") and ":" in h[1:-1]:
        return "server-node"
    return h


def nss_tstclnt_host_and_extra_argv(hostname, port) -> tuple[str, list[str]]:
    """``(-h value, extra argv)``. Resolves to IP when GnuTLS×NSS pair env is set."""
    h = hostname or "localhost"
    extra = ["-a", nss_tstclnt_sni_name(h)]
    if os.environ.get("INTEROP_GNUTLS_NSS_PAIR") != "true":
        return h, extra
    try:
        for fam in (socket.AF_INET, socket.AF_INET6):
            infos = socket.getaddrinfo(h, int(port), family=fam, type=socket.SOCK_STREAM)
            if infos:
                return str(infos[0][4][0]), extra
    except OSError:
        pass
    return h, extra


def orchestration_env(active_backends: frozenset[str] | set[str]) -> dict[str, str]:
    if "gnutls" in active_backends and "nss" in active_backends:
        return {"INTEROP_GNUTLS_NSS_PAIR": "true"}
    return {}


def local_wrapper_env(
    repo: Path, backend_id: str, active_backends: frozenset[str] | set[str],
    *, slot_id: int | None = None) -> dict[str, str]:
    del active_backends
    db_id = f"nss_slot{slot_id}" if slot_id is not None else backend_id
    return {"NSSDB": str(repo / "wrappers" / "nss" / "nssdb" / db_id)}


def _tls_version_range(config) -> str:
    v = (getattr(config, "version", None) or "").strip().lower()
    if v in ("1.2", "1.2.0", "tls1.2", "tls1_2"):
        return "tls1.2:tls1.2"
    if v in ("1.3", "1.3.0", "tls1.3", "tls1_3"):
        return "tls1.3:tls1.3"
    return "tls1.2:tls1.3"


class NSSWrapper(BaseTemplateWrapper):
    CAPABILITIES = CAPABILITIES

    def __init__(self) -> None:
        super().__init__()
        self._nssdb = os.environ.get(
            "NSSDB", str(repository_root() / "wrappers" / "nss" / "nssdb" / "nss"))
        self._selfserv = resolve_cli_tool("selfserv") or "selfserv"
        self._tstclnt = resolve_cli_tool("tstclnt") or "tstclnt"
        self._nss_db_ready = False
        self._nss_db_lock = threading.Lock()
        self._pre_transmit_pause_s = 0.0

    def _pre_transmit_pause_seconds(self, role: int) -> float:
        if int(role) != int(interop_pb2.CLIENT):
            return 0.0
        return self._pre_transmit_pause_s

    def _ensure_nss_db_ready(self) -> None:
        if self._nss_db_ready:
            return
        with self._nss_db_lock:
            if self._nss_db_ready:
                return
            _ensure_nss_db_identities(
                self._nssdb, nss_interop_identity_import_rows(repo=repository_root()))
            self._nss_db_ready = True

    def _cleanup_nss_db(self) -> None:
        try:
            shutil.rmtree(os.path.abspath(self._nssdb), ignore_errors=True)
        finally:
            self._nss_db_ready = False

    @property
    def _component_name(self) -> str:
        return "NSS"

    def GetMetadata(self, request, context):
        self._ensure_nss_db_ready()
        return standard_library_metadata(
            self._component_name, get_nss_library_version() or "unknown")

    def _parse_negotiated_params(self, stdout: str) -> dict[str, str]:
        text = stdout or ""
        out: dict[str, str] = {}
        if m := re.search(r"(?:TLS\s+Version|Version)\s*:\s*(\S+)", text, re.IGNORECASE):
            out["protocol_version"] = m.group(1).strip()
        if m := re.search(r"Cipher\s*Suite\s*:\s*(\S+)", text, re.IGNORECASE):
            out["cipher_suite"] = m.group(1).strip()
        if m := re.search(
            r"(?:Negotiated\s+ECC|Named\s+Curve|Group)\s*[:=]\s*(\S+)", text, re.IGNORECASE):
            out["named_group"] = m.group(1).strip()
        return out

    def _client_establish_output_indicates_failure(self, text: str) -> str | None:
        blob = (text or "").strip()
        for marker in _CLIENT_FAIL_MARKERS:
            if marker in blob:
                return marker
        return None

    def _db_spec(self) -> str:
        return f"sql:{os.path.abspath(self._nssdb)}"

    def _start_server(self, config):
        self._ensure_nss_db_ready()
        cwd = os.getcwd()
        cmd = [
            "stdbuf", "-o0", self._selfserv, "-d", self._db_spec(),
            "-n", nss_server_nickname_for_config(config, repo=repository_root()),
            "-p", str(int(config.port)), "-V", _tls_version_range(config),
            *tls_argv_for_config(config).argv]
        if test_feature_enabled_in_config(config, "mtls"):
            cmd.append("-r")
        cmd.extend(["-v", "-v"])
        return (
            popen_stdio_merged(cmd, cwd=cwd), format_executed_command(cmd, cwd),
            "NSS Server started")

    def _start_client(self, config):
        step = (getattr(config, "resumption_step", None) or "").strip()
        resume = resumption_or_0rtt_enabled(config) and step == "resume"
        self._pre_transmit_pause_s = 0.5 if resume else 0.0
        self._ensure_nss_db_ready()
        host = config.server_hostname or "localhost"
        peer, extra = nss_tstclnt_host_and_extra_argv(host, int(config.port))
        cwd = os.getcwd()
        cmd = [
            self._tstclnt, "-d", self._db_spec(), "-h", peer,
            *tls_argv_for_config(config).argv, "-o"]
        if resume:
            cmd.append("-R")
        if test_feature_enabled_in_config(config, "mtls"):
            cmd.extend(["-n", "interop_rsa_default"])
        cmd.extend(["-p", str(int(config.port)), *extra, "-V", _tls_version_range(config)])
        return (
            popen_stdio_merged(cmd, cwd=cwd), format_executed_command(cmd, cwd),
            "NSS Client connected")

    def _server_transmit_poll(self) -> bool:
        return True

    def _extra_cleanup(self) -> None:
        self._pre_transmit_pause_s = 0.0
        super()._extra_cleanup()
        self._cleanup_nss_db()


if __name__ == "__main__":
    serve_insecure(NSSWrapper, "NSS")

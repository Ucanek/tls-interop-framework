"""OpenSSL backend: ``s_server`` / ``s_client``."""

from __future__ import annotations

import os
import re
import subprocess
from typing import Any

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
    catalog_identity_pem_paths_for_prefix,
    cipher_catalog_id_uses_dsa_auth,
    repeated_config_tokens,
)
from wrappers.base import (
    BaseTemplateWrapper,
    WrapperSetupError,
    format_executed_command,
    popen_stdio_merged,
    serve_insecure,
    standard_library_metadata,
    test_feature_enabled_in_config,
    tls_mode_12_or_13,
)

CAPABILITIES = load_local_capabilities(__file__)

_EPHEM_CERT = "/tmp/interop_openssl_cert.pem"
_EPHEM_KEY = "/tmp/interop_openssl_key.pem"

_DNS_LABEL_OK = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_LEGACY_DSS_CIPHER_RE = re.compile(r"dss|dsh", re.IGNORECASE)


def _openssl_cipher_needs_legacy_dss(cipher_suite: str) -> bool:
    """OpenSSL 3 needs legacy provider + SECLEVEL=0 for DHE-DSS / DH-DSS suites."""
    c = norm_catalog_token(cipher_suite)
    if not c:
        return False
    if cipher_catalog_id_uses_dsa_auth(c):
        return True
    return bool(_LEGACY_DSS_CIPHER_RE.search(c.replace("_", "-")))


def _openssl_legacy_provider_argv(config: Any) -> list[str]:
    raw = (getattr(config, "cipher_suite", None) or "").strip()
    if not _openssl_cipher_needs_legacy_dss(raw):
        return []
    return ["-provider", "legacy", "-provider", "default"]


def _append_seclevel_zero(cipher_val: str) -> str:
    if ":@SECLEVEL" in cipher_val:
        return cipher_val
    return f"{cipher_val}:@SECLEVEL=0"


def _is_server_role(role: Any | None) -> bool:
    if role is None:
        return True
    try:
        from proto import interop_pb2

        return int(role) == int(interop_pb2.SERVER)
    except Exception:
        return True


def _build_tls_argv(
    config: Any,
    *,
    role: Any | None = None,
    capabilities: dict[str, Any] | None = None,
) -> TranslationResult:
    caps = capabilities if capabilities is not None else CAPABILITIES
    argv: list[str] = []
    unsupported: list[str] = []
    mode = tls_mode_12_or_13(config)
    cap13, cap12 = cipher_maps_from_capabilities(caps)

    tv = caps.get("tls_version")
    if isinstance(tv, dict):
        flag = tv.get(mode)
        if flag:
            if isinstance(flag, list):
                argv.extend(flag)
            else:
                argv.append(str(flag))

    raw_cipher = (getattr(config, "cipher_suite", None) or "").strip()
    if raw_cipher:
        key = norm_catalog_token(raw_cipher)
        if mode == "1.3":
            if key in cap13:
                argv.extend(["-ciphersuites", cap13[key]])
            else:
                unsupported.append(f"cipher_suite:{raw_cipher!r} (no TLS 1.3 mapping)")
        elif key in cap12:
            cipher_val = cap12[key]
            if test_feature_enabled_in_config(config, "anonymous") and cipher_catalog_id_requires_anon(
                raw_cipher
            ):
                cipher_val = _append_seclevel_zero(cipher_val)
            elif _openssl_cipher_needs_legacy_dss(raw_cipher):
                cipher_val = _append_seclevel_zero(cipher_val)
            argv.extend(["-cipher", cipher_val])
        else:
            unsupported.append(f"cipher_suite:{raw_cipher!r} (no TLS 1.2 mapping)")

    if (
        raw_cipher
        and test_feature_enabled_in_config(config, "psk")
        and cipher_catalog_id_requires_psk(raw_cipher)
    ):
        mat = psk_material_from_capabilities(caps, raw_cipher)
        if mat:
            argv.extend(["-psk_identity", mat[0], "-psk", mat[1]])
        else:
            unsupported.append(
                "psk (missing or wrong-length test_features.psk secret_hex_* for cipher)"
            )

    if mode == "1.3":
        for field, flag in (
            ("supported_groups", "-groups"),
            ("signature_schemes", "-sigalgs"),
        ):
            items = repeated_config_tokens(config, field)
            if not items:
                continue
            block = caps.get(field)
            if not isinstance(block, dict):
                continue
            mapped: list[str] = []
            for it in items:
                k = norm_catalog_token(it)
                v = block.get(k) or block.get(it)
                if not v:
                    unsupported.append(
                        f"{field}:{it!r} (unsupported for openssl mapping)"
                    )
                    continue
                mapped.append(str(v))
            if mapped:
                argv.extend([flag, ":".join(mapped)])

    return TranslationResult(tuple(argv), tuple(unsupported))


def tls_argv_for_config(
    config: Any,
    *,
    role: Any | None = None,
    capabilities: dict[str, Any] | None = None,
) -> TranslationResult:
    return _build_tls_argv(config, role=role, capabilities=capabilities)


def _host_ok_for_sni(hostname: str) -> bool:
    hn = (hostname or "").strip().rstrip(".")
    if not hn or len(hn) > 253:
        return False
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", hn):
        return False
    if hn.startswith("[") and hn.endswith("]"):
        return False
    for label in hn.split("."):
        if not label or not _DNS_LABEL_OK.fullmatch(label):
            return False
    return True


class OpenSSLWrapper(BaseTemplateWrapper):
    CAPABILITIES = CAPABILITIES

    @property
    def _component_name(self) -> str:
        return "OpenSSL"

    @property
    def _ephemeral_pem_paths(self) -> tuple[str, str]:
        return (_EPHEM_CERT, _EPHEM_KEY)

    def _ensure_cert_paths(self, config):
        raw_cipher = str(getattr(config, "cipher_suite", None) or "")
        if _openssl_cipher_needs_legacy_dss(raw_cipher):
            cert, key = catalog_identity_pem_paths_for_prefix("dsa_default")
            if cert and key:
                return cert, key
            cert_b = getattr(config, "certificate", None) or b""
            key_b = getattr(config, "private_key", None) or b""
            if cert_b.strip() and key_b.strip():
                return super()._ensure_cert_paths(config)
            raise WrapperSetupError(
                "DSS cipher requires certs/dsa_default.crt and certs/dsa_default.key "
                "(run scripts/gen_interop_certs.sh)"
            )
        try:
            return super()._ensure_cert_paths(config)
        except WrapperSetupError:
            eph_cert, eph_key = self._ephemeral_pem_paths
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-keyout",
                    eph_key,
                    "-out",
                    eph_cert,
                    "-days",
                    "1",
                    "-nodes",
                    "-subj",
                    "/CN=localhost",
                ],
                check=True,
                capture_output=True,
                timeout=90,
                text=True,
            )
            try:
                os.chmod(eph_key, 0o600)
            except OSError:
                pass
            self._used_ephemeral_pem = True
            return eph_cert, eph_key

    def _version_command(self) -> list[str]:
        return ["openssl", "version"]

    def _build_library_metadata(self, version: str):
        return standard_library_metadata(
            self._component_name, version, capabilities=CAPABILITIES
        )

    def _parse_negotiated_params(self, stdout: str) -> dict[str, str]:
        text = stdout or ""
        out: dict[str, str] = {}
        m = re.search(
            r"New,\s*(TLSv[\d.]+|DTLSv[\d.]+)\s*,\s*Cipher\s+is\s+(\S+)",
            text,
            re.IGNORECASE,
        )
        if m:
            out["protocol_version"] = m.group(1)
            out["cipher_suite"] = m.group(2)
        else:
            m2 = re.search(
                r"(?:Protocol|Version)\s*:\s*(TLSv[\d.]+|TLS\s*[\d.]+|DTLSv[\d.]+)",
                text,
                re.IGNORECASE,
            )
            if m2:
                out["protocol_version"] = m2.group(1).replace(" ", "")
            m3 = re.search(
                r"Cipher\s+(?:is|name)\s*[:=]?\s*(\S+)",
                text,
                re.IGNORECASE,
            )
            if m3:
                out["cipher_suite"] = m3.group(1).strip()
        g = re.search(
            r"(?:Named\s+Group|Negotiated\s+TLS\s+group|Using\s+default\s+temp\s+key\s+parameters\s+name)\s*:\s*(\S+)",
            text,
            re.IGNORECASE,
        ) or re.search(
            r"Server\s+Temp\s+Key:\s*(\S+)",
            text,
            re.IGNORECASE,
        )
        if g:
            out["named_group"] = g.group(1).strip()
        return out

    def _alpn_cli_args(self, config) -> list[str]:
        parts = repeated_config_tokens(config, "alpn_protocols")
        if not parts:
            return []
        return ["-alpn", ",".join(parts)]

    def _build_common_args(self, config, *, for_server: bool) -> list[str]:
        from proto import interop_pb2

        role = interop_pb2.SERVER if for_server else interop_pb2.CLIENT
        args = list(_build_tls_argv(config, role=role).argv)
        if for_server and bool(getattr(config, "session_tickets_enabled", False)):
            args.extend(["-num_tickets", "2"])
        args.extend(self._alpn_cli_args(config))
        return args

    def _client_sni_args(self, config) -> list[str]:
        host = (getattr(config, "server_hostname", None) or "").strip()
        if not _host_ok_for_sni(host):
            return ["-noservername"]
        return ["-servername", host]

    def _start_server(self, config):
        cert_path, key_path = self._ensure_cert_paths(config)
        cmd = (
            ["openssl", "s_server"]
            + _openssl_legacy_provider_argv(config)
            + [
                "-accept",
                f"0.0.0.0:{config.port}",
                "-cert",
                cert_path,
                "-key",
                key_path,
            ]
            + self._build_common_args(config, for_server=True)
        )
        cwd = os.getcwd()
        proc = popen_stdio_merged(cmd, cwd=cwd, env=self._popen_env(config))
        return proc, format_executed_command(cmd, cwd), "Server started"

    def _start_client(self, config):
        host = getattr(config, "server_hostname", None) or "localhost"
        tls_flag_pack = self._build_common_args(config, for_server=False)
        cmd = (
            ["openssl", "s_client"]
            + _openssl_legacy_provider_argv(config)
            + ["-connect", f"{host}:{config.port}"]
            + self._client_sni_args(config)
            + tls_flag_pack
        )
        cwd = os.getcwd()
        proc = popen_stdio_merged(cmd, cwd=cwd, env=self._popen_env(config))
        return proc, format_executed_command(cmd, cwd), "Client connected"


if __name__ == "__main__":
    serve_insecure(OpenSSLWrapper, "OpenSSL")

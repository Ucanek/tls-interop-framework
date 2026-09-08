"""OpenSSL backend: ``s_server`` / ``s_client``."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any

from core.capabilities import (
    TranslationResult,
    cipher_catalog_id_requires_anon,
    cipher_catalog_id_requires_psk,
    cipher_maps_from_capabilities,
    load_local_capabilities,
    psk_material_from_capabilities,
    repository_root,
)
from core.identity import (
    cipher_catalog_id_uses_dsa_auth,
    dsa_cipher_setup_error,
    has_inline_identity_pem,
    repeated_config_tokens,
    resolve_dsa_cipher_cert_paths,
    resolve_server_mtls_cafile,
)
from core.tls_config_view import RoleLike, TlsConfigLike, TlsConfigView
from core.utils import norm_catalog_token
from interop_proto import interop_pb2
from wrappers.base import (
    BaseTemplateWrapper,
    WrapperSessionState,
    WrapperSetupError,
    format_executed_command,
    popen_stdio_merged,
    serve_insecure,
)
from wrappers.utils import (
    alpn_cli_protocol_list,
    standard_library_metadata,
    test_feature_enabled_in_config,
    tls_mode_12_or_13,
)

CAPABILITIES = load_local_capabilities(__file__)

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


def _openssl_legacy_provider_argv(config: TlsConfigLike) -> list[str]:
    raw = TlsConfigView(config).cipher_suite
    if not _openssl_cipher_needs_legacy_dss(raw):
        return []
    return ["-provider", "legacy", "-provider", "default"]


def _append_seclevel_zero(cipher_val: str) -> str:
    if ":@SECLEVEL" in cipher_val:
        return cipher_val
    return f"{cipher_val}:@SECLEVEL=0"


def _openssl_session_state_paths(config: TlsConfigLike) -> tuple[str, str]:
    """Session ticket and 0-RTT payload paths under ``TlsConfig.repo_root`` (or repo root)."""
    raw = TlsConfigView(config).repo_root
    root = Path(raw).resolve() if raw else repository_root()
    return str(root / "session.ticket"), str(root / "early_data.txt")


def _build_tls_argv(
    config: TlsConfigLike,
    *,
    role: RoleLike | None = None,
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

    raw_cipher = TlsConfigView(config).cipher_suite
    if raw_cipher:
        key = norm_catalog_token(raw_cipher)
        if mode == "1.3":
            if key in cap13:
                argv.extend(["-ciphersuites", cap13[key]])
            else:
                unsupported.append(f"cipher_suite:{raw_cipher!r} (no TLS 1.3 mapping)")
        elif key in cap12:
            cipher_val = cap12[key]
            if test_feature_enabled_in_config(
                config, "anonymous"
            ) and cipher_catalog_id_requires_anon(raw_cipher):
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

    @classmethod
    def tls_argv_for_config(
        cls,
        config: Any,
        *,
        role: Any | None = None,
        capabilities: dict[str, Any] | None = None,
    ) -> TranslationResult:
        return _build_tls_argv(config, role=role, capabilities=capabilities)

    @property
    def _component_name(self) -> str:
        return "OpenSSL"

    def _generate_fallback_rsa_identity(
        self, cert_path: str, key_path: str, state: WrapperSessionState
    ) -> tuple[str, str]:
        """One-day RSA leaf when catalog/cwd PEMs are unavailable (ephemeral paths)."""
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_path,
                "-out",
                cert_path,
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
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        state.used_ephemeral_pem = True
        return cert_path, key_path

    def _ensure_cert_paths(
        self, config: interop_pb2.TlsConfig, state: WrapperSessionState
    ):
        raw_cipher = TlsConfigView(config).cipher_suite
        if _openssl_cipher_needs_legacy_dss(raw_cipher):
            dsa = resolve_dsa_cipher_cert_paths(config)
            if dsa:
                return dsa
            if has_inline_identity_pem(config):
                return super()._ensure_cert_paths(config, state)
            raise WrapperSetupError(dsa_cipher_setup_error())
        try:
            return super()._ensure_cert_paths(config, state)
        except WrapperSetupError:
            cert_path, key_path = self._session_ephemeral_pem_paths(state)
            return self._generate_fallback_rsa_identity(cert_path, key_path, state)

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
            out["protocol_version"], out["cipher_suite"] = m.group(1), m.group(2)
        else:
            if m2 := re.search(
                r"(?:Protocol|Version)\s*:\s*(TLSv[\d.]+|TLS\s*[\d.]+|DTLSv[\d.]+)",
                text,
                re.IGNORECASE,
            ):
                out["protocol_version"] = m2.group(1).replace(" ", "")
            if m3 := re.search(
                r"Cipher\s+(?:is|name)\s*[:=]?\s*(\S+)", text, re.IGNORECASE
            ):
                out["cipher_suite"] = m3.group(1).strip()
        g = re.search(
            r"(?:Named\s+Group|Negotiated\s+TLS\s+group|Using\s+default\s+temp\s+key\s+parameters\s+name)\s*:\s*(\S+)",
            text,
            re.IGNORECASE,
        ) or re.search(r"Server\s+Temp\s+Key:\s*(\S+)", text, re.IGNORECASE)
        if g:
            out["named_group"] = g.group(1).strip()
        return out

    def _build_common_args(
        self, config: interop_pb2.TlsConfig, *, for_server: bool
    ) -> list[str]:
        role = interop_pb2.SERVER if for_server else interop_pb2.CLIENT
        args = list(self.tls_argv_for_config(config, role=role).argv)
        cfg = TlsConfigView(config)
        if for_server and cfg.session_tickets_enabled:
            args.extend(["-num_tickets", "2"])
        alpn = alpn_cli_protocol_list(config)
        if alpn:
            args.extend(["-alpn", alpn])
        return args

    def _openssl_state_args(self, config: interop_pb2.TlsConfig) -> list[str]:
        cfg = TlsConfigView(config)
        if tls_mode_12_or_13(config) == "1.3" or cfg.expect_hrr:
            return ["-state"]
        return []

    def _openssl_mtls_server_args(
        self, config: interop_pb2.TlsConfig, cert_path: str
    ) -> list[str]:
        if test_feature_enabled_in_config(config, "mtls"):
            ca_path = resolve_server_mtls_cafile(config, cert_path)
            return ["-Verify", "1", "-CAfile", ca_path]
        return []

    def _openssl_mtls_client_args(
        self, config: interop_pb2.TlsConfig, state: WrapperSessionState
    ) -> list[str]:
        if test_feature_enabled_in_config(config, "mtls"):
            client_cert, client_key = self._ensure_cert_paths(config, state)
            return ["-cert", client_cert, "-key", client_key]
        return []

    def _openssl_client_session_args(self, config: interop_pb2.TlsConfig) -> list[str]:
        has_resumption = test_feature_enabled_in_config(config, "resumption")
        has_0rtt = test_feature_enabled_in_config(config, "0rtt")
        if not has_resumption and not has_0rtt:
            return []
        session_file, early_data_file = _openssl_session_state_paths(config)
        step = TlsConfigView(config).resumption_step
        args: list[str] = []
        if step == "save":
            args.extend(["-sess_out", session_file])
        if step == "resume":
            args.extend(["-sess_in", session_file])
            if has_0rtt:
                Path(early_data_file).write_text("Hello 0-RTT", encoding="ascii")
                args.extend(["-early_data", early_data_file])
        return args

    def _popen_merged_cmd(self, cmd: list[str]) -> tuple[subprocess.Popen[bytes], str]:
        cwd = os.getcwd()
        return popen_stdio_merged(cmd, cwd=cwd), format_executed_command(cmd, cwd)

    def _client_sni_args(self, config: interop_pb2.TlsConfig) -> list[str]:
        host = TlsConfigView(config).server_hostname
        if not _host_ok_for_sni(host):
            return ["-noservername"]
        return ["-servername", host]

    def _start_server(self, config: interop_pb2.TlsConfig, state: WrapperSessionState):
        cert_path, key_path = self._ensure_cert_paths(config, state)
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
        if test_feature_enabled_in_config(config, "0rtt"):
            cmd = list(cmd) + ["-early_data"]
        cmd = (
            list(cmd)
            + self._openssl_mtls_server_args(config, cert_path)
            + self._openssl_state_args(config)
        )
        proc, logs = self._popen_merged_cmd(cmd)
        return proc, logs, "Server started"

    def _start_client(self, config: interop_pb2.TlsConfig, state: WrapperSessionState):
        cfg = TlsConfigView(config)
        host = cfg.server_hostname or "localhost"
        cmd = (
            ["openssl", "s_client"]
            + _openssl_legacy_provider_argv(config)
            + ["-connect", f"{host}:{config.port}"]
            + self._client_sni_args(config)
            + self._build_common_args(config, for_server=False)
        )
        cmd = (
            list(cmd)
            + self._openssl_client_session_args(config)
            + self._openssl_mtls_client_args(config, state)
            + self._openssl_state_args(config)
        )
        proc, logs = self._popen_merged_cmd(cmd)
        return proc, logs, "Client connected"


def create_servicer() -> OpenSSLWrapper:
    return OpenSSLWrapper()


if __name__ == "__main__":
    serve_insecure(create_servicer, "OpenSSL")

WRAPPER_CLASS = OpenSSLWrapper

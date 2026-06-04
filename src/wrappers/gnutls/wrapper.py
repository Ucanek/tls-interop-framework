"""GnuTLS backend: ``gnutls-serv`` / ``gnutls-cli``."""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
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
    catalog_identity_trust_pem_path,
    cipher_catalog_id_uses_dsa_auth,
    repeated_config_tokens,
    server_trust_signature_schemes_tokens,
)
from proto import interop_pb2
from wrappers.base import (
    BaseTemplateWrapper,
    WrapperSetupError,
    format_executed_command,
    popen_stdio_merged,
    serve_insecure,
)
from wrappers.utils import (
    is_server_role,
    standard_library_metadata,
    test_feature_enabled_in_config,
    tls_mode_12_or_13,
)

CAPABILITIES = load_local_capabilities(__file__)

_EPHEM_CERT = "/tmp/interop_gnutls_cert.pem"
_EPHEM_KEY = "/tmp/interop_gnutls_key.pem"
_INTEROP_PSK_PASSWD = "/tmp/interop_gnutls_pskpasswd.txt"


def _gnutls_psk_passwd_file(identity: str, secret_hex: str) -> str:
    """``gnutls-serv`` reads PSK credentials from ``identity:hexkey`` lines."""
    with open(_INTEROP_PSK_PASSWD, "w", encoding="ascii") as f:
        f.write(f"{identity}:{secret_hex}\n")
    return _INTEROP_PSK_PASSWD


def _gnutls_psk_argv(role: Any | None, identity: str, secret_hex: str) -> list[str]:
    if is_server_role(role):
        return ["--pskpasswd", _gnutls_psk_passwd_file(identity, secret_hex)]
    return ["--pskusername", identity, "--pskkey", secret_hex]


def _interop_dhparams_pem() -> str:
    from core.identity import interop_certs_dir

    return str(interop_certs_dir() / "dh2048.pem")


def _profile_key(config: Any, role: Any | None, capabilities: dict[str, Any]) -> str:
    mode = tls_mode_12_or_13(config)
    side = "server" if is_server_role(role) else "client"
    return f"{side}:{mode}"


def _gnutls_join_priority_tokens(
    items: Sequence[str],
    token_map: dict[str, str],
    *,
    reset: str,
    entry_template: str,
    strict: bool,
    unsupported: list[str],
    field: str = "token",
) -> str:
    parts: list[str] = []
    if reset:
        parts.append(reset)
    for raw in items:
        key = norm_catalog_token(raw)
        mapped = token_map.get(key) or token_map.get(raw)
        if not mapped:
            if strict:
                unsupported.append(f"{field}:{raw!r} (unsupported for GnuTLS mapping)")
            continue
        parts.append(entry_template.format(value=mapped))
    if reset:
        return "".join(parts) if len(parts) > 1 else ""
    return "".join(parts)


def _build_tls_argv(
    config: Any,
    *,
    role: Any | None = None,
    capabilities: dict[str, Any] | None = None,
) -> TranslationResult:
    caps = capabilities if capabilities is not None else CAPABILITIES
    argv: list[str] = []
    extras: list[str] = []
    unsupported: list[str] = []
    mode = tls_mode_12_or_13(config)
    cap13, cap12 = cipher_maps_from_capabilities(caps)
    gprio: list[str] = []

    profiles = caps.get("gnutls_priority_base")
    if isinstance(profiles, dict):
        base = profiles.get(_profile_key(config, role, caps))
        if base:
            gprio.append(str(base))

    raw_cipher = (getattr(config, "cipher_suite", None) or "").strip()
    if raw_cipher:
        key = norm_catalog_token(raw_cipher)
        cap_mode = cap13 if mode == "1.3" else cap12
        wrap = ":-CIPHER-ALL:{v}"
        if key in cap_mode:
            gprio.append(wrap.format(v=cap_mode[key]))
        else:
            unsupported.append(
                f"cipher_suite:{raw_cipher!r} (no GnuTLS priority mapping)"
            )

    groups_block = caps.get("supported_groups")
    if isinstance(groups_block, dict) and mode == "1.3":
        items = repeated_config_tokens(config, "supported_groups")
        if items:
            frag = _gnutls_join_priority_tokens(
                items,
                groups_block,
                reset=":-GROUP-ALL",
                entry_template=":+GROUP-{value}",
                strict=True,
                unsupported=unsupported,
                field="supported_groups",
            )
            if frag:
                gprio.append(frag)

    sig_block = caps.get("signature_schemes")
    if isinstance(sig_block, dict) and mode == "1.3":
        items = repeated_config_tokens(config, "signature_schemes")
        if items:
            frag = _gnutls_join_priority_tokens(
                items,
                sig_block,
                reset="",
                entry_template=":+{value}",
                strict=True,
                unsupported=unsupported,
                field="signature_schemes",
            )
            if frag:
                gprio.append(frag)

    if (
        raw_cipher
        and test_feature_enabled_in_config(config, "psk")
        and cipher_catalog_id_requires_psk(raw_cipher)
    ):
        mat = psk_material_from_capabilities(caps, raw_cipher)
        if mat:
            extras.extend(_gnutls_psk_argv(role, mat[0], mat[1]))
        else:
            unsupported.append(
                "psk (missing or wrong-length test_features.psk secret_hex_* for cipher)"
            )

    if (
        raw_cipher
        and test_feature_enabled_in_config(config, "anonymous")
        and cipher_catalog_id_requires_anon(raw_cipher)
        and norm_catalog_token(raw_cipher).startswith("dh-anon")
        and is_server_role(role)
    ):
        extras.extend(["--dhparams", _interop_dhparams_pem()])

    if (
        raw_cipher
        and mode == "1.2"
        and cipher_catalog_id_uses_dsa_auth(raw_cipher)
    ):
        # DHE-DSS / DH-DSS need DSA signature algorithms for the server certificate.
        gprio.append(":+SIGN-DSA-SHA256:+SIGN-DSA-SHA1")

    prio = "".join(gprio)
    argv.extend(extras)
    argv.extend(["--priority", prio])
    return TranslationResult(tuple(argv), tuple(unsupported))


def tls_argv_for_config(
    config: Any,
    *,
    role: Any | None = None,
    capabilities: dict[str, Any] | None = None,
) -> TranslationResult:
    return _build_tls_argv(config, role=role, capabilities=capabilities)


def _split_priority_argv(argv: list[str]) -> tuple[str, list[str]]:
    if len(argv) < 2 or argv[-2] != "--priority":
        return "", argv
    return argv[-1], argv[:-2]


class GnuTLSWrapper(BaseTemplateWrapper):
    CAPABILITIES = CAPABILITIES

    @property
    def _component_name(self) -> str:
        return "GnuTLS"

    @property
    def _ephemeral_pem_paths(self) -> tuple[str, str]:
        return (_EPHEM_CERT, _EPHEM_KEY)

    def _version_command(self) -> list[str]:
        return ["gnutls-cli", "--version"]

    def _build_library_metadata(self, version: str):
        return standard_library_metadata(
            self._component_name, version, capabilities=CAPABILITIES
        )

    def _parse_negotiated_params(self, stdout: str) -> dict[str, str]:
        text = stdout or ""
        out: dict[str, str] = {}
        m = re.search(r"Version:\s*(TLS[\d.]+|DTLS[\d.]+)", text, re.IGNORECASE)
        if m:
            out["protocol_version"] = m.group(1)
        m2 = re.search(
            r"(?:Handshake completed|Simple\s+client\s+mode)\s+.*?(\S+-\S+-\S+)",
            text,
            re.IGNORECASE | re.DOTALL,
        )
        if m2:
            out["cipher_suite"] = m2.group(1).strip()
        m3 = re.search(r"Group:\s*(\S+)", text, re.IGNORECASE)
        if m3:
            out["named_group"] = m3.group(1).strip()
        return out

    def _ensure_cert_paths(self, config):
        raw_cipher = str(getattr(config, "cipher_suite", None) or "")
        if cipher_catalog_id_uses_dsa_auth(raw_cipher):
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
        return super()._ensure_cert_paths(config)

    def _client_x509_cafile(self, config) -> str:
        raw_cipher = str(getattr(config, "cipher_suite", None) or "")
        if cipher_catalog_id_uses_dsa_auth(raw_cipher):
            cert, _ = catalog_identity_pem_paths_for_prefix("dsa_default")
            if cert and os.path.isfile(cert):
                return cert
        trust = catalog_identity_trust_pem_path(
            server_trust_signature_schemes_tokens(config)
        )
        if trust and os.path.isfile(trust):
            return trust
        for candidate in (os.path.join(os.getcwd(), "cert.pem"), "cert.pem"):
            if candidate and os.path.isfile(candidate):
                return candidate
        return "cert.pem"

    def _start_server(self, config):
        cert_path, key_path = self._ensure_cert_paths(config)
        prio, mid = _split_priority_argv(
            list(_build_tls_argv(config, role=interop_pb2.SERVER).argv)
        )
        if not prio:
            raise RuntimeError("empty GnuTLS priority string")
        client_cert_flag = (
            "--require-client-cert"
            if test_feature_enabled_in_config(config, "mtls")
            else "--disable-client-cert"
        )
        cmd = [
            "gnutls-serv",
            "-p",
            str(config.port),
            "--x509certfile",
            cert_path,
            "--x509keyfile",
            key_path,
            client_cert_flag,
            *mid,
            "--priority",
            prio,
            "-q",
            "--echo",
        ]
        cwd = os.getcwd()
        proc = popen_stdio_merged(cmd, cwd=cwd, env=self._popen_env(config))
        return proc, format_executed_command(cmd, cwd), "GnuTLS Server started"

    def _start_client(self, config):
        host = config.server_hostname or "localhost"
        prio, mid = _split_priority_argv(
            list(_build_tls_argv(config, role=interop_pb2.CLIENT).argv)
        )
        if not prio:
            raise RuntimeError("empty GnuTLS priority string")
        cmd = [
            "gnutls-cli",
            "-p",
            str(config.port),
            "--disable-sni",
            "--insecure",
            "--x509cafile",
            self._client_x509_cafile(config),
            *mid,
            "--priority",
            prio,
        ]
        if test_feature_enabled_in_config(config, "mtls"):
            client_cert, client_key = self._ensure_cert_paths(config)
            cmd.extend(["--x509certfile", client_cert, "--x509keyfile", client_key])
        cmd.append(host)
        cwd = os.getcwd()
        proc = popen_stdio_merged(cmd, cwd=cwd, env=self._popen_env(config))
        return proc, format_executed_command(cmd, cwd), "GnuTLS Client connected"

    def _server_transmit_poll(self) -> bool:
        return True


if __name__ == "__main__":
    serve_insecure(GnuTLSWrapper, "GnuTLS")

"""OpenSSL backend: ``s_server`` / ``s_client``."""

from __future__ import annotations

import os
import re
from pathlib import Path

from core.catalog import (
    BackendCapabilities, TranslationResult, cipher_catalog_id_requires_anon,
    cipher_catalog_id_requires_psk, load_local_capabilities, norm_catalog_token,
    repository_root)
from core.identity import (
    catalog_identity_pem_paths_for_prefix, cipher_catalog_id_uses_dsa_auth,
    get_cert_prefix_for_schemes, repeated_config_tokens,
    server_trust_signature_schemes_tokens)
from wrappers.base import BaseTemplateWrapper, WrapperSetupError
from wrappers.utils import (
    alpn_cli_protocol_list, format_executed_command, interop_staging_pem_paths,
    popen_stdio_merged, serve_insecure, test_feature_enabled_in_config,
    tls_mode_12_or_13)

CAPABILITIES = load_local_capabilities(__file__)
_DNS_LABEL_OK = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _openssl_cipher_needs_legacy_dss(cipher_suite: str) -> bool:
    """OpenSSL 3 needs legacy provider + SECLEVEL=0 for DHE-DSS / DH-DSS."""
    c = norm_catalog_token(cipher_suite)
    return bool(c) and cipher_catalog_id_uses_dsa_auth(c)


def _openssl_legacy_provider_argv(config) -> list[str]:
    raw = (getattr(config, "cipher_suite", None) or "").strip()
    if not _openssl_cipher_needs_legacy_dss(raw):
        return []
    return ["-provider", "legacy", "-provider", "default"]


def _append_seclevel_zero(cipher_val: str) -> str:
    if ":@SECLEVEL" in cipher_val:
        return cipher_val
    return f"{cipher_val}:@SECLEVEL=0"


def _openssl_session_state_paths(config) -> tuple[str, str]:
    raw = (getattr(config, "repo_root", None) or "").strip()
    root = Path(raw).resolve() if raw else repository_root()
    return str(root / "session.ticket"), str(root / "early_data.txt")


def _tls_version_argv(caps: dict, mode: str) -> list[str]:
    tv = caps.get("tls_version")
    if not isinstance(tv, dict):
        return []
    flag = tv.get(mode)
    if isinstance(flag, list):
        return list(flag)
    return [str(flag)] if flag else []


def _cipher_argv(
    config, raw_cipher: str, mode: str, cap13: dict, cap12: dict,
    unsupported: list[str]) -> list[str]:
    if not raw_cipher:
        return []
    key = norm_catalog_token(raw_cipher)
    if mode == "1.3":
        if key in cap13:
            return ["-ciphersuites", cap13[key]]
        unsupported.append(f"cipher_suite:{raw_cipher!r} (no TLS 1.3 mapping)")
        return []
    if key not in cap12:
        unsupported.append(f"cipher_suite:{raw_cipher!r} (no TLS 1.2 mapping)")
        return []
    cipher_val = cap12[key]
    anon = (test_feature_enabled_in_config(config, "anonymous")
            and cipher_catalog_id_requires_anon(raw_cipher))
    if anon or _openssl_cipher_needs_legacy_dss(raw_cipher):
        cipher_val = _append_seclevel_zero(cipher_val)
    return ["-cipher", cipher_val]


def _psk_argv(config, caps: dict, raw_cipher: str, unsupported: list[str]) -> list[str]:
    if not (raw_cipher and test_feature_enabled_in_config(config, "psk")
            and cipher_catalog_id_requires_psk(raw_cipher)):
        return []
    mat = BackendCapabilities(caps).psk_material(raw_cipher)
    if mat:
        return ["-psk_identity", mat[0], "-psk", mat[1]]
    unsupported.append(
        "psk (missing or wrong-length test_features.psk secret_hex_* for cipher)")
    return []


def _mapped_colon_argv(config, caps: dict, field: str, flag: str) -> tuple[list[str], list[str]]:
    items = repeated_config_tokens(config, field)
    block = caps.get(field)
    if not items or not isinstance(block, dict):
        return [], []
    mapped: list[str] = []
    unsupported: list[str] = []
    for it in items:
        v = block.get(norm_catalog_token(it)) or block.get(it)
        if not v:
            unsupported.append(f"{field}:{it!r} (unsupported for openssl mapping)")
            continue
        mapped.append(str(v))
    return ([flag, ":".join(mapped)] if mapped else []), unsupported


def tls_argv_for_config(config, *, role=None, capabilities=None) -> TranslationResult:
    del role
    caps = capabilities if capabilities is not None else CAPABILITIES
    unsupported: list[str] = []
    mode = tls_mode_12_or_13(config)
    cap13, cap12 = BackendCapabilities(caps).cipher_maps()
    raw_cipher = (getattr(config, "cipher_suite", None) or "").strip()
    argv = _tls_version_argv(caps, mode)
    argv.extend(_cipher_argv(config, raw_cipher, mode, cap13, cap12, unsupported))
    argv.extend(_psk_argv(config, caps, raw_cipher, unsupported))
    if mode == "1.3":
        for field, flag in (("supported_groups", "-groups"), ("signature_schemes", "-sigalgs")):
            extra, bad = _mapped_colon_argv(config, caps, field, flag)
            argv.extend(extra)
            unsupported.extend(bad)
    return TranslationResult(tuple(argv), tuple(unsupported))


def _host_ok_for_sni(hostname: str) -> bool:
    hn = (hostname or "").strip().rstrip(".")
    if not hn or len(hn) > 253:
        return False
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", hn) or (hn.startswith("[") and hn.endswith("]")):
        return False
    return all(label and _DNS_LABEL_OK.fullmatch(label) for label in hn.split("."))


def _state_debug_argv(config) -> list[str]:
    if tls_mode_12_or_13(config) == "1.3" or getattr(config, "expect_hrr", False):
        return ["-state"]
    return []


class OpenSSLWrapper(BaseTemplateWrapper):
    CAPABILITIES = CAPABILITIES

    @property
    def _component_name(self) -> str:
        return "OpenSSL"

    @property
    def _ephemeral_pem_paths(self) -> tuple[str, str]:
        return interop_staging_pem_paths("openssl")

    def _ensure_cert_paths(self, config):
        raw_cipher = str(getattr(config, "cipher_suite", None) or "")
        if not _openssl_cipher_needs_legacy_dss(raw_cipher):
            return super()._ensure_cert_paths(config)
        cert, key = catalog_identity_pem_paths_for_prefix("dsa_default")
        if cert and key:
            return cert, key
        cert_b = getattr(config, "certificate", None) or b""
        key_b = getattr(config, "private_key", None) or b""
        if cert_b.strip() and key_b.strip():
            return super()._ensure_cert_paths(config)
        raise WrapperSetupError(
            "DSS cipher requires certs/dsa_default.crt and certs/dsa_default.key "
            "(run core/gen_interop_certs.sh)")

    def _version_command(self) -> list[str]:
        return ["openssl", "version"]

    def _parse_negotiated_params(self, stdout: str) -> dict[str, str]:
        text = stdout or ""
        out: dict[str, str] = {}
        if m := re.search(
            r"New,\s*(TLSv[\d.]+|DTLSv[\d.]+)\s*,\s*Cipher\s+is\s+(\S+)",
            text, re.IGNORECASE):
            out["protocol_version"], out["cipher_suite"] = m.group(1), m.group(2)
        else:
            if m := re.search(
                r"(?:Protocol|Version)\s*:\s*(TLSv[\d.]+|TLS\s*[\d.]+|DTLSv[\d.]+)",
                text, re.IGNORECASE):
                out["protocol_version"] = m.group(1).replace(" ", "")
            if m := re.search(r"Cipher\s+(?:is|name)\s*[:=]?\s*(\S+)", text, re.IGNORECASE):
                out["cipher_suite"] = m.group(1).strip()
        g = re.search(
            r"(?:Named\s+Group|Negotiated\s+TLS\s+group|"
            r"Using\s+default\s+temp\s+key\s+parameters\s+name)\s*:\s*(\S+)",
            text, re.IGNORECASE) or re.search(r"Server\s+Temp\s+Key:\s*(\S+)", text, re.IGNORECASE)
        if g:
            out["named_group"] = g.group(1).strip()
        return out

    def _common_args(self, config) -> list[str]:
        args = list(tls_argv_for_config(config).argv)
        if alpn := alpn_cli_protocol_list(config):
            args.extend(["-alpn", alpn])
        return args

    def _client_sni_args(self, config) -> list[str]:
        host = (getattr(config, "server_hostname", None) or "").strip()
        if not _host_ok_for_sni(host):
            return ["-noservername"]
        return ["-servername", host]

    def _client_session_argv(self, config) -> list[str]:
        has_ticket = (test_feature_enabled_in_config(config, "resumption")
                      or test_feature_enabled_in_config(config, "0rtt"))
        if not has_ticket:
            return []
        session_file, early_data_file = _openssl_session_state_paths(config)
        step = (getattr(config, "resumption_step", "") or "").strip()
        extra: list[str] = []
        if step == "save":
            extra.extend(["-sess_out", session_file])
        if step == "resume":
            extra.extend(["-sess_in", session_file])
            if test_feature_enabled_in_config(config, "0rtt"):
                Path(early_data_file).write_text("Hello 0-RTT", encoding="ascii")
                extra.extend(["-early_data", early_data_file])
        return extra

    def _start_server(self, config):
        cert_path, key_path = self._ensure_cert_paths(config)
        cwd = os.getcwd()
        cmd = [
            "openssl", "s_server", *_openssl_legacy_provider_argv(config),
            "-accept", f"0.0.0.0:{config.port}", "-cert", cert_path, "-key", key_path,
            *self._common_args(config)]
        if test_feature_enabled_in_config(config, "0rtt"):
            cmd.append("-early_data")
        if test_feature_enabled_in_config(config, "mtls"):
            ca_path, _ = catalog_identity_pem_paths_for_prefix(
                get_cert_prefix_for_schemes(server_trust_signature_schemes_tokens(config)))
            if not ca_path or not os.path.isfile(ca_path):
                ca_path = cert_path
            cmd.extend(["-Verify", "1", "-CAfile", ca_path])
        cmd.extend(_state_debug_argv(config))
        return (
            popen_stdio_merged(cmd, cwd=cwd), format_executed_command(cmd, cwd), "Server started")

    def _start_client(self, config):
        host = getattr(config, "server_hostname", None) or "localhost"
        cwd = os.getcwd()
        cmd = [
            "openssl", "s_client", *_openssl_legacy_provider_argv(config),
            "-connect", f"{host}:{config.port}", *self._client_sni_args(config),
            *self._common_args(config), *self._client_session_argv(config)]
        if test_feature_enabled_in_config(config, "mtls"):
            client_cert, client_key = self._ensure_cert_paths(config)
            cmd.extend(["-cert", client_cert, "-key", client_key])
        cmd.extend(_state_debug_argv(config))
        return (
            popen_stdio_merged(cmd, cwd=cwd), format_executed_command(cmd, cwd),
            "Client connected")


if __name__ == "__main__":
    serve_insecure(OpenSSLWrapper, "OpenSSL")

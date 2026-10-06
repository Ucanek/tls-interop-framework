"""GnuTLS backend: ``gnutls-serv`` / ``gnutls-cli``."""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from pathlib import Path

from core.catalog import (
    BackendCapabilities, TranslationResult, load_local_capabilities,
    norm_catalog_token, repository_root)
from core.features import cipher_catalog_id_requires_anon, cipher_catalog_id_requires_psk
from core.identity import (
    catalog_identity_pem_paths_for_prefix, cipher_catalog_id_uses_dsa_auth,
    get_cert_prefix_for_schemes, repeated_config_tokens, server_trust_signature_schemes_tokens)
from interop_proto import interop_pb2
from wrappers.base import BaseTemplateWrapper, WrapperSetupError
from wrappers.utils import (
    alpn_cli_protocol_list, format_executed_command, interop_staging_pem_paths,
    interop_staging_sidecar_path, is_server_role, popen_stdio_merged,
    resumption_or_0rtt_enabled, serve_insecure, test_feature_enabled_in_config,
    tls_mode_12_or_13, tls_session_state_paths, write_early_data_file)

CAPABILITIES = load_local_capabilities(__file__)
_HOOK_SO = Path(__file__).resolve().parent / "gnutls_session_hook.so"


def _gnutls_popen_env(*, session_env: dict[str, str]) -> dict[str, str]:
    env = dict(os.environ)
    env.update(session_env)
    if _HOOK_SO.is_file():
        prev = env.get("LD_PRELOAD", "")
        env["LD_PRELOAD"] = str(_HOOK_SO) if not prev else f"{_HOOK_SO}{os.pathsep}{prev}"
    return env


def _gnutls_psk_passwd_file(identity: str, secret_hex: str) -> str:
    path = interop_staging_sidecar_path("gnutls", "pskpasswd.txt")
    with open(path, "w", encoding="ascii") as f:
        f.write(f"{identity}:{secret_hex}\n")
    return path


def _gnutls_psk_argv(role, identity: str, secret_hex: str) -> list[str]:
    if is_server_role(role):
        return ["--pskpasswd", _gnutls_psk_passwd_file(identity, secret_hex)]
    return ["--pskusername", identity, "--pskkey", secret_hex]


def _gnutls_join_priority_tokens(
    items: Sequence[str], token_map: dict[str, str], *,
    reset: str, entry_template: str, unsupported: list[str], field: str) -> str:
    parts: list[str] = [reset] if reset else []
    for raw in items:
        mapped = token_map.get(norm_catalog_token(raw)) or token_map.get(raw)
        if not mapped:
            unsupported.append(f"{field}:{raw!r} (unsupported for GnuTLS mapping)")
            continue
        parts.append(entry_template.format(value=mapped))
    if reset and len(parts) < 2:
        return ""
    return "".join(parts)


def _priority_frags_13(config, caps: dict, unsupported: list[str]) -> list[str]:
    out: list[str] = []
    for field, reset, template in (
        ("supported_groups", ":-GROUP-ALL", ":+GROUP-{value}"),
        ("signature_schemes", "", ":+{value}")):
        block = caps.get(field)
        items = repeated_config_tokens(config, field)
        if not isinstance(block, dict) or not items:
            continue
        frag = _gnutls_join_priority_tokens(
            items, block, reset=reset, entry_template=template,
            unsupported=unsupported, field=field)
        if frag:
            out.append(frag)
    return out


def _cipher_priority_token(
    raw_cipher: str, mode: str, cap13: dict, cap12: dict, unsupported: list[str]) -> str:
    if not raw_cipher:
        return ""
    key = norm_catalog_token(raw_cipher)
    cap_mode = cap13 if mode == "1.3" else cap12
    if key in cap_mode:
        return f":-CIPHER-ALL:{cap_mode[key]}"
    unsupported.append(f"cipher_suite:{raw_cipher!r} (no GnuTLS priority mapping)")
    return ""


def _psk_and_anon_extras(
    config, role, caps: dict, raw_cipher: str, unsupported: list[str]) -> list[str]:
    extras: list[str] = []
    if (raw_cipher and test_feature_enabled_in_config(config, "psk")
            and cipher_catalog_id_requires_psk(raw_cipher)):
        mat = BackendCapabilities(caps).psk_material(raw_cipher)
        if mat:
            extras.extend(_gnutls_psk_argv(role, mat[0], mat[1]))
        else:
            unsupported.append(
                "psk (missing or wrong-length test_features.psk secret_hex_* for cipher)")
    if (raw_cipher and test_feature_enabled_in_config(config, "anonymous")
            and cipher_catalog_id_requires_anon(raw_cipher)
            and norm_catalog_token(raw_cipher).startswith("dh-anon")
            and is_server_role(role)):
        extras.extend(["--dhparams", str(repository_root() / "certs" / "dh2048.pem")])
    return extras


def _gnutls_priority_parts(
    config, role, caps: dict, mode: str, raw_cipher: str, cap13: dict, cap12: dict,
    unsupported: list[str]) -> list[str]:
    gprio: list[str] = []
    profiles = caps.get("gnutls_priority_base")
    if isinstance(profiles, dict):
        side = "server" if is_server_role(role) else "client"
        base = profiles.get(f"{side}:{mode}")
        if base:
            gprio.append(str(base))
    if token := _cipher_priority_token(raw_cipher, mode, cap13, cap12, unsupported):
        gprio.append(token)
    if mode == "1.3":
        gprio.extend(_priority_frags_13(config, caps, unsupported))
    if raw_cipher and mode == "1.2" and cipher_catalog_id_uses_dsa_auth(raw_cipher):
        gprio.append(":+SIGN-DSA-SHA256:+SIGN-DSA-SHA1")
    return gprio


def tls_argv_for_config(config, *, role=None, capabilities=None) -> TranslationResult:
    caps = capabilities if capabilities is not None else CAPABILITIES
    unsupported: list[str] = []
    mode = tls_mode_12_or_13(config)
    cap13, cap12 = BackendCapabilities(caps).cipher_maps()
    raw_cipher = (getattr(config, "cipher_suite", None) or "").strip()
    extras = _psk_and_anon_extras(config, role, caps, raw_cipher, unsupported)
    prio = "".join(_gnutls_priority_parts(
        config, role, caps, mode, raw_cipher, cap13, cap12, unsupported))
    extras.extend(["--priority", prio])
    return TranslationResult(tuple(extras), tuple(unsupported))


def _priority_and_mid(config, role) -> tuple[str, list[str]]:
    argv = list(tls_argv_for_config(config, role=role).argv)
    if len(argv) >= 2 and argv[-2] == "--priority":
        prio, mid = argv[-1], argv[:-2]
    else:
        prio, mid = "", argv
    if not prio:
        raise RuntimeError("empty GnuTLS priority string")
    return prio, mid


class GnuTLSWrapper(BaseTemplateWrapper):
    CAPABILITIES = CAPABILITIES

    @property
    def _component_name(self) -> str:
        return "GnuTLS"

    @property
    def _ephemeral_pem_paths(self) -> tuple[str, str]:
        return interop_staging_pem_paths("gnutls")

    def _version_command(self) -> list[str]:
        return ["gnutls-cli", "--version"]

    def _parse_negotiated_params(self, stdout: str) -> dict[str, str]:
        text = stdout or ""
        out: dict[str, str] = {}
        if m := re.search(r"Version:\s*(TLS[\d.]+|DTLS[\d.]+)", text, re.IGNORECASE):
            out["protocol_version"] = m.group(1)
        if m := re.search(
            r"(?:Handshake completed|Simple\s+client\s+mode)\s+.*?(\S+-\S+-\S+)",
            text, re.IGNORECASE | re.DOTALL):
            out["cipher_suite"] = m.group(1).strip()
        if m := re.search(r"Group:\s*(\S+)", text, re.IGNORECASE):
            out["named_group"] = m.group(1).strip()
        if m := re.search(r"Description:\s*\([^)]+\)-\(([^)]+)\)-", text, re.IGNORECASE):
            out["named_group"] = m.group(1).strip()
        return out

    def _infer_hrr_from_negotiation(self, config: interop_pb2.TlsConfig, text: str) -> bool:
        """gnutls-cli does not log HRR; infer from ``--single-key-share`` + negotiated group."""
        if not getattr(config, "expect_hrr", False):
            return False
        if "--single-key-share" not in (self._last_client_cmd or ""):
            return False
        m = re.search(r"Description:\s*\([^)]+\)-\(([^)]+)\)-", text or "", re.IGNORECASE)
        groups = repeated_config_tokens(config, "supported_groups")
        if not m or len(groups) < 2:
            return False
        negotiated = m.group(1).lower().replace("-", "")
        first = groups[0].lower().replace("-", "")
        if first in negotiated:
            return False
        return any(g.lower().replace("-", "") in negotiated for g in groups[1:])

    def _client_x509_cafile(self, config) -> str:
        raw_cipher = str(getattr(config, "cipher_suite", None) or "")
        if cipher_catalog_id_uses_dsa_auth(raw_cipher):
            cert, _ = catalog_identity_pem_paths_for_prefix("dsa_default")
            if cert and os.path.isfile(cert):
                return cert
        trust, _ = catalog_identity_pem_paths_for_prefix(
            get_cert_prefix_for_schemes(server_trust_signature_schemes_tokens(config)))
        if trust and os.path.isfile(trust):
            return trust
        raise WrapperSetupError(
            "No trust PEM under certs/ for this client (run core/gen_interop_certs.sh)")

    def _client_session_bits(self, config) -> tuple[list[str], dict[str, str]]:
        if not resumption_or_0rtt_enabled(config):
            return [], {}
        session_file, _ = tls_session_state_paths(config)
        step = (getattr(config, "resumption_step", None) or "").strip()
        extra: list[str] = []
        env: dict[str, str] = {}
        if step == "save":
            extra.extend(["--resume", "--waitresumption"])
            env["GNUTLS_INTEROP_SESSION_OUT"] = session_file
        if step == "resume":
            env["GNUTLS_INTEROP_SESSION_IN"] = session_file
            if test_feature_enabled_in_config(config, "0rtt"):
                extra.extend(["--earlydata", write_early_data_file(config)])
        return extra, env

    def _start_server(self, config):
        cert_path, key_path = self._ensure_cert_paths(config)
        prio, mid = _priority_and_mid(config, interop_pb2.SERVER)
        mtls = test_feature_enabled_in_config(config, "mtls")
        cwd = os.getcwd()
        cmd = [
            "gnutls-serv", "-p", str(config.port),
            "--x509certfile", cert_path, "--x509keyfile", key_path,
            "--require-client-cert" if mtls else "--disable-client-cert",
            *mid, "--priority", prio, "-q", "--echo"]
        if test_feature_enabled_in_config(config, "0rtt"):
            cmd.append("--earlydata")
        if alpn := alpn_cli_protocol_list(config):
            cmd.extend(["--alpn", alpn])
        return (
            popen_stdio_merged(cmd, cwd=cwd), format_executed_command(cmd, cwd),
            "GnuTLS Server started")

    def _start_client(self, config):
        prio, mid = _priority_and_mid(config, interop_pb2.CLIENT)
        session_extra, session_env = self._client_session_bits(config)
        cwd = os.getcwd()
        cmd = [
            "gnutls-cli", "-p", str(config.port), "--disable-sni", "--insecure",
            "--x509cafile", self._client_x509_cafile(config),
            *mid, "--priority", prio, *session_extra]
        if test_feature_enabled_in_config(config, "mtls"):
            client_cert, client_key = self._ensure_cert_paths(config)
            cmd.extend(["--x509certfile", client_cert, "--x509keyfile", client_key])
        if alpn := alpn_cli_protocol_list(config):
            cmd.extend(["--alpn", alpn])
        if getattr(config, "expect_hrr", False):
            cmd.append("--single-key-share")
        cmd.append(config.server_hostname or "localhost")
        return (
            popen_stdio_merged(cmd, cwd=cwd, env=_gnutls_popen_env(session_env=session_env)),
            format_executed_command(cmd, cwd), "GnuTLS Client connected")

    def _server_transmit_poll(self) -> bool:
        return True


if __name__ == "__main__":
    serve_insecure(GnuTLSWrapper, "GnuTLS")

"""TLS identity PEM paths and signature-scheme → certificate mapping."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

from core.orchestration_context import active_orchestration_context

from core.tls_config_view import RoleLike, TlsConfigInput, TlsConfigLike, TlsConfigView
from core.utils import norm_scheme_token, split_asymmetric_csv

# Catalog prefixes under ``certs/`` (``{prefix}.crt`` + ``{prefix}.key``).
IDENTITY_PREFIXES: tuple[str, ...] = ("rsa_default", "rsa_pss_pure", "dsa_default", "ecdsa_p256",
    "ecdsa_p384", "ecdsa_p521", "ed25519", "ed448")

_DEFAULT_PREFIX = "rsa_default"


def cipher_catalog_id_uses_dsa_auth(cipher_catalog_id: str) -> bool:
    """True for ``dhe-dss-*``, ``dh-dss-*``, … (not ECDSA)."""
    c = (cipher_catalog_id or "").strip().lower().replace("_", "-")
    return bool(re.search(r"(^|-)dss(-|$)", c))


def get_cert_prefix_for_scheme(scheme: str) -> str:
    """
    Map a catalog ``signature_schemes`` id to a ``certs/`` filename prefix.

    Examples:
      ``rsa-pkcs1-sha256`` → ``rsa_default``
      ``rsa-pss-pss-sha256`` → ``rsa_pss_pure``
      ``ecdsa-secp384r1-sha384`` → ``ecdsa_p384``
    """
    tok = norm_scheme_token(scheme)
    if not tok:
        return _DEFAULT_PREFIX
    if tok.startswith("ed25519") or tok == "ed25519":
        return "ed25519"
    if tok.startswith("ed448") or tok == "ed448":
        return "ed448"
    if tok.startswith("dsa") or tok == "dsa":
        return "dsa_default"
    if "ecdsa" in tok:
        if "secp521" in tok or "-p521" in tok or tok.endswith("p521"):
            return "ecdsa_p521"
        if "secp384" in tok or "p384" in tok or "384" in tok:
            return "ecdsa_p384"
        return "ecdsa_p256"
    if "rsa-pss-pss" in tok or "rsapss-pss" in tok.replace("-", ""):
        return "rsa_pss_pure"
    if tok.startswith("rsa") or "rsa" in tok:
        return "rsa_default"
    return _DEFAULT_PREFIX


def get_cert_prefix_for_schemes(schemes: Sequence[str]) -> str:
    """First listed scheme wins (TLS signature_algorithms preference order)."""
    for raw in schemes:
        if (raw or "").strip():
            return get_cert_prefix_for_scheme(raw)
    return _DEFAULT_PREFIX


def get_cert_prefix_for_cipher_suite(cipher_catalog_id: str) -> str:
    """Coarse fallback when ``signature_schemes`` is unset (cipher auth hint only)."""
    c = (cipher_catalog_id or "").strip().lower()
    if not c:
        return _DEFAULT_PREFIX
    if cipher_catalog_id_uses_dsa_auth(c):
        return "dsa_default"
    if "ecdsa" in c:
        return "ecdsa_p256"
    if "ed25519" in c:
        return "ed25519"
    if "ed448" in c:
        return "ed448"
    if "rsa" in c:
        return "rsa_default"
    return _DEFAULT_PREFIX


def get_cert_prefix_for_config(config: TlsConfigLike) -> str:
    """Resolve prefix from ``signature_schemes``, else ``cipher_suite`` on ``config``."""
    schemes = repeated_config_tokens(config, "signature_schemes")
    if schemes:
        return get_cert_prefix_for_schemes(schemes)
    return get_cert_prefix_for_cipher_suite(TlsConfigView(config).cipher_suite)


def interop_certs_dir(repo: Path | None = None) -> Path:
    if repo is not None:
        return repo / "certs"
    from core.registry import repository_root

    return repository_root() / "certs"


def identity_pem_present(prefix: str, *, repo: Path | None = None) -> bool:
    """True when both ``certs/{prefix}.crt`` and ``certs/{prefix}.key`` exist."""
    cert_path, key_path = catalog_identity_pem_paths_for_prefix(prefix, repo=repo)
    return bool(cert_path and key_path)


def catalog_identity_pem_paths_for_prefix(prefix: str, *, repo: Path | None = None) -> tuple[str, str]:
    """Return absolute paths to ``{prefix}.crt`` and ``{prefix}.key`` when present."""
    p = (prefix or "").strip() or _DEFAULT_PREFIX
    cert_name = f"{p}.crt"
    key_name = f"{p}.key"
    candidates_dirs = ([interop_certs_dir(repo)] if repo is not None else []) + [interop_certs_dir(None)]

    cert = ""
    key = ""
    for base in candidates_dirs:
        c = base / cert_name
        k = base / key_name
        if c.is_file() and k.is_file():
            return str(c.resolve()), str(k.resolve())
        if not cert and c.is_file():
            cert = str(c.resolve())
        if not key and k.is_file():
            key = str(k.resolve())
    if cert and key:
        return cert, key
    return "", ""


def read_identity_pem_bytes(prefix: str, *, repo: Path | None = None) -> tuple[bytes, bytes]:
    cert_path, key_path = catalog_identity_pem_paths_for_prefix(prefix, repo=repo)
    if not cert_path or not key_path:
        return b"", b""
    return Path(cert_path).read_bytes(), Path(key_path).read_bytes()


def repeated_config_tokens(config: TlsConfigLike, field: str) -> list[str]:
    return TlsConfigView(config).list_field(field)


def identity_kind_from_signature_schemes(schemes: Sequence[str]) -> str:
    """Legacy coarse kind (``rsa`` | ``ecdsa`` | ``ed25519`` | ``ed448``)."""
    prefix = get_cert_prefix_for_schemes(schemes)
    if prefix == "dsa_default" or prefix.startswith("dsa"):
        return "dsa"
    if prefix.startswith("ecdsa"):
        return "ecdsa"
    if prefix == "ed25519":
        return "ed25519"
    if prefix == "ed448":
        return "ed448"
    return "rsa"


def identity_kind_from_cipher_suite(cipher_catalog_id: str) -> str | None:
    prefix = get_cert_prefix_for_cipher_suite(cipher_catalog_id)
    if prefix == "dsa_default" or prefix.startswith("dsa"):
        return "dsa"
    if prefix.startswith("ecdsa"):
        return "ecdsa"
    if prefix == "ed25519":
        return "ed25519"
    if prefix == "ed448":
        return "ed448"
    if prefix.startswith("rsa"):
        return "rsa"
    return None


def resolve_identity_kind(config: TlsConfigLike) -> str:
    return (identity_kind_from_signature_schemes(repeated_config_tokens(config, "signature_schemes"))
        or identity_kind_from_cipher_suite(TlsConfigView(config).cipher_suite) or "rsa")


def catalog_identity_pem_paths_for_config(config: TlsConfigLike) -> tuple[str, str]:
    return catalog_identity_pem_paths_for_prefix(get_cert_prefix_for_config(config))


def catalog_identity_trust_pem_path(schemes: Sequence[str]) -> str:
    cert, _ = catalog_identity_pem_paths_for_prefix(get_cert_prefix_for_schemes(schemes))
    return cert


def has_inline_identity_pem(config: TlsConfigLike) -> bool:
    return TlsConfigView(config).has_inline_identity_pem()


def dsa_cipher_setup_error() -> str:
    return "DSS cipher requires certs/dsa_default.crt and certs/dsa_default.key (run scripts/gen_interop_certs.sh)"


def resolve_dsa_cipher_cert_paths(config: TlsConfigLike, *, repo: Path | None = None) -> tuple[str, str] | None:
    """Catalog ``dsa_default`` PEM paths when ``cipher_suite`` needs DSA auth."""
    raw_cipher = TlsConfigView(config).cipher_suite
    if not cipher_catalog_id_uses_dsa_auth(raw_cipher):
        return None
    cert, key = catalog_identity_pem_paths_for_prefix("dsa_default", repo=repo)
    if cert and key:
        return cert, key
    return None


def resolve_client_trust_pem_path(config: TlsConfigLike, schemes: Sequence[str] | None = None) -> str:
    """Client trust anchor: DSA leaf, scheme-based leaf, cwd ``cert.pem``, or fallback name."""
    dsa = resolve_dsa_cipher_cert_paths(config)
    if dsa and os.path.isfile(dsa[0]):
        return dsa[0]
    trust_schemes = schemes if schemes is not None else server_trust_signature_schemes_tokens(config)
    trust = catalog_identity_trust_pem_path(trust_schemes)
    if trust and os.path.isfile(trust):
        return trust
    for candidate in (os.path.join(os.getcwd(), "cert.pem"), "cert.pem"):
        if candidate and os.path.isfile(candidate):
            return candidate
    return "cert.pem"


def resolve_server_mtls_cafile(config: TlsConfigLike, server_cert_path: str,
    schemes: Sequence[str] | None = None) -> str:
    """mTLS CA file: explicit ``ca_file``, scheme trust leaf, or server certificate."""
    ca_path = TlsConfigView(config).ca_file
    if ca_path and os.path.isfile(ca_path):
        return ca_path
    trust_schemes = schemes if schemes is not None else server_trust_signature_schemes_tokens(config)
    ca_path = catalog_identity_trust_pem_path(trust_schemes)
    if ca_path and os.path.isfile(ca_path):
        return ca_path
    return server_cert_path


def server_trust_signature_schemes_tokens(config: TlsConfigLike) -> list[str]:
    """
    Schemes that determine **server** leaf identity for client trust stores.

    Prefer ``INTEROP_SERVER_SIGNATURE_SCHEMES`` (manual override), else the
    server half of ``INTEROP_SIGNATURE_SCHEMES`` when it uses ``SERVER:CLIENT``,
    else ``TlsConfig.signature_schemes`` from the active request config.
    """
    ctx = active_orchestration_context()
    if ctx.server_signature_schemes:
        return [p.strip() for p in ctx.server_signature_schemes.split(",") if p.strip()]
    gsig = ctx.asymmetric_signature_schemes
    if gsig and ":" in gsig:
        left, _ = split_asymmetric_csv(gsig)
        return left
    return repeated_config_tokens(config, "signature_schemes")

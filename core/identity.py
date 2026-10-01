"""TLS identity PEM paths and signature-scheme → certificate mapping."""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from core.catalog import repository_root

IDENTITY_PREFIXES = (
    "rsa_default", "rsa_pss_pure", "dsa_default", "ecdsa_p256", "ecdsa_p384",
    "ecdsa_p521", "ed25519", "ed448"
)
DEFAULT_PREFIX = "rsa_default"


def cipher_catalog_id_uses_dsa_auth(cipher_catalog_id: str) -> bool:
    """True for dhe-dss-*, dh-dss-*, etc."""
    c = (cipher_catalog_id or "").strip().lower().replace("_", "-")
    return bool(re.search(r"(^|-)dss(-|$)", c))


def get_cert_prefix_for_scheme(scheme: str) -> str:
    """Map a catalog signature_schemes id to a certs/ filename prefix."""
    tok = (scheme or "").strip().lower().replace(" ", "").replace("_", "-")
    if not tok:
        return DEFAULT_PREFIX
    if "ed25519" in tok:
        return "ed25519"
    if "ed448" in tok:
        return "ed448"
    if "dsa" in tok:
        return "dsa_default"
    if "ecdsa" in tok:
        if "secp521" in tok:
            return "ecdsa_p521"
        if "secp384" in tok:
            return "ecdsa_p384"
        return "ecdsa_p256"
    if "rsa-pss-pss" in tok:
        return "rsa_pss_pure"
    if "rsa" in tok:
        return "rsa_default"
    return DEFAULT_PREFIX


def get_cert_prefix_for_schemes(schemes: Sequence[str]) -> str:
    """First listed scheme wins (TLS signature_algorithms preference order)."""
    return next((get_cert_prefix_for_scheme(s) for s in schemes if s and s.strip()), DEFAULT_PREFIX)


def get_cert_prefix_for_cipher_suite(cipher_catalog_id: str) -> str:
    """Coarse fallback when signature_schemes is unset (cipher auth hint only)."""
    if cipher_catalog_id_uses_dsa_auth(cipher_catalog_id):
        return "dsa_default"
    return get_cert_prefix_for_scheme(cipher_catalog_id)


def get_cert_prefix_for_config(config: Any) -> str:
    """Resolve prefix from signature_schemes, else cipher_suite on config."""
    schemes = repeated_config_tokens(config, "signature_schemes")
    if schemes:
        return get_cert_prefix_for_schemes(schemes)
    return get_cert_prefix_for_cipher_suite(str(getattr(config, "cipher_suite", "") or ""))


def interop_certs_dir(repo: Path | None = None) -> Path:
    return (repo or repository_root()) / "certs"


def catalog_identity_pem_paths_for_prefix(prefix: str, *, repo: Path | None = None) -> tuple[str, str]:
    """Return absolute paths to {prefix}.crt and {prefix}.key when present."""
    p = (prefix or "").strip() or DEFAULT_PREFIX
    base = interop_certs_dir(repo)
    cert, key = base / f"{p}.crt", base / f"{p}.key"
    if cert.is_file() and key.is_file():
        return str(cert.resolve()), str(key.resolve())
    return "", ""


def identity_pem_present(prefix: str, *, repo: Path | None = None) -> bool:
    """True when both certs/{prefix}.crt and certs/{prefix}.key exist."""
    cert_path, key_path = catalog_identity_pem_paths_for_prefix(prefix, repo=repo)
    return bool(cert_path and key_path)


def read_identity_pem_bytes(prefix: str, *, repo: Path | None = None) -> tuple[bytes, bytes]:
    cert_path, key_path = catalog_identity_pem_paths_for_prefix(prefix, repo=repo)
    if not cert_path or not key_path:
        return b"", b""
    return Path(cert_path).read_bytes(), Path(key_path).read_bytes()


def repeated_config_tokens(config: Any, field: str) -> list[str]:
    raw = getattr(config, field, None)
    if not raw:
        return []
    return [str(x).strip() for x in raw if str(x).strip()]


def server_trust_signature_schemes_tokens(config: Any) -> list[str]:
    """Schemes that select the peer leaf / trust PEM under certs/."""
    return repeated_config_tokens(config, "signature_schemes_cert") or repeated_config_tokens(config, "signature_schemes")
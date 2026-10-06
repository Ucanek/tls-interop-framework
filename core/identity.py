"""TLS identity PEM paths and signature-scheme → certificate mapping."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from core.catalog import repository_root


# (needle in scheme/cipher token, certs/{prefix}). First match wins; keep specific before general.
# ``ecdsa`` before ``dsa``/``dss`` — otherwise ``"dsa" in "ecdsa…"`` steals ECDSA schemes.
_SCHEME_PREFIX_RULES: tuple[tuple[str, str], ...] = (
    ("ed25519", "ed25519"),
    ("ed448", "ed448"),
    ("secp521", "ecdsa_p521"),
    ("secp384", "ecdsa_p384"),
    ("ecdsa", "ecdsa_p256"),
    ("dss", "dsa_default"),
    ("dsa", "dsa_default"),
    ("rsa-pss-pss", "rsa_pss_pure"),
    ("rsa", "rsa_default"))

IDENTITY_PREFIXES: tuple[str, ...] = tuple(dict.fromkeys(p for _, p in _SCHEME_PREFIX_RULES))
DEFAULT_PREFIX = next(p for needle, p in _SCHEME_PREFIX_RULES if needle == "rsa")


def cipher_catalog_id_uses_dsa_auth(cipher_catalog_id: str) -> bool:
    """True for dhe-dss-*, dh-dss-*, etc."""
    parts = (cipher_catalog_id or "").strip().lower().replace("_", "-").split("-")
    return "dss" in parts


def get_cert_prefix_for_scheme(scheme: str) -> str:
    """Map a catalog signature_schemes / cipher id to a certs/ filename prefix."""
    tok = (scheme or "").strip().lower().replace(" ", "").replace("_", "-")
    if not tok:
        return DEFAULT_PREFIX
    for pattern, prefix in _SCHEME_PREFIX_RULES:
        if pattern in tok:
            return prefix
    return DEFAULT_PREFIX


def get_cert_prefix_for_schemes(schemes: Sequence[str]) -> str:
    """First listed scheme wins (TLS signature_algorithms preference order)."""
    return next(
        (get_cert_prefix_for_scheme(s) for s in schemes if s and s.strip()), DEFAULT_PREFIX)


def get_cert_prefix_for_config(config: Any) -> str:
    """Resolve prefix from signature_schemes, else cipher_suite on config."""
    schemes = repeated_config_tokens(config, "signature_schemes")
    if schemes:
        return get_cert_prefix_for_schemes(schemes)
    return get_cert_prefix_for_scheme(str(getattr(config, "cipher_suite", "") or ""))


def catalog_identity_pem_paths_for_prefix(prefix: str, *, repo: Path | None = None) -> tuple[str, str]:
    """Return absolute paths to {prefix}.crt and {prefix}.key when present."""
    p = (prefix or "").strip() or DEFAULT_PREFIX
    base = (repo or repository_root()) / "certs"
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
"""TLS identity PEM paths and signature-scheme → certificate mapping."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

# Catalog prefixes under ``certs/`` (``{prefix}.crt`` + ``{prefix}.key``).
IDENTITY_PREFIXES: tuple[str, ...] = (
    "rsa_default",
    "rsa_pss_pure",
    "ecdsa_p256",
    "ecdsa_p384",
    "ecdsa_p521",
    "ed25519",
    "ed448",
)

_DEFAULT_PREFIX = "rsa_default"

# Legacy kind → default prefix (NSS / coarse fallbacks).
_KIND_TO_PREFIX: dict[str, str] = {
    "rsa": "rsa_default",
    "ecdsa": "ecdsa_p256",
    "ed25519": "ed25519",
    "ed448": "ed448",
}


def _split_asymmetric_csv(val: str | None) -> tuple[list[str], list[str]]:
    whole = (val or "").strip()
    if not whole:
        return [], []
    if ":" in whole:
        left, right = whole.split(":", 1)
        return (
            [p.strip() for p in left.split(",") if p.strip()],
            [p.strip() for p in right.split(",") if p.strip()],
        )
    parts = [p.strip() for p in whole.split(",") if p.strip()]
    return parts, parts


def _norm_scheme_token(raw: str) -> str:
    return (raw or "").strip().lower().replace(" ", "").replace("_", "-")


def get_cert_prefix_for_scheme(scheme: str) -> str:
    """
    Map a catalog ``signature_schemes`` id to a ``certs/`` filename prefix.

    Examples:
      ``rsa-pkcs1-sha256`` → ``rsa_default``
      ``rsa-pss-pss-sha256`` → ``rsa_pss_pure``
      ``ecdsa-secp384r1-sha384`` → ``ecdsa_p384``
    """
    tok = _norm_scheme_token(scheme)
    if not tok:
        return _DEFAULT_PREFIX
    if tok.startswith("ed25519") or tok == "ed25519":
        return "ed25519"
    if tok.startswith("ed448") or tok == "ed448":
        return "ed448"
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
    if "ecdsa" in c:
        return "ecdsa_p256"
    if "ed25519" in c:
        return "ed25519"
    if "ed448" in c:
        return "ed448"
    if "rsa" in c:
        return "rsa_default"
    return _DEFAULT_PREFIX


def get_cert_prefix_for_config(config: Any) -> str:
    """Resolve prefix from ``signature_schemes``, else ``cipher_suite`` on ``config``."""
    schemes = repeated_config_tokens(config, "signature_schemes")
    if schemes:
        return get_cert_prefix_for_schemes(schemes)
    return get_cert_prefix_for_cipher_suite(str(getattr(config, "cipher_suite", "") or ""))


def nss_nickname_for_prefix(prefix: str) -> str:
    p = (prefix or "").strip() or _DEFAULT_PREFIX
    return f"interop_{p}"


def interop_certs_dir(repo: Path | None = None) -> Path:
    if repo is not None:
        return repo / "certs"
    cwd = Path.cwd()
    if (cwd / "certs").is_dir():
        return cwd / "certs"
    return Path("/app/certs")


def catalog_identity_pem_paths_for_prefix(
    prefix: str,
    *,
    repo: Path | None = None,
) -> tuple[str, str]:
    """Return absolute paths to ``{prefix}.crt`` and ``{prefix}.key`` when present."""
    p = (prefix or "").strip() or _DEFAULT_PREFIX
    cert_name = f"{p}.crt"
    key_name = f"{p}.key"
    candidates_dirs = []
    if repo is not None:
        candidates_dirs.append(interop_certs_dir(repo))
    candidates_dirs.append(interop_certs_dir(None))

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


def repeated_config_tokens(config: Any, field: str) -> list[str]:
    raw = getattr(config, field, None)
    if not raw:
        return []
    out: list[str] = []
    for x in raw:
        s = str(x).strip()
        if s:
            out.append(s)
    return out


def identity_kind_from_signature_schemes(schemes: Sequence[str]) -> str:
    """Legacy coarse kind (``rsa`` | ``ecdsa`` | ``ed25519`` | ``ed448``)."""
    prefix = get_cert_prefix_for_schemes(schemes)
    if prefix.startswith("ecdsa"):
        return "ecdsa"
    if prefix == "ed25519":
        return "ed25519"
    if prefix == "ed448":
        return "ed448"
    return "rsa"


def identity_kind_from_cipher_suite(cipher_catalog_id: str) -> str | None:
    prefix = get_cert_prefix_for_cipher_suite(cipher_catalog_id)
    if prefix.startswith("ecdsa"):
        return "ecdsa"
    if prefix == "ed25519":
        return "ed25519"
    if prefix == "ed448":
        return "ed448"
    if prefix.startswith("rsa"):
        return "rsa"
    return None


def resolve_identity_kind(config: Any) -> str:
    return identity_kind_from_signature_schemes(
        repeated_config_tokens(config, "signature_schemes")
    ) or identity_kind_from_cipher_suite(
        str(getattr(config, "cipher_suite", "") or "")
    ) or "rsa"


def catalog_identity_pem_paths_for_kind(kind: str) -> tuple[str, str]:
    prefix = _KIND_TO_PREFIX.get(kind, _DEFAULT_PREFIX)
    return catalog_identity_pem_paths_for_prefix(prefix)


def catalog_identity_pem_paths(schemes: Sequence[str]) -> tuple[str, str]:
    return catalog_identity_pem_paths_for_prefix(get_cert_prefix_for_schemes(schemes))


def catalog_identity_pem_paths_for_config(config: Any) -> tuple[str, str]:
    return catalog_identity_pem_paths_for_prefix(get_cert_prefix_for_config(config))


def catalog_identity_trust_pem_path(schemes: Sequence[str]) -> str:
    cert, _ = catalog_identity_pem_paths(schemes)
    return cert


def server_trust_signature_schemes_tokens(config: Any) -> list[str]:
    """
    Schemes that determine **server** leaf identity for client trust stores.

    Prefer ``INTEROP_SERVER_SIGNATURE_SCHEMES`` (manual override), else the
    server half of ``INTEROP_SIGNATURE_SCHEMES`` when it uses ``SERVER:CLIENT``,
    else ``TlsConfig.signature_schemes`` from the active request config.
    """
    env_raw = (os.environ.get("INTEROP_SERVER_SIGNATURE_SCHEMES") or "").strip()
    if env_raw:
        return [p.strip() for p in env_raw.split(",") if p.strip()]
    gsig = (os.environ.get("INTEROP_SIGNATURE_SCHEMES") or "").strip()
    if gsig and ":" in gsig:
        left, _ = _split_asymmetric_csv(gsig)
        return left
    return repeated_config_tokens(config, "signature_schemes")


def all_identity_import_rows(
    *,
    repo: Path | None = None,
) -> list[tuple[str, str, str]]:
    """``(nss_nickname, cert_path, key_path)`` for every generated prefix."""
    rows: list[tuple[str, str, str]] = []
    for prefix in IDENTITY_PREFIXES:
        cert, key = catalog_identity_pem_paths_for_prefix(prefix, repo=repo)
        if cert and key:
            rows.append((nss_nickname_for_prefix(prefix), cert, key))
    return rows

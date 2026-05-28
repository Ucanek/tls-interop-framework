"""TLS identity PEM paths and related config helpers."""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from typing import Any


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

_IDENTITY_KIND_FILES: dict[str, tuple[str, str]] = {
    "rsa": ("cert_rsa.pem", "key_rsa.pem"),
    "ecdsa": ("cert_ecdsa.pem", "key_ecdsa.pem"),
    "ed25519": ("cert_ed25519.pem", "key_ed25519.pem"),
    "ed448": ("cert_ed448.pem", "key_ed448.pem"),
}

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


def _first_existing_path(*candidates: str) -> str:
    for p in candidates:
        if p and os.path.isfile(p):
            return p
    return ""


def identity_kind_from_signature_schemes(schemes: Sequence[str]) -> str:
    """
    Map catalog ``signature_schemes`` preference order to server identity material.

    Returns one of: ``rsa`` | ``ecdsa`` | ``ed25519`` | ``ed448``.
    """
    for raw in schemes:
        tok = (raw or "").strip().lower().replace(" ", "").replace("_", "")
        if not tok:
            continue
        if tok.startswith("ed25519"):
            return "ed25519"
        if tok.startswith("ed448"):
            return "ed448"
        if "ecdsa" in tok or tok.startswith("ecdsa"):
            return "ecdsa"
        if tok.startswith("rsa"):
            return "rsa"
    return "rsa"


def identity_kind_from_cipher_suite(cipher_catalog_id: str) -> str | None:
    """Infer leaf cert kind from catalog ``cipher_suite`` id (e.g. ``ecdhe-ecdsa-*`` → ECDSA)."""
    c = (cipher_catalog_id or "").strip().lower()
    if not c:
        return None
    if "ecdsa" in c:
        return "ecdsa"
    if "rsa" in c:
        return "rsa"
    return None


def resolve_identity_kind(config: Any) -> str:
    """Pick server/client identity material: ``signature_schemes`` first, else cipher hint."""
    schemes = repeated_config_tokens(config, "signature_schemes")
    if schemes:
        return identity_kind_from_signature_schemes(schemes)
    kind = identity_kind_from_cipher_suite(str(getattr(config, "cipher_suite", "") or ""))
    return kind or "rsa"


def catalog_identity_pem_paths_for_kind(kind: str) -> tuple[str, str]:
    """Resolve absolute paths to PEM cert/key for an identity kind."""
    cert_f, key_f = _IDENTITY_KIND_FILES.get(kind, _IDENTITY_KIND_FILES["rsa"])
    cwd = os.getcwd()
    cert = _first_existing_path(
        os.path.join("/app/certs", cert_f),
        os.path.join(cwd, "certs", cert_f),
    )
    key = _first_existing_path(
        os.path.join("/app/certs", key_f),
        os.path.join(cwd, "certs", key_f),
    )
    if cert and key:
        return cert, key
    return "", ""


def catalog_identity_pem_paths(schemes: Sequence[str]) -> tuple[str, str]:
    """Resolve PEM paths from ``signature_schemes`` preference order."""
    return catalog_identity_pem_paths_for_kind(identity_kind_from_signature_schemes(schemes))


def catalog_identity_pem_paths_for_config(config: Any) -> tuple[str, str]:
    """Resolve PEM paths from ``TlsConfig`` (schemes and/or ``cipher_suite``)."""
    return catalog_identity_pem_paths_for_kind(resolve_identity_kind(config))


def catalog_identity_trust_pem_path(schemes: Sequence[str]) -> str:
    """Public cert PEM path to trust the peer (self-signed server) for given schemes."""
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



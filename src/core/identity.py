"""TLS identity PEM paths, NSS DB import rows, and related config helpers."""

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

_NSS_NICK_BY_KIND: dict[str, str] = {
    "rsa": "interop_rsa",
    "ecdsa": "interop_ecdsa",
    "ed25519": "interop_ed25519",
    "ed448": "interop_ed448",
}

# NSS pk12util cannot import OpenSSL-generated Ed25519/Ed448 PKCS#12 (Mozilla bug 1993638).
_NSS_SKIP_PKCS12_IMPORT_NICKS: frozenset[str] = frozenset({"interop_ed25519", "interop_ed448"})


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


def catalog_identity_pem_paths(schemes: Sequence[str]) -> tuple[str, str]:
    """
    Resolve absolute paths to PEM cert/key for ``signature_schemes`` preference.

    Prefers ``/app/certs/`` (container), then ``<cwd>/certs/`` for local runs.
    Returns ``("", "")`` when no known bundle exists on disk.
    """
    kind = identity_kind_from_signature_schemes(schemes)
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


def nss_server_nickname_for_signature_schemes(schemes: Sequence[str]) -> str:
    kind = identity_kind_from_signature_schemes(schemes)
    return _NSS_NICK_BY_KIND.get(kind, _NSS_NICK_BY_KIND["rsa"])


def nss_interop_identity_import_rows() -> list[tuple[str, str, str]]:
    """
    Return ``(nickname, cert_pem_path, key_pem_path)`` for each identity bundle
    that exists on disk (used to populate NSS DB).

    Ed25519/Ed448 PEM bundles are omitted: ``pk12util`` cannot import them from
    OpenSSL PKCS#12 until NSS bug 1993638 is fixed in the distro build.
    """
    rows: list[tuple[str, str, str]] = []
    for kind in ("rsa", "ecdsa", "ed25519", "ed448"):
        nick = _NSS_NICK_BY_KIND[kind]
        if nick in _NSS_SKIP_PKCS12_IMPORT_NICKS:
            continue
        cert_f, key_f = _IDENTITY_KIND_FILES[kind]
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
            rows.append((nick, cert, key))
    return rows

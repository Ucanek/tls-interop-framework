"""NSS-specific identity helpers (nicknames, import rows)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from core.identity import (
    catalog_identity_pem_paths_for_kind,
    identity_kind_from_signature_schemes,
    resolve_identity_kind,
    server_trust_signature_schemes_tokens,
)

_NSS_NICK_BY_KIND: dict[str, str] = {
    "rsa": "interop_rsa",
    "ecdsa": "interop_ecdsa",
    "ed25519": "interop_ed25519",
    "ed448": "interop_ed448",
}

# NSS pk12util cannot import OpenSSL-generated Ed25519/Ed448 PKCS#12 (Mozilla bug 1993638).
_NSS_SKIP_PKCS12_IMPORT_NICKS: frozenset[str] = frozenset(
    {"interop_ed25519", "interop_ed448"}
)


def nss_server_nickname_for_signature_schemes(schemes: Sequence[str]) -> str:
    kind = identity_kind_from_signature_schemes(schemes)
    return _NSS_NICK_BY_KIND.get(kind, _NSS_NICK_BY_KIND["rsa"])


def nss_server_nickname_for_config(config: Any) -> str:
    """``selfserv -n`` nickname: trust schemes first, else infer from ``cipher_suite``."""
    schemes = server_trust_signature_schemes_tokens(config)
    if schemes:
        kind = identity_kind_from_signature_schemes(schemes)
    else:
        kind = resolve_identity_kind(config)
    return _NSS_NICK_BY_KIND.get(kind, _NSS_NICK_BY_KIND["rsa"])


def nss_interop_identity_import_rows() -> list[tuple[str, str, str]]:
    """
    Return ``(nickname, cert_pem_path, key_pem_path)`` for each identity bundle
    that exists on disk (used to populate NSS DB).
    """
    rows: list[tuple[str, str, str]] = []
    for kind in ("rsa", "ecdsa", "ed25519", "ed448"):
        nick = _NSS_NICK_BY_KIND[kind]
        if nick in _NSS_SKIP_PKCS12_IMPORT_NICKS:
            continue
        cert, key = catalog_identity_pem_paths_for_kind(kind)
        if cert and key:
            rows.append((nick, cert, key))
    return rows

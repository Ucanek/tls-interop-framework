"""NSS-specific identity helpers (nicknames, import rows)."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from core.identity import (
    all_identity_import_rows,
    cipher_catalog_id_uses_dsa_auth,
    get_cert_prefix_for_config,
    identity_pem_present,
    nss_nickname_for_prefix,
    server_trust_signature_schemes_tokens,
)

# NSS pk12util cannot import OpenSSL-generated Ed25519/Ed448 PKCS#12 (Mozilla bug 1993638).
_NSS_SKIP_PKCS12_IMPORT_PREFIXES: frozenset[str] = frozenset({"ed25519", "ed448"})


def nss_server_nickname_for_signature_schemes(schemes: Sequence[str]) -> str:
    from core.identity import get_cert_prefix_for_schemes

    return nss_nickname_for_prefix(get_cert_prefix_for_schemes(schemes))


def nss_server_nickname_for_config(
    config: Any,
    *,
    repo: Path | None = None,
) -> str:
    """``selfserv -n`` nickname from server ``signature_schemes`` / ``cipher_suite``."""
    raw_cipher = str(getattr(config, "cipher_suite", None) or "").strip()
    if cipher_catalog_id_uses_dsa_auth(raw_cipher):
        if not identity_pem_present("dsa_default", repo=repo):
            raise RuntimeError(
                "DSS cipher requires certs/dsa_default.crt and certs/dsa_default.key "
                "(run scripts/gen_interop_certs.sh)"
            )
        return nss_nickname_for_prefix("dsa_default")
    return nss_nickname_for_prefix(get_cert_prefix_for_config(config))


def nss_interop_identity_import_rows(
    *,
    repo: Path | None = None,
) -> list[tuple[str, str, str]]:
    """
    Return ``(nickname, cert_pem_path, key_pem_path)`` for each identity bundle
    that exists on disk (used to populate NSS DB).
    """
    rows: list[tuple[str, str, str]] = []
    for nick, cert, key in all_identity_import_rows(repo=repo):
        prefix = nick.removeprefix("interop_")
        if prefix in _NSS_SKIP_PKCS12_IMPORT_PREFIXES:
            continue
        rows.append((nick, cert, key))
    return rows

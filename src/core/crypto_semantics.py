"""Cipher-suite semantics: PSK sizing, anonymous suites, identity requirements, TLS 1.2 metadata."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from core.constants import TlsFeature
from core.utils import norm_catalog_token


def psk_key_bits_for_cipher(cipher_id: str) -> int:
    """PSK key length implied by catalog cipher id (128-bit vs 256-bit suites)."""
    c = norm_catalog_token(cipher_id)
    if "chacha20" in c:
        return 256
    if re.search(r"(?:aes|aria|camellia)(?:-)?256|[-/]256[-/](?:gcm|ccm|cbc)|[-]256[-](?:gcm|ccm|cbc)", c):
        return 256
    return 128


def cipher_catalog_id_requires_psk(cipher_id: str) -> bool:
    """True for catalog ids such as ``psk-aes-128-gcm``, ``rsa-psk-*``, ``dhe-psk-*``."""
    c = norm_catalog_token(cipher_id)
    return bool(re.search(r"(^|-)psk(-|$)", c))


def cipher_catalog_id_requires_anon(cipher_id: str) -> bool:
    """True for DH/ECDH anonymous catalog ids (``dh-anon-*``, ``ecdh-anon-*``, …)."""
    c = norm_catalog_token(cipher_id)
    return "anon" in c.split("-") or c.startswith("adh-")


def cipher_required_test_feature(cipher_id: str) -> str | None:
    if cipher_catalog_id_requires_psk(cipher_id):
        return TlsFeature.PSK.value
    if cipher_catalog_id_requires_anon(cipher_id):
        return TlsFeature.ANONYMOUS.value
    return None


def cipher_catalog_id_requires_identity_pem(cipher_id: str) -> bool:
    """
    True when the server must present a leaf certificate matching the cipher auth.

    Excludes anonymous suites and static PSK (``psk-aes-*``); includes RSA/ECDSA/EdDSA
    ciphers and hybrid ``*-psk`` suites that combine certificates with PSK.
    """
    c = norm_catalog_token(cipher_id)
    if not c:
        return False
    if cipher_catalog_id_requires_anon(c):
        return False
    if cipher_catalog_id_requires_psk(c):
        return bool(re.search(r"(^|-)(rsa|dhe|ecdhe)-psk", c))
    from core.identity import cipher_catalog_id_uses_dsa_auth

    if cipher_catalog_id_uses_dsa_auth(c):
        return True
    if "ecdsa" in c or "ed25519" in c or "ed448" in c:
        return True
    if re.search(r"(^|-)rsa", c):
        return True
    return False


def psk_secret_hex_for_cipher(capabilities: dict[str, object], cipher_id: str) -> str | None:
    from core.capabilities import test_feature_entry

    entry = test_feature_entry(capabilities, TlsFeature.PSK.value)
    bits = psk_key_bits_for_cipher(cipher_id)
    field = "secret_hex_256" if bits >= 256 else "secret_hex_128"
    secret_hex = str(entry.get(field) or entry.get("secret_hex") or "").strip()
    if not secret_hex:
        return None
    expected = bits // 4
    if len(secret_hex) != expected:
        return None
    return secret_hex


def psk_material_from_capabilities(capabilities: dict[str, object], cipher_id: str) -> tuple[str, str] | None:
    from core.capabilities import test_feature_entry

    entry = test_feature_entry(capabilities, TlsFeature.PSK.value)
    identity = str(entry.get("identity") or "interop").strip()
    secret_hex = psk_secret_hex_for_cipher(capabilities, cipher_id)
    if not secret_hex:
        return None
    return identity, secret_hex


@dataclass(frozen=True)
class Tls12CipherMetadata:
    """Metadata extracted from a TLS 1.2 cipher token/name."""

    kx: Literal["ecdhe", "dhe", "static-rsa", "unknown"]
    au: Literal["rsa", "ecdsa", "dsa", "unknown"]


def tls12_cipher_metadata_from_name(cipher_name: str) -> Tls12CipherMetadata:
    """
    Extract TLS 1.2 semantics from cipher token/name (catalog id or backend literal).

    This parser is intentionally TLS1.2-oriented and must not be used for TLS 1.3 ciphers.
    """
    raw = (cipher_name or "").strip().lower()
    tok = raw.replace("_", "-").replace(" ", "")
    if not tok or tok.startswith("tls-"):
        return Tls12CipherMetadata(kx="unknown", au="unknown")
    if "ecdhe" in tok:
        kx: Literal["ecdhe", "dhe", "static-rsa", "unknown"] = "ecdhe"
    elif re.search(r"(^|-)dhe(-|$)", tok):
        kx = "dhe"
    elif "rsa" in tok or tok.startswith("aes"):
        kx = "static-rsa"
    else:
        kx = "unknown"

    if re.search(r"(^|-)dss(-|$)", tok):
        au: Literal["rsa", "ecdsa", "dsa", "unknown"] = "dsa"
    elif "ecdsa" in tok:
        au = "ecdsa"
    elif "rsa" in tok or tok.startswith("aes"):
        au = "rsa"
    else:
        au = "unknown"
    return Tls12CipherMetadata(kx=kx, au=au)

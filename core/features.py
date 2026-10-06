"""PSK, anonymous, and TLS 1.2 cipher metadata derived from catalog ids."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from core.catalog import norm_catalog_token


@dataclass(frozen=True)
class Tls12CipherMetadata:
    kx: Literal["ecdhe", "dhe", "static-rsa", "unknown"]
    au: Literal["rsa", "ecdsa", "dsa", "unknown"]


def _tls12_kx_from_token(tok: str) -> Literal["ecdhe", "dhe", "static-rsa", "unknown"]:
    if "ecdhe" in tok:
        return "ecdhe"
    if re.search(r"(^|-)dhe(-|$)", tok):
        return "dhe"
    if "rsa" in tok or tok.startswith("aes"):
        return "static-rsa"
    return "unknown"


def _tls12_au_from_token(tok: str) -> Literal["rsa", "ecdsa", "dsa", "unknown"]:
    if re.search(r"(^|-)dss(-|$)", tok):
        return "dsa"
    if "ecdsa" in tok:
        return "ecdsa"
    if "rsa" in tok or tok.startswith("aes"):
        return "rsa"
    return "unknown"


def tls12_cipher_metadata_from_name(cipher_name: str) -> Tls12CipherMetadata:
    raw = (cipher_name or "").strip().lower()
    tok = raw.replace("_", "-").replace(" ", "")
    if not tok or tok.startswith("tls-"):
        return Tls12CipherMetadata(kx="unknown", au="unknown")
    return Tls12CipherMetadata(kx=_tls12_kx_from_token(tok), au=_tls12_au_from_token(tok))


def cipher_catalog_id_requires_psk(cipher_id: str) -> bool:
    c = norm_catalog_token(cipher_id)
    return bool(re.search(r"(^|-)psk(-|$)", c))


def cipher_catalog_id_requires_anon(cipher_id: str) -> bool:
    c = norm_catalog_token(cipher_id)
    return "anon" in c.split("-") or c.startswith("adh-")


def cipher_required_test_feature(cipher_id: str) -> str | None:
    if cipher_catalog_id_requires_psk(cipher_id):
        return "psk"
    if cipher_catalog_id_requires_anon(cipher_id):
        return "anonymous"

    return None


def cipher_catalog_id_requires_identity_pem(cipher_id: str) -> bool:
    c = norm_catalog_token(cipher_id)
    if not c or cipher_catalog_id_requires_anon(c):
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


def parse_test_features_enabled(raw: str) -> frozenset[str]:
    if not (raw or "").strip():
        return frozenset()

    return frozenset(p.strip().lower() for p in str(raw).split(",") if p.strip())


def psk_key_bits_for_cipher(cipher_id: str) -> int:
    c = norm_catalog_token(cipher_id)
    if "chacha20" in c:
        return 256

    aes256_pattern = r"(?:aes|aria|camellia)(?:-)?256|[-/]256[-/](?:gcm|ccm|cbc)|[-]256[-](?:gcm|ccm|cbc)"
    if re.search(aes256_pattern, c):
        return 256

    return 128


def signature_scheme_auth_kind(token: str) -> Literal["rsa", "ecdsa", "dsa", "eddsa", "unknown"]:
    t = (token or "").strip().lower().replace("_", "").replace("-", "")
    if not t:
        return "unknown"
    if t.startswith("dsa"):
        return "dsa"
    if "rsa" in t:
        return "rsa"
    if "ecdsa" in t:
        return "ecdsa"
    if t.startswith(("ed25519", "ed448", "eddsa")):
        return "eddsa"
    return "unknown"


def group_family(token: str) -> Literal["ec", "ffdhe", "other"]:
    t = (token or "").strip().lower().replace("_", "-")
    if not t:
        return "other"

    if t.startswith("ffdhe"):
        return "ffdhe"

    ec_prefixes = ("secp", "x25519", "x448", "brainpool", "xyber", "mlkem")
    if t.startswith(ec_prefixes) or "mlkem" in t:
        return "ec"

    return "other"


def tls12_group_semantic_skip(cipher_id: str, grp_tokens: list[str]) -> str | None:
    if not grp_tokens:
        return None

    meta = tls12_cipher_metadata_from_name(cipher_id)
    if meta.kx == "static-rsa":
        return "TLS 1.2 static RSA cipher does not support groups"

    if meta.kx == "ecdhe" and any(group_family(g) != "ec" for g in grp_tokens):
        return "TLS 1.2 ECDHE cipher requires EC groups (secp*/x25519/x448)"

    if meta.kx == "dhe" and any(group_family(g) != "ffdhe" for g in grp_tokens):
        return "TLS 1.2 DHE cipher requires FFDHE groups"

    return None


def tls12_sig_semantic_skip(cipher_id: str, sig_tokens: list[str]) -> str | None:
    if not sig_tokens:
        return None

    meta = tls12_cipher_metadata_from_name(cipher_id)
    if meta.au == "unknown":
        return None

    for sig in sig_tokens:
        sk = signature_scheme_auth_kind(sig)
        if sk != "unknown" and meta.au != sk:
            return "Signature scheme type conflicts with TLS 1.2 cipher authentication"

    return None

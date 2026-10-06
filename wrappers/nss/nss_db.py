"""NSS DB population, CLI tool resolution, and library version detection."""

from __future__ import annotations

import fcntl
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from core.identity import (
    DEFAULT_PREFIX, IDENTITY_PREFIXES, catalog_identity_pem_paths_for_prefix,
    cipher_catalog_id_uses_dsa_auth, get_cert_prefix_for_config)
from wrappers.utils import parse_version_line

_UNSUPPORTED_TOOL_PREFIXES = (
    "/usr/lib64/nss/unsupported-tools", "/usr/lib/nss/unsupported-tools")
# NSS pk12util cannot import OpenSSL-generated Ed25519/Ed448 PKCS#12 (Mozilla bug 1993638).
_NSS_SKIP_PKCS12_IMPORT_PREFIXES = frozenset({"ed25519", "ed448"})


def nss_nickname_for_prefix(prefix: str) -> str:
    return f"interop_{(prefix or '').strip() or DEFAULT_PREFIX}"


def resolve_cli_tool(name: str) -> str | None:
    """Resolve NSS CLI binaries (PATH, then Fedora ``unsupported-tools``)."""
    found = shutil.which(name)
    if found:
        return found
    for prefix in _UNSUPPORTED_TOOL_PREFIXES:
        path = os.path.join(prefix, name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _require_cli_tool(name: str) -> str:
    path = resolve_cli_tool(name)
    if path:
        return path
    raise RuntimeError(f"NSS setup: required tool not found: {name}")


def _run_checked(cmd: list[str]) -> None:
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        detail = (r.stderr or r.stdout or "").strip()
        raise RuntimeError(f"NSS setup failed: {' '.join(cmd)} | {detail}")


def _nss_db_has_nickname(certutil: str, db_spec: str, nickname: str) -> bool:
    r = subprocess.run(
        [certutil, "-L", "-d", db_spec, "-n", nickname], capture_output=True, text=True)
    return r.returncode == 0


def _import_pkcs12_identity(
    *, openssl: str, pk12util: str, certutil: str, db_abs: str, db_spec: str,
    nickname: str, cert_pem: str, key_pem: str) -> None:
    if not (os.path.isfile(cert_pem) and os.path.isfile(key_pem)):
        raise RuntimeError(
            f"NSS setup: missing PEM for {nickname}: {cert_pem!r} / {key_pem!r}")
    p12_path = os.path.join(db_abs, f"{nickname}.p12")
    try:
        _run_checked([
            openssl, "pkcs12", "-export", "-in", cert_pem, "-inkey", key_pem,
            "-out", p12_path, "-passout", "pass:", "-nodes", "-name", nickname])
        _run_checked([pk12util, "-d", db_spec, "-i", p12_path, "-W", "", "-K", ""])
        _run_checked([certutil, "-M", "-d", db_spec, "-n", nickname, "-t", "CT,u,u"])
    finally:
        if os.path.isfile(p12_path):
            os.remove(p12_path)


def _ensure_nss_db_identities(nssdb_path: str, identities: list[tuple[str, str, str]]) -> None:
    """Idempotent: recreate NSS DB unless every nickname is already present."""
    if not identities:
        raise RuntimeError("NSS setup: no identity bundles to import")

    certutil = _require_cli_tool("certutil")
    pk12util = _require_cli_tool("pk12util")
    openssl = _require_cli_tool("openssl")
    db_abs = os.path.abspath(nssdb_path)
    db_spec = f"sql:{db_abs}"
    lock_path = db_abs + ".lock"
    os.makedirs(os.path.dirname(lock_path) or ".", exist_ok=True)
    with open(lock_path, "w", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if all(_nss_db_has_nickname(certutil, db_spec, nick) for nick, _, _ in identities):
            return
        if os.path.isdir(db_abs):
            shutil.rmtree(db_abs)
        os.makedirs(db_abs, exist_ok=True)
        _run_checked([certutil, "-N", "-d", db_spec, "--empty-password"])
        for nickname, cert_pem, key_pem in identities:
            _import_pkcs12_identity(
                openssl=openssl, pk12util=pk12util, certutil=certutil, db_abs=db_abs,
                db_spec=db_spec, nickname=nickname, cert_pem=cert_pem, key_pem=key_pem)


def get_nss_library_version() -> str:
    """Package version string for ``GetMetadata`` (rpm or dpkg)."""
    queries = (
        (["rpm", "-q", "nss-softokn"], shutil.which("rpm")),
        (["dpkg-query", "-W", "-f=${Version}\n", "libnss3"], shutil.which("dpkg-query")))
    for cmd, present in queries:
        if not present:
            continue
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode == 0 and (r.stdout or "").strip():
            return parse_version_line(r.stdout) or ""
    return ""


def nss_server_nickname_for_config(config: Any, *, repo: Path | None = None) -> str:
    """``selfserv -n`` nickname from server ``signature_schemes`` / ``cipher_suite``."""
    raw_cipher = str(getattr(config, "cipher_suite", None) or "").strip()
    if cipher_catalog_id_uses_dsa_auth(raw_cipher):
        cert, _ = catalog_identity_pem_paths_for_prefix("dsa_default", repo=repo)
        if not cert:
            raise RuntimeError(
                "No identity PEM for this test (use certs/ from core/gen_interop_certs.sh)")
        return nss_nickname_for_prefix("dsa_default")
    return nss_nickname_for_prefix(get_cert_prefix_for_config(config))


def nss_interop_identity_import_rows(*, repo: Path | None = None) -> list[tuple[str, str, str]]:
    """``(nickname, cert_pem, key_pem)`` for each on-disk bundle NSS can import."""
    rows: list[tuple[str, str, str]] = []
    for prefix in IDENTITY_PREFIXES:
        if prefix in _NSS_SKIP_PKCS12_IMPORT_PREFIXES:
            continue
        cert, key = catalog_identity_pem_paths_for_prefix(prefix, repo=repo)
        if cert and key:
            rows.append((nss_nickname_for_prefix(prefix), cert, key))
    return rows

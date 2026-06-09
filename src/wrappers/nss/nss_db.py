"""NSS DB population, CLI tool resolution, and library version detection."""

from __future__ import annotations

import fcntl
import os
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from core.identity import(IDENTITY_PREFIXES, catalog_identity_pem_paths_for_prefix,
    cipher_catalog_id_uses_dsa_auth, get_cert_prefix_for_config, get_cert_prefix_for_schemes, identity_pem_present)
from wrappers.utils import parse_version_line

_UNSUPPORTED_TOOL_PREFIXES = ("/usr/lib64/nss/unsupported-tools", "/usr/lib/nss/unsupported-tools")

# NSS pk12util cannot import OpenSSL-generated Ed25519/Ed448 PKCS#12 (Mozilla bug 1993638).
_NSS_SKIP_PKCS12_IMPORT_PREFIXES: frozenset[str] = frozenset({"ed25519", "ed448"})
_DEFAULT_CERT_PREFIX = "rsa_default"


def nss_nickname_for_prefix(prefix: str) -> str:
    p = (prefix or "").strip() or _DEFAULT_CERT_PREFIX
    return f"interop_{p}"


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
    if name == "openssl":
        found = shutil.which("openssl")
        if found:
            return found
    raise RuntimeError(f"NSS setup: required tool not found: {name}")


def _run_checked(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        detail = (r.stderr or r.stdout or "").strip()
        raise RuntimeError(f"NSS setup failed: {' '.join(cmd)} | {detail}")
    return r


def _nss_db_has_nickname(certutil: str, db_spec: str, nickname: str) -> bool:
    r = subprocess.run([certutil, "-L", "-d", db_spec, "-n", nickname], capture_output=True, text=True)
    return r.returncode == 0


def _ensure_nss_db_identities(nssdb_path: str, identities: list[tuple[str, str, str]]) -> None:
    """
    Ensure NSS DB exists and contains every ``(nickname, cert_pem, key_pem)``.

    Idempotent when all nicknames are already present.
    """
    if not identities:
        raise RuntimeError("NSS setup: no identity bundles to import")

    certutil = _require_cli_tool("certutil")
    pk12util = _require_cli_tool("pk12util")
    openssl = _require_cli_tool("openssl")
    db_abs = os.path.abspath(nssdb_path)
    db_spec = f"sql:{db_abs}"
    lock_path = db_abs + ".lock"
    lock_parent = os.path.dirname(os.path.abspath(lock_path))
    if lock_parent:
        os.makedirs(lock_parent, exist_ok=True)
    with open(lock_path, "w", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if all(_nss_db_has_nickname(certutil, db_spec, nick) for nick, _, _ in identities):
            return

        if os.path.isdir(db_abs):
            shutil.rmtree(db_abs)
        os.makedirs(db_abs, exist_ok=True)

        _run_checked([certutil, "-N", "-d", db_spec, "--empty-password"])

        for nickname, cert_pem, key_pem in identities:
            if not (os.path.isfile(cert_pem) and os.path.isfile(key_pem)):
                raise RuntimeError(f"NSS setup: missing PEM for {nickname}: {cert_pem!r} / {key_pem!r}")
            p12_path = os.path.join(db_abs, f"{nickname}.p12")
            _run_checked([openssl, "pkcs12", "-export", "-in", cert_pem, "-inkey", key_pem, "-out", p12_path,
                "-passout", "pass:", "-nodes", "-name", nickname])
            try:
                _run_checked([pk12util, "-d", db_spec, "-i", p12_path, "-W", "", "-K", ""])
                _run_checked([certutil, "-M", "-d", db_spec, "-n", nickname, "-t", "CT,u,u"])
            finally:
                if os.path.isfile(p12_path):
                    os.remove(p12_path)


def get_nss_library_version() -> str:
    """Package version string for ``GetMetadata`` (rpm or dpkg)."""
    try:
        if shutil.which("rpm"):
            r = subprocess.run(["rpm", "-q", "nss-softokn"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and (r.stdout or "").strip():
                return parse_version_line(r.stdout) or ""
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        if shutil.which("dpkg-query"):
            r = subprocess.run(["dpkg-query", "-W", "-f=${Version}\n", "libnss3"],
                capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and (r.stdout or "").strip():
                return parse_version_line(r.stdout) or ""
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def nss_server_nickname_for_signature_schemes(schemes: Sequence[str]) -> str:
    return nss_nickname_for_prefix(get_cert_prefix_for_schemes(schemes))


def nss_server_nickname_for_config(config: Any, *, repo: Path | None = None) -> str:
    """``selfserv -n`` nickname from server ``signature_schemes`` / ``cipher_suite``."""
    raw_cipher = str(getattr(config, "cipher_suite", None) or "").strip()
    if cipher_catalog_id_uses_dsa_auth(raw_cipher):
        if not identity_pem_present("dsa_default", repo=repo):
            raise RuntimeError("DSS cipher requires certs/dsa_default.crt and certs/dsa_default.key "
                "(run scripts/gen_interop_certs.sh)")
        return nss_nickname_for_prefix("dsa_default")
    return nss_nickname_for_prefix(get_cert_prefix_for_config(config))


def nss_interop_identity_import_rows(*, repo: Path | None = None) -> list[tuple[str, str, str]]:
    """
    Return ``(nickname, cert_pem_path, key_pem_path)`` for each identity bundle
    that exists on disk (used to populate NSS DB).
    """
    rows: list[tuple[str, str, str]] = []
    for prefix in IDENTITY_PREFIXES:
        cert, key = catalog_identity_pem_paths_for_prefix(prefix, repo=repo)
        if not cert or not key:
            continue
        if prefix in _NSS_SKIP_PKCS12_IMPORT_PREFIXES:
            continue
        rows.append((nss_nickname_for_prefix(prefix), cert, key))
    return rows

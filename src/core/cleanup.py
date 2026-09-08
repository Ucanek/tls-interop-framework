"""Shared directory teardown for matrix certs and per-session wrapper staging."""

from __future__ import annotations

import logging
import shutil
import subprocess
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path

logger = logging.getLogger(__name__)


def remove_directory_tree(path: Path | str, *, verbose: bool = False, label: str = "") -> None:
    """Remove a directory tree when it exists."""
    root = Path(path)
    if not root.is_dir():
        return
    if verbose:
        tag = label or str(root)
        logger.debug("Removing %s", tag)
    try:
        shutil.rmtree(root)
    except Exception as e:
        logger.warning("Failed to remove directory %s: %s", root, e)


def ensure_interop_certs(repo: Path, *, verbose: bool = False) -> None:
    """Create ``certs/{prefix}.crt`` bundles when any are missing."""
    from core.identity import IDENTITY_PREFIXES

    cert_dir = repo / "certs"
    missing = [prefix for prefix in IDENTITY_PREFIXES if not (cert_dir / f"{prefix}.crt").is_file()
        or not (cert_dir / f"{prefix}.key").is_file()]
    if not missing:
        return
    script = repo / "scripts" / "gen_interop_certs.sh"
    if not script.is_file():
        raise FileNotFoundError(f"Missing certs/ bundles ({', '.join(missing)}); "
            f"run scripts/gen_interop_certs.sh or create certs/ manually")
    if verbose:
        logger.debug("Generating identity PEMs (%s) via %s", ", ".join(missing), script)
    subprocess.run(["bash", str(script)], cwd=repo, check=True)


def remove_interop_certs(repo: Path, *, verbose: bool = False) -> None:
    """Remove ``certs/`` after a matrix run (including ``dh2048.pem``)."""
    remove_directory_tree(repo / "certs", verbose=verbose, label=str(repo / "certs"))


@contextmanager
def matrix_identity_certs(repo: Path, *, enabled: bool, verbose: bool = False) -> Iterator[None]:
    """Ensure repo ``certs/`` for a matrix run and remove the tree on exit when ``enabled``."""
    if not enabled:
        yield
        return
    ensure_interop_certs(repo, verbose=verbose)
    try:
        yield
    finally:
        remove_interop_certs(repo, verbose=verbose)

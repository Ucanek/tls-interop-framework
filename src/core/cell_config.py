"""Build gRPC ``TlsConfig`` messages from normalized matrix cells."""

from __future__ import annotations

from pathlib import Path

from core.matrix_cell import MatrixCell
from core.registry import load_capabilities
from core.session_manager import BaseExecutionSession
from core.worker_pool import WorkerSlotSession

from interop_proto import interop_pb2


def _server_accepts_inline_pem_identity(backend: str, repo: Path) -> bool:
    """False when wrapper uses out-of-band identity (e.g. NSS DB nicknames)."""
    try:
        rt = load_capabilities(backend, repo).get("runtime") or {}
    except (FileNotFoundError, ValueError):
        return True
    blocked = frozenset(rt.get("unsupported_tls_fields") or ())
    return "certificate" not in blocked and "private_key" not in blocked


def _attach_cell_server_identity(
    cfg: interop_pb2.TlsConfig, cell: MatrixCell, *, repo: Path
) -> None:
    """Load server leaf PEM bytes from ``certs/{prefix}.*`` for this cell's sig schemes."""
    from core.identity import (
        get_cert_prefix_for_cipher_suite,
        get_cert_prefix_for_schemes,
        read_identity_pem_bytes,
    )

    schemes = cell.list_tokens("signature_schemes", server=True)
    if schemes:
        prefix = get_cert_prefix_for_schemes(schemes)
    else:
        prefix = get_cert_prefix_for_cipher_suite(cell.cipher_id(server=True))
    cert_b, key_b = read_identity_pem_bytes(prefix, repo=repo)
    if cert_b and key_b:
        cfg.certificate = cert_b
        cfg.private_key = key_b


def tls_config_from_cell(
    cell: MatrixCell, role: int, *, repo: Path | None = None
) -> interop_pb2.TlsConfig:
    """Build ``TlsConfig`` for one matrix role from a normalized cell."""
    server = role == interop_pb2.SERVER
    cfg = interop_pb2.TlsConfig()
    ver = cell.scalar("tls_version", server=server)
    if ver:
        cfg.version = ver
    else:
        cfg.version = "1.3"
    cs = cell.scalar("cipher_suite", server=server)
    if cs:
        cfg.cipher_suite = cs
    port_raw = cell.scalar("tls_port", server=server)
    if port_raw:
        cfg.port = int(port_raw)
    elif not (cell.tls_port or "").strip():
        cfg.port = 5555
    cfg.supported_groups.extend(cell.list_tokens("supported_groups", server=server))
    cfg.signature_schemes.extend(cell.list_tokens("signature_schemes", server=server))
    cfg.alpn_protocols.extend(cell.list_tokens("alpn", server=server))
    from core.capabilities import enabled_test_features_from_cell

    cfg.psk_modes.extend(sorted(enabled_test_features_from_cell(cell)))
    if cell.truthy("expect_hrr"):
        cfg.expect_hrr = True
    if server and repo is not None:
        backend = cell.server
        if _server_accepts_inline_pem_identity(backend, repo):
            _attach_cell_server_identity(cfg, cell, repo=repo)
    return cfg


def wrapper_filesystem_root(session: BaseExecutionSession) -> str:
    """Repo root path as seen inside wrapper subprocesses (per-slot dir when parallel)."""
    if isinstance(session, WorkerSlotSession):
        root = session.repo / ".interop_worker" / f"slot{session.slot_id}"
        root.mkdir(parents=True, exist_ok=True)
        return str(root.resolve())
    return str(session.repo.resolve())


def copy_tls_config(cfg: interop_pb2.TlsConfig) -> interop_pb2.TlsConfig:
    out = interop_pb2.TlsConfig()
    out.CopyFrom(cfg)
    return out


def tls_config_resumption_or_0rtt_active(cfg: interop_pb2.TlsConfig) -> bool:
    from wrappers.utils import test_feature_enabled_in_config

    return test_feature_enabled_in_config(
        cfg, "resumption"
    ) or test_feature_enabled_in_config(cfg, "0rtt")

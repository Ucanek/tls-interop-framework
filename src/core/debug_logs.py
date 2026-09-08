"""Debug log files for failed or timed-out matrix cells."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from core.matrix_cell import MatrixCell
from core.registry import merged_orchestration_env, session_wrapper_env

from interop_proto import interop_pb2

if TYPE_CHECKING:
    from core.driver import InteropDriver


def cell_log_basename(
    server: str, client: str, cell: MatrixCell | None, *, kind: str
) -> str:
    base = f"{server}_x_{client}"
    if cell:
        tags: list[str] = []
        mapping = cell.to_mapping()
        for key in (
            "tls_version",
            "cipher_suite",
            "supported_groups",
            "signature_schemes",
            "alpn",
            "tls_port",
        ):
            raw = (mapping.get(key) or "").strip()
            if raw:
                safe = re.sub(r"[^\w.-]+", "-", raw)[:48]
                tags.append(safe)
        if tags:
            base = f"{base}_{'_'.join(tags)}"
    prefix = f"{kind.lower()}_" if kind else "fail_"
    return f"{prefix}{base}.log"


def format_output_data(data: bytes) -> str:
    if not data:
        return "(empty)"
    ascii_repr = data.decode("ascii", errors="replace")
    lines = [f"len={len(data)}", f"ascii: {ascii_repr!r}", f"hex: {data.hex()}"]
    return "\n".join(lines)


def negotiated_debug_text(neg: interop_pb2.NegotiatedTlsParameters | None) -> str:
    if neg is None:
        return "(none)"
    parts = []
    if (neg.protocol_version or "").strip():
        parts.append(f"protocol_version={neg.protocol_version}")
    if (neg.cipher_suite or "").strip():
        parts.append(f"cipher_suite={neg.cipher_suite}")
    if (neg.named_group or "").strip():
        parts.append(f"named_group={neg.named_group}")
    if neg.hrr_occurred:
        parts.append("hrr_occurred=true")
    return ", ".join(parts) if parts else "(empty negotiated block)"


def metadata_debug_text(label: str, meta: interop_pb2.LibraryMetadata | None) -> str:
    if meta is None:
        return f"{label}: (not loaded)"
    roles = [str(r) for r in meta.roles]
    versions = [c.name for c in meta.supported_versions[:8]]
    ciphers = [c.name for c in meta.cipher_suites[:8]]
    groups = [c.name for c in meta.groups[:8]]
    return "\n".join(
        [
            f"{label}: {meta.component_name} {meta.version}",
            f"  roles: {', '.join(roles) or '-'}",
            f"  supported_versions (sample): {', '.join(versions) or '-'}",
            f"  cipher_suites (sample): {', '.join(ciphers) or '-'}",
            f"  groups (sample): {', '.join(groups) or '-'}",
        ]
    )


def wrapper_env_debug_text(repo: Path, backends: list[str]) -> str:
    active = frozenset(backends)
    lines = ["=== Orchestration environment ==="]
    merged = merged_orchestration_env(active)
    if merged:
        for key in sorted(merged):
            lines.append(f"{key}={merged[key]}")
    else:
        lines.append("(no merged orchestration env)")
    for backend in sorted(active):
        lines.append(f"--- {backend} session_wrapper_env ---")
        env = session_wrapper_env(backend, repo, active)
        if env:
            for key in sorted(env):
                lines.append(f"{key}={env[key]}")
        else:
            lines.append("(empty)")
    return "\n".join(lines)


def tls_config_debug_text(label: str, cfg: interop_pb2.TlsConfig) -> str:
    cert_b = getattr(cfg, "certificate", None) or b""
    key_b = getattr(cfg, "private_key", None) or b""
    lines = [
        f"=== {label} TlsConfig ===",
        f"version: {cfg.version or '-'}",
        f"cipher_suite: {cfg.cipher_suite or '-'}",
        f"port: {cfg.port}",
        f"server_hostname: {cfg.server_hostname or '-'}",
        f"supported_groups: {', '.join(cfg.supported_groups) or '-'}",
        f"signature_schemes: {', '.join(cfg.signature_schemes) or '-'}",
        f"signature_schemes_cert: {', '.join(cfg.signature_schemes_cert) or '-'}",
        f"alpn_protocols: {', '.join(cfg.alpn_protocols) or '-'}",
        f"supported_versions: {', '.join(cfg.supported_versions) or '-'}",
        f"psk_modes / test_features: {', '.join(cfg.psk_modes) or '-'}",
        f"resumption_step: {cfg.resumption_step or '-'}",
        f"repo_root: {cfg.repo_root or '-'}",
        f"certificate inline: {'yes (' + str(len(cert_b)) + ' bytes)' if cert_b.strip() else 'no'}",
        f"private_key inline: {'yes (' + str(len(key_b)) + ' bytes)' if key_b.strip() else 'no'}",
        f"ca_file: {cfg.ca_file or '-'}",
        f"ca_path: {cfg.ca_path or '-'}",
        f"session_tickets_enabled: {cfg.session_tickets_enabled}",
        f"enable_early_data: {cfg.enable_early_data}",
        f"prefer_server_ciphers: {cfg.prefer_server_ciphers}",
        f"record_size_limit: {cfg.record_size_limit or '-'}",
        f"max_fragment_length: {cfg.max_fragment_length or '-'}",
        f"ocsp_stapling: {cfg.ocsp_stapling}",
        f"renegotiation: {cfg.renegotiation or '-'}",
        f"post_handshake_auth: {cfg.post_handshake_auth}",
        f"expect_hrr: {cfg.expect_hrr}",
    ]
    return "\n".join(lines)


@dataclass
class OpTrace:
    label: str
    status: int
    message: str
    logs: str
    negotiated: interop_pb2.NegotiatedTlsParameters | None = None
    output_data: bytes = b""


def format_op_trace(trace: OpTrace) -> str:
    status_map = {
        interop_pb2.OperationResponse.SUCCESS: "SUCCESS",
        interop_pb2.OperationResponse.FAILURE: "FAILURE",
        interop_pb2.OperationResponse.ERROR: "ERROR",
    }
    status_name = status_map.get(trace.status, str(trace.status))
    parts = [f"--- {trace.label} (status={status_name}) ---"]
    if trace.message:
        parts.append(f"message: {trace.message}")
    if trace.negotiated is not None:
        parts.append(f"negotiated: {negotiated_debug_text(trace.negotiated)}")
    if trace.output_data:
        parts.append("output_data:")
        parts.append(format_output_data(trace.output_data))
    if trace.logs:
        parts.append(trace.logs)
    return "\n".join(parts)


def prepare_debug_run_dir(repo: Path) -> Path:
    """Create ``debug_logs/run_<timestamp>/`` for one matrix invocation."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = repo / "debug_logs" / f"run_{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


class DebugRunLogs:
    """Lazy debug log directory: created on first FAIL, omitted when all cells pass."""

    def __init__(self, repo: Path) -> None:
        self.repo = repo
        self._dir: Path | None = None

    @property
    def ready(self) -> bool:
        return self._dir is not None

    @property
    def path(self) -> Path | None:
        return self._dir

    def ensure_dir(self) -> Path:
        if self._dir is None:
            self._dir = prepare_debug_run_dir(self.repo)
        return self._dir


def _unique_log_path(run_dir: Path, basename: str) -> Path:
    path = run_dir / basename
    if not path.exists():
        return path
    stem = basename[:-4] if basename.endswith(".log") else basename
    for i in range(2, 1000):
        alt = run_dir / f"{stem}_{i}.log"
        if not alt.exists():
            return alt
    return run_dir / f"{stem}_dup.log"


def write_cell_debug_log(
    repo: Path,
    *,
    server: str,
    client: str,
    server_conf: interop_pb2.TlsConfig,
    client_conf: interop_pb2.TlsConfig,
    driver: InteropDriver,
    debug_logs: DebugRunLogs,
    cell: MatrixCell | None = None,
    tcp_host: str = "",
    tcp_port: int = 0,
    extra_error: str = "",
    result_kind: str = "FAIL",
) -> Path:
    """Write one cell log into the run's debug directory; return the log file path."""
    debug_run_dir = debug_logs.ensure_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    kind = (result_kind or "FAIL").strip().upper()
    path = _unique_log_path(
        debug_run_dir, cell_log_basename(server, client, cell, kind=kind)
    )
    parts: list[str] = [
        f"TLS interop {kind} log",
        f"timestamp: {ts}",
        f"server: {server}",
        f"client: {client}",
    ]
    if cell:
        parts.append(
            "matrix_cell: "
            + ", ".join(
                f"{k}={v}"
                for k, v in sorted(cell.to_mapping().items())
                if str(v).strip()
            )
        )
    if driver._last_failure:
        label, status, detail = driver._last_failure
        parts.append(f"last_failure: label={label} status={status}")
        parts.append(f"last_failure_summary: {detail}")
    if extra_error:
        parts.append(f"extra_error: {extra_error}")
    parts.append("")
    parts.append("=== Endpoints ===")
    parts.append(f"gRPC server: {driver.server_addr}")
    parts.append(f"gRPC client: {driver.client_addr}")
    if tcp_host or tcp_port:
        parts.append(f"TCP check (post-ESTABLISH): {tcp_host}:{tcp_port}")
    parts.append("")
    parts.append("=== Wrapper metadata ===")
    parts.append(metadata_debug_text("server", driver.server_metadata))
    parts.append(metadata_debug_text("client", driver.client_metadata))
    parts.append("")
    parts.append(wrapper_env_debug_text(repo, sorted({server, client})))
    parts.append("")
    parts.append(tls_config_debug_text("SERVER", server_conf))
    parts.append("")
    parts.append(tls_config_debug_text("CLIENT", client_conf))
    parts.append("")
    parts.append("=== Operation traces ===")
    if driver._op_traces:
        for trace in driver._op_traces:
            parts.append(format_op_trace(trace))
            parts.append("")
    else:
        parts.append("(no gRPC operation traces captured)")
    path.write_text("\n".join(parts).rstrip() + "\n", encoding="utf-8")
    return path


def write_fail_debug_log(
    repo: Path,
    *,
    server: str,
    client: str,
    server_conf: interop_pb2.TlsConfig,
    client_conf: interop_pb2.TlsConfig,
    driver: InteropDriver,
    debug_logs: DebugRunLogs,
    cell: MatrixCell | None = None,
    tcp_host: str = "",
    tcp_port: int = 0,
    extra_error: str = "",
) -> Path:
    return write_cell_debug_log(
        repo,
        server=server,
        client=client,
        server_conf=server_conf,
        client_conf=client_conf,
        driver=driver,
        debug_logs=debug_logs,
        cell=cell,
        tcp_host=tcp_host,
        tcp_port=tcp_port,
        extra_error=extra_error,
        result_kind="FAIL",
    )

"""Pre-run cell skip reasons and backend CLI parameter conflict checks."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.catalog import (
    BackendCapabilities, TLS13_ORTHOGONAL_DIMS, TlsMode, asymmetric_role_part,
    capability_dimension_name, load_backend_capabilities, parse_asymmetric,
    split_csv_tokens, tls_argv_for_config, tls_mode_from_version)
from core.features import (
    cipher_catalog_id_requires_identity_pem, cipher_required_test_feature,
    parse_test_features_enabled, tls12_group_semantic_skip, tls12_sig_semantic_skip)
from core.matrix import cell_cipher_id, effective_cell_tls_mode


def _check_cipher_side(
    cell: dict[str, str], server: bool, wrapper: str, caps: dict[str, Any], mode: TlsMode) -> str | None:
    cipher_id = cell_cipher_id(cell, server=server)
    if not cipher_id:
        return None

    bc = BackendCapabilities(caps)
    if bc.supports_cipher(cipher_id, mode):
        return None

    modes = bc.cipher_modes(cipher_id)
    if not modes:
        return f"{wrapper} lacks cipher_suite={cipher_id!r}"

    modes_str = ", ".join(sorted(modes))
    return f"{wrapper} lacks cipher_suite={cipher_id!r} for TLS {mode} (supported modes: {modes_str})"


def _check_list_dim(
    cell: dict[str, str], dim: str, server: bool, wrapper: str, caps: dict[str, Any], mode: TlsMode) -> str | None:
    if mode == "1.2" and dim in TLS13_ORTHOGONAL_DIMS:
        raw_val = (cell.get(dim) or "").strip()
        if not raw_val:
            return None

    tokens = split_csv_tokens(asymmetric_role_part(cell.get(dim), server=server))
    if not tokens:
        return None

    cap_dim = capability_dimension_name(dim)
    bc = BackendCapabilities(caps)
    for tok in tokens:
        if not bc.supports_token(cap_dim, tok, tls_mode=mode):
            return f"{wrapper} lacks {dim}={tok!r}"

    return None


def _required_server_identity_prefix(cell: dict[str, str]) -> str | None:
    from core.identity import get_cert_prefix_for_scheme, get_cert_prefix_for_schemes

    schemes = split_csv_tokens(asymmetric_role_part(cell.get("signature_schemes"), server=True))
    if schemes:
        return get_cert_prefix_for_schemes(schemes)

    cipher = cell_cipher_id(cell, server=True)
    if not cipher or not cipher_catalog_id_requires_identity_pem(cipher):
        return None

    return get_cert_prefix_for_scheme(cipher)


def _tls12_semantic_skip_reason_side(cell: dict[str, str], server: bool, mode: TlsMode) -> str | None:
    if mode != "1.2":
        return None

    cipher_id = cell_cipher_id(cell, server=server)
    if not cipher_id:
        return None

    grp_tokens = split_csv_tokens(asymmetric_role_part(cell.get("supported_groups"), server=server))
    sig_tokens = split_csv_tokens(asymmetric_role_part(cell.get("signature_schemes"), server=server))

    return (
        tls12_group_semantic_skip(cipher_id, grp_tokens)
        or tls12_sig_semantic_skip(cipher_id, sig_tokens))


@dataclass(frozen=True)
class _CellSkipCtx:
    cell: dict[str, str]
    repo: Path
    server: str
    client: str
    srv_caps: dict[str, Any]
    cli_caps: dict[str, Any]
    mode_srv: TlsMode
    mode_cli: TlsMode


def _feature_entry_skip(
    feat: str, role_label: str, caps: dict[str, Any], wired_msg: str | None = None) -> str | None:
    entry = BackendCapabilities(caps).feature_entry(feat)
    if not entry.get("wired", False):
        return wired_msg or f"Feature {feat} is not wired in {role_label} wrapper"
    if not entry.get("supported", False):
        return f"Feature {feat} is not supported in {role_label} wrapper"

    return None


def _semantic_skip_reason(ctx: _CellSkipCtx) -> str | None:
    return (
        _tls12_semantic_skip_reason_side(ctx.cell, server=True, mode=ctx.mode_srv)
        or _tls12_semantic_skip_reason_side(ctx.cell, server=False, mode=ctx.mode_cli))


def _enabled_features_skip_reason(
    enabled: frozenset[str], roles: tuple[tuple[str, dict[str, Any]], ...]) -> str | None:
    for feat in sorted(enabled):
        for role_label, caps in roles:
            reason = _feature_entry_skip(feat, role_label, caps)
            if reason:
                return reason
    return None


def _cipher_required_feature_skip_reason(
    ctx: _CellSkipCtx, enabled: frozenset[str], roles: tuple[tuple[str, dict[str, Any]], ...]) -> str | None:
    cid = cell_cipher_id(ctx.cell, server=True) or cell_cipher_id(ctx.cell, server=False)
    if not cid:
        return None
    feat = cipher_required_test_feature(cid)
    if not feat:
        return None
    if feat not in enabled:
        return "Feature disabled"
    for role_label, caps in roles:
        reason = _feature_entry_skip(feat, role_label, caps, wired_msg="Not wired")
        if reason:
            return reason
    return None


def _feature_skip_reason(ctx: _CellSkipCtx) -> str | None:
    roles = (
        (f"server ({ctx.server})", ctx.srv_caps),
        (f"client ({ctx.client})", ctx.cli_caps))
    enabled = parse_test_features_enabled(str(ctx.cell.get("test_features") or ""))
    return (
        _enabled_features_skip_reason(enabled, roles)
        or _cipher_required_feature_skip_reason(ctx, enabled, roles))


def _identity_skip_reason(ctx: _CellSkipCtx) -> str | None:
    from core.identity import identity_pem_present

    prefix = _required_server_identity_prefix(ctx.cell)
    if not prefix or identity_pem_present(prefix, repo=ctx.repo):
        return None

    return f"Missing identity PEM: certs/{prefix}.crt and certs/{prefix}.key"


def _expect_hrr_skip_reason(ctx: _CellSkipCtx) -> str | None:
    if (ctx.cell.get("expect_hrr") or "").strip().lower() not in ("true", "1", "yes"):
        return None

    unsupported = BackendCapabilities(ctx.cli_caps).runtime().get("unsupported_tls_fields") or ()
    blocked = frozenset(str(x).strip() for x in unsupported)
    if "expect_hrr" in blocked:
        return f"client ({ctx.client}) does not support expect_hrr"

    return None


def _cipher_skip_reason(ctx: _CellSkipCtx) -> str | None:
    return (
        _check_cipher_side(
            ctx.cell, server=True, wrapper=f"server ({ctx.server})", caps=ctx.srv_caps, mode=ctx.mode_srv)
        or _check_cipher_side(
            ctx.cell, server=False, wrapper=f"client ({ctx.client})", caps=ctx.cli_caps, mode=ctx.mode_cli))


def _dimension_skip_reason(ctx: _CellSkipCtx) -> str | None:
    for dim in ("supported_groups", "signature_schemes", "alpn"):
        reason = (
            _check_list_dim(
                ctx.cell, dim, server=True, wrapper=f"server ({ctx.server})",
                caps=ctx.srv_caps, mode=ctx.mode_srv)
            or _check_list_dim(
                ctx.cell, dim, server=False, wrapper=f"client ({ctx.client})",
                caps=ctx.cli_caps, mode=ctx.mode_cli))
        if reason:
            return reason

    return None


def _tls_version_skip_reason(ctx: _CellSkipCtx) -> str | None:
    tv = (ctx.cell.get("tls_version") or "").strip()
    if not tv or ":" in tv:
        return None

    wrappers = (
        (f"server ({ctx.server})", ctx.srv_caps, ctx.mode_srv),
        (f"client ({ctx.client})", ctx.cli_caps, ctx.mode_cli))
    for wrapper, caps, mode in wrappers:
        block = caps.get("tls_version")
        if isinstance(block, dict) and block:
            key = "1.2" if mode == "1.2" else "1.3"
            if key not in block:
                return f"{wrapper} lacks tls_version={key!r}"

    return None


def _resolve_cell_tls_modes(
    cell: dict[str, str], srv_caps: dict[str, Any], cli_caps: dict[str, Any]) -> tuple[TlsMode, TlsMode]:
    mode_srv = effective_cell_tls_mode(cell, srv_caps, cli_caps)
    mode_cli = mode_srv
    tv = (cell.get("tls_version") or "").strip()
    if tv and ":" in tv:
        lv, rv = parse_asymmetric(tv)
        if lv:
            mode_srv = tls_mode_from_version(lv)
        if rv:
            mode_cli = tls_mode_from_version(rv)
    return mode_srv, mode_cli


CELL_SKIP_CHECKS = (
    _semantic_skip_reason, _feature_skip_reason, _identity_skip_reason, _expect_hrr_skip_reason,
    _cipher_skip_reason, _dimension_skip_reason, _tls_version_skip_reason)


def cell_capability_skip_reason(cell: dict[str, str], repo: Path) -> str | None:
    server = (cell.get("server") or "").strip().lower()
    client = (cell.get("client") or "").strip().lower()
    if not server or not client:
        return None

    try:
        srv_caps = load_backend_capabilities(server).raw
        cli_caps = load_backend_capabilities(client).raw
    except (FileNotFoundError, ValueError) as exc:
        return str(exc)

    mode_srv, mode_cli = _resolve_cell_tls_modes(cell, srv_caps, cli_caps)
    ctx = _CellSkipCtx(
        cell=cell, repo=repo, server=server, client=client,
        srv_caps=srv_caps, cli_caps=cli_caps, mode_srv=mode_srv, mode_cli=mode_cli)
    for check in CELL_SKIP_CHECKS:
        if reason := check(ctx):
            return reason
    return None


def _iterable_field_has_value(raw: Any) -> bool:
    return any(str(x).strip() for x in raw)


def _config_has_value(config: Any, field: str) -> bool:
    raw = getattr(config, field, None)
    if raw is None:
        return False
    if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes, bytearray)):
        return _iterable_field_has_value(raw)
    if isinstance(raw, Iterable) and not isinstance(raw, (str, bytes, bytearray, dict)):
        return _iterable_field_has_value(raw)
    if isinstance(raw, bytes):
        return bool(raw.strip())
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return raw != 0
    return bool(str(raw).strip())


def unsupported_cli_params(config: Any, backend: str, repo: Path | None = None) -> list[str]:
    key = (backend or "").strip().lower()
    runtime_info = load_backend_capabilities(key).runtime()
    extra_fields = runtime_info.get("unsupported_tls_fields") or ()

    if not isinstance(extra_fields, (list, tuple)):
        return []

    bad: list[str] = []
    for field in extra_fields:
        name = str(field).strip()
        if name and _config_has_value(config, name):
            bad.append(name)

    return bad


def catalog_parameter_conflicts(
    config: Any, backend: str, role: Any | None = None, capabilities: dict[str, Any] | None = None, repo: Path | None = None) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []

    for item in unsupported_cli_params(config, backend, repo):
        if item not in seen:
            seen.add(item)
            output.append(item)

    if capabilities:
        for item in tls_argv_for_config(config, backend, capabilities, role=role).unsupported:
            if item not in seen:
                seen.add(item)
                output.append(item)

    return output

"""CLI/matrix validation, TLS version helpers, and cell capability skip reasons."""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal

from core.capabilities import(ASYMMETRIC_SCALAR_OPTION_IDS, MULTI_VALUE_OPTION_IDS,
    NON_TLS_OPTION_IDS, TlsMode, backend_cipher_modes, backend_supports_cipher, backend_supports_token,
    capability_dimension_name, cipher_catalog_id_requires_identity_pem, cipher_required_test_feature,
    enabled_test_features_from_cell, load_capabilities, load_options_catalog, option_choice_tokens,
    parse_test_features_enabled, repository_root, test_feature_supported, test_feature_wired,
    tls_argv_for_config, wrapper_runtime_config)
from core.matrix_cell import MatrixCell
from core.tls_config_view import RoleLike, TlsConfigInput


from core.utils import(asymmetric_role_part, norm_token, parse_asymmetric, split_csv_tokens)


def tls_mode_from_version(version: str | None) -> TlsMode:
    if not (version or "").strip():
        return "1.3"
    folded = norm_token((version or "").replace(".", ""))
    if "13" in folded:
        return "1.3"
    if "12" in folded:
        return "1.2"
    return "1.3"


def tls_version_forces_12(tok: str) -> bool:
    return tls_mode_from_version(tok) == "1.2"


def tls_version_to_capability_name(version_str: str | None) -> str:
    if version_str is None or str(version_str).strip() == "":
        return "TLS1.3"
    if tls_mode_from_version(str(version_str)) == "1.2":
        return "TLS1.2"
    return "TLS1.3"


def tls_mode_filter_from_args(args: Any) -> TlsMode | None:
    """
    When ``args.tls_version`` is a single protocol version, return ``1.2`` or ``1.3``.

    Returns ``None`` if unset or asymmetric (``1.3:1.2``) so cipher expansion stays broad
    and per-cell skip/normalize handles mismatches.
    """
    raw = str(getattr(args, "tls_version", "") or "").strip()
    if not raw:
        return None
    if ":" in raw:
        left, right = parse_asymmetric(raw)
        if left and right and tls_mode_from_version(left) == tls_mode_from_version(right):
            return tls_mode_from_version(left)
        return None
    return tls_mode_from_version(raw)


def parse_csv_values(raw: str, arg_name: str) -> list[str]:
    if not raw:
        return []
    values = [part.strip() for part in raw.split(",")]
    if any(not v for v in values):
        raise ValueError(f"{arg_name} must be a comma-separated list of non-empty values")
    return values


def _config_has_value(config: TlsConfigInput, field: str) -> bool:
    raw = getattr(config, field, None)
    if raw is None:
        return False
    if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes, bytearray)):
        return any(str(x).strip() for x in raw)
    if isinstance(raw, Iterable) and not isinstance(raw, (str, bytes, bytearray, dict)):
        return any(str(x).strip() for x in raw)
    if isinstance(raw, bytes):
        return bool(raw.strip())
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return raw != 0
    return bool(str(raw).strip())


def unsupported_cli_params(config: TlsConfigInput, backend: str, repo: Path | None = None) -> list[str]:
    """
    Return unsupported non-empty ``TlsConfig`` fields for a backend CLI.

    Declared per wrapper in ``capabilities.json`` → ``runtime.unsupported_tls_fields``.
    """
    key = (backend or "").strip().lower()
    rt = wrapper_runtime_config(key, repo)
    extra = rt.get("unsupported_tls_fields") or ()
    if not isinstance(extra, (list, tuple)):
        return []
    bad: list[str] = []
    for field in extra:
        name = str(field).strip()
        if name and _config_has_value(config, name):
            bad.append(name)
    return bad


def catalog_parameter_conflicts(config: TlsConfigInput, backend: str, *, role: RoleLike | None = None,
    capabilities: dict[str, Any] | None = None, repo: Path | None = None) -> list[str]:
    """
    Union of ``unsupported_cli_params`` and capability-translator unsupported
    entries (deduplicated, stable order).
    """
    seen: set[str] = set()
    out: list[str] = []
    for item in unsupported_cli_params(config, backend, repo):
        if item not in seen:
            seen.add(item)
            out.append(item)
    if capabilities:
        for item in tls_argv_for_config(config, backend, capabilities, role=role).unsupported:
            if item not in seen:
                seen.add(item)
                out.append(item)
    return out


def run_args_tls_config_view(args: Any, *, server: bool) -> SimpleNamespace:
    """Build a TlsConfig-like view from host CLI ``args`` for one matrix role."""

    def pick_scalar(field: str) -> str:
        raw = getattr(args, field, None)
        if raw in (None, "", 0):
            return ""
        s = str(raw).strip()
        if ":" in s and field in ASYMMETRIC_SCALAR_OPTION_IDS:
            left, right = parse_asymmetric(s)
            return left if server else right
        return s

    def pick_list(field: str) -> list[str]:
        raw = getattr(args, field, None)
        if raw in (None, "", 0):
            return []
        return split_csv_tokens(asymmetric_role_part(str(raw), server=server))

    version = pick_scalar("tls_version") or "1.3"
    return SimpleNamespace(version=version, cipher_suite=pick_scalar("cipher_suite"),
        supported_groups=pick_list("supported_groups"),
        signature_schemes=pick_list("signature_schemes"),
        alpn_protocols=pick_list("alpn"),
        psk_modes=sorted(parse_test_features_enabled(",".join(pick_list("test_features")))))


def _coerce_cipher_tls13_only(cipher_side: str, ver_side: str, caps: dict[str, Any]) -> str | None:
    from core.capabilities import is_cipher_tls13_only

    if not tls_version_forces_12(ver_side):
        return None
    cid = (cipher_side or "").strip()
    if not cid:
        return None
    if is_cipher_tls13_only(caps, cid):
        return "1.3"
    return None


def coerce_tls_version_for_cipher_capabilities(args: Any, repo: Path | None = None) -> None:
    """
    If ``--tls-version`` pins TLS 1.2 but the cipher exists only under ``tls13`` in
    the active server/client capabilities, bump version to 1.3 for that side.
    """
    cs_raw = getattr(args, "cipher_suite", None)
    tv_raw = getattr(args, "tls_version", None)
    if cs_raw in (None, "", 0) or tv_raw in (None, "", 0):
        return
    cs_s = str(cs_raw).strip()
    tv_s = str(tv_raw).strip()
    if not cs_s or not tv_s:
        return

    root = repo or repository_root()
    server = (getattr(args, "server", None) or "").strip().lower()
    client = (getattr(args, "client", None) or "").strip().lower()
    try:
        srv_caps = load_capabilities(server, root) if server else {}
        cli_caps = load_capabilities(client, root) if client else {}
    except (FileNotFoundError, ValueError):
        return

    def _pair(cipher_side: str, ver_side: str, caps: dict[str, Any]) -> str | None:
        return _coerce_cipher_tls13_only(cipher_side, ver_side, caps)

    warn = ("[catalog] TLS 1.3-only cipher with --tls-version 1.2: ",
        "adjusting protocol version to 1.3 to avoid handshake mismatch.")

    if ":" in cs_s and ":" in tv_s:
        lc, rc = cs_s.split(":", 1)
        lv, rv = tv_s.split(":", 1)
        nl = _pair(lc.strip(), lv.strip(), srv_caps)
        nr = _pair(rc.strip(), rv.strip(), cli_caps)
        if nl or nr:
            print(warn, file=sys.stderr)
            setattr(args, "tls_version", f"{nl or lv.strip()}:{nr or rv.strip()}")
        return
    if ":" in tv_s:
        lv, rv = tv_s.split(":", 1)
        nl = _pair(cs_s, lv.strip(), srv_caps)
        nr = _pair(cs_s, rv.strip(), cli_caps)
        if nl or nr:
            print(warn, file=sys.stderr)
            setattr(args, "tls_version", f"{nl or lv.strip()}:{nr or rv.strip()}")
        return
    if ":" in cs_s:
        lc, rc = cs_s.split(":", 1)
        n1 = _pair(lc.strip(), tv_s, srv_caps)
        n2 = _pair(rc.strip(), tv_s, cli_caps)
        if n1 or n2:
            print(warn, file=sys.stderr)
            setattr(args, "tls_version", f"{n1 or tv_s}:{n2 or tv_s}")
        return
    caps = srv_caps if server and not client else cli_caps
    if server and client:
        modes = backend_cipher_modes(srv_caps, cs_s) | backend_cipher_modes(cli_caps, cs_s)
        if "1.3" in modes and "1.2" not in modes:
            caps = srv_caps
        else:
            caps = srv_caps
    n = _pair(cs_s, tv_s, caps)
    if n:
        print(warn, file=sys.stderr)
        setattr(args, "tls_version", n)


def _validate_wrapper_config_conflicts(args: Any, *, known_wrappers: frozenset[str]) -> None:
    from interop_proto import interop_pb2

    for attr, role in (("server", interop_pb2.SERVER), ("client", interop_pb2.CLIENT)):
        wid = (getattr(args, attr, None) or "").strip().lower()
        if not wid or wid not in known_wrappers:
            continue
        caps = load_capabilities(wid)
        view = run_args_tls_config_view(args, server=(role == interop_pb2.SERVER))
        conflicts = catalog_parameter_conflicts(view, wid, role=role, capabilities=caps)
        if conflicts:
            raise ValueError(f"{attr} wrapper {wid!r} cannot apply requested parameter(s): "
                f"{', '.join(conflicts)}")


def _validate_cipher_suite_for_tls_version(args: Any, *,
    known_wrappers: frozenset[str], repo: Path | None = None) -> None:
    """Reject explicit ``--cipher-suite`` tokens that exist only for another TLS version."""
    from core.capabilities import load_capabilities_cache, union_cipher_suite_ids_for_wrappers
    from core.matrix import expand_dimension

    mode = tls_mode_filter_from_args(args)
    if mode is None:
        return
    raw = str(getattr(args, "cipher_suite", "") or "").strip()
    if not raw or re.match(r"(?is)^ALL", raw):
        return

    root = repo or repository_root()
    wr = sorted(known_wrappers)
    active: set[str] = set()
    for token in (str(args.server or ""), str(args.client or "")):
        t = token.strip()
        if not t:
            continue
        if re.match(r"(?is)^ALL", t):
            active |= set(wr)
        else:
            for part in expand_dimension(t, wr):
                if part in known_wrappers:
                    active.add(part)
    if not active:
        active = set(wr)

    caps_cache = load_capabilities_cache(active, root)
    allowed = set(union_cipher_suite_ids_for_wrappers(caps_cache, sorted(active), mode=mode))

    def _check_part(part: str) -> None:
        p = (part or "").strip()
        if not p or p in allowed:
            return
        raise ValueError(f"--cipher-suite {p!r} is not available for TLS {mode} "
            f"(see tls{mode.replace('.', '')} in capabilities.json)")

    if ":" in raw:
        left, right = raw.split(":", 1)
        for part in parse_csv_values(left, "--cipher-suite"):
            _check_part(part)
        for part in parse_csv_values(right, "--cipher-suite"):
            _check_part(part)
    else:
        for part in expand_dimension(raw, sorted(allowed)):
            _check_part(part)


def validate_run_args(args: Any, *, known_wrappers: frozenset[str], repo: Path | None = None) -> None:
    if args.server not in known_wrappers:
        raise ValueError(f"Unknown --server '{args.server}'. Known: {sorted(known_wrappers)}")
    if args.client not in known_wrappers:
        raise ValueError(f"Unknown --client '{args.client}'. Known: {sorted(known_wrappers)}")
    if not (0 <= int(args.tls_port) <= 65535):
        raise ValueError("--tls-port must be in range 0..65535")
    for attr in ("server_grpc_port", "client_grpc_port"):
        if not (0 <= int(getattr(args, attr, 0) or 0) <= 65535):
            raise ValueError(f"--{attr.replace('_', '-')} must be in range 0..65535")

    for item in load_options_catalog(repo):
        option_id = item["id"]
        if option_id in NON_TLS_OPTION_IDS:
            continue
        value = getattr(args, option_id, None)
        if value in (None, "", 0):
            continue
        if option_id == "tls_port" and int(value) == 0:
            continue

        arg_name = f"--{option_id.replace('_', '-')}"
        choices = item.get("choices") or []

        if option_id in MULTI_VALUE_OPTION_IDS:
            raw = str(value).strip()
            if ":" in raw:
                left_s, right_s = parse_asymmetric(raw)
                values = parse_csv_values(left_s, arg_name) + parse_csv_values(right_s, arg_name)
            else:
                values = parse_csv_values(raw, arg_name)
            if choices:
                tokens = option_choice_tokens(item)
                unknown = sorted(x for x in values if x not in tokens)
                if unknown:
                    raise ValueError(f"{arg_name} unknown value(s): {', '.join(unknown)}. "
                        f"Known: {', '.join(tokens)}")
            continue
        if not choices:
            continue

        if option_id in ASYMMETRIC_SCALAR_OPTION_IDS:
            tokens = option_choice_tokens(item)
            for part in parse_asymmetric(str(value)):
                if part and part not in tokens:
                    raise ValueError(f"{arg_name} must use catalog values; unknown: {part!r}. ",
                        f"Known: {', '.join(tokens)}")
        elif str(value).strip() not in option_choice_tokens(item):
            raise ValueError(f"{arg_name} must be one of: {', '.join(option_choice_tokens(item))}")

    coerce_tls_version_for_cipher_capabilities(args, repo)
    _validate_cipher_suite_for_tls_version(args, known_wrappers=known_wrappers, repo=repo)
    _validate_wrapper_config_conflicts(args, known_wrappers=known_wrappers)


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


def _split_cell_list_tokens(cell: MatrixCell, field: str, *, server: bool) -> list[str]:
    return cell.list_tokens(field, server=server)


def _cell_cipher_id(cell: MatrixCell, *, server: bool) -> str:
    return cell.cipher_id(server=server)


def _signature_scheme_auth_kind(token: str) -> Literal["rsa", "ecdsa", "dsa", "eddsa", "unknown"]:
    t = (token or "").strip().lower().replace("_", "").replace("-", "")
    if not t:
        return "unknown"
    if t.startswith("dsa") or t == "dsa":
        return "dsa"
    if t.startswith("rsa") or "rsa" in t:
        return "rsa"
    if t.startswith("ecdsa") or "ecdsa" in t:
        return "ecdsa"
    if t.startswith("ed25519") or t.startswith("ed448") or t.startswith("eddsa"):
        return "eddsa"
    return "unknown"


def _group_family(token: str) -> Literal["ec", "ffdhe", "other"]:
    t = (token or "").strip().lower().replace("_", "-")
    if not t:
        return "other"
    if t.startswith("ffdhe"):
        return "ffdhe"
    if (t.startswith("secp") or t.startswith("x25519") or t.startswith("x448") or t.startswith("brainpool")
        or t.startswith("xyber") or t.startswith("mlkem") or "mlkem" in t):
        return "ec"
    return "other"


def _tls12_semantic_skip_reason_side(cell: MatrixCell, *, server: bool, mode: TlsMode) -> str | None:
    if mode != "1.2":
        return None
    cipher_id = _cell_cipher_id(cell, server=server)
    if not cipher_id:
        return None
    meta = tls12_cipher_metadata_from_name(cipher_id)
    grp_tokens = _split_cell_list_tokens(cell, "supported_groups", server=server)
    if grp_tokens and meta.kx == "static-rsa":
        return "TLS 1.2 static RSA cipher does not support groups"
    if grp_tokens and meta.kx == "ecdhe":
        for grp in grp_tokens:
            fam = _group_family(grp)
            if fam != "ec":
                return "TLS 1.2 ECDHE cipher requires EC groups (secp*/x25519/x448)"
    if grp_tokens and meta.kx == "dhe":
        for grp in grp_tokens:
            fam = _group_family(grp)
            if fam != "ffdhe":
                return "TLS 1.2 DHE cipher requires FFDHE groups"

    sig_tokens = _split_cell_list_tokens(cell, "signature_schemes", server=server)
    if not sig_tokens or meta.au == "unknown":
        return None
    for sig in sig_tokens:
        sk = _signature_scheme_auth_kind(sig)
        if sk == "unknown":
            continue
        if meta.au == "rsa" and sk != "rsa":
            return "Signature scheme type conflicts with TLS 1.2 cipher authentication"
        if meta.au == "ecdsa" and sk != "ecdsa":
            return "Signature scheme type conflicts with TLS 1.2 cipher authentication"
        if meta.au == "dsa" and sk != "dsa":
            return "Signature scheme type conflicts with TLS 1.2 cipher authentication"
    return None


def _check_cipher_side(cell: MatrixCell, *, server: bool,
    wrapper: str, caps: dict[str, Any], mode: TlsMode) -> str | None:
    cid = _cell_cipher_id(cell, server=server)
    if not cid:
        return None
    if backend_supports_cipher(caps, cid, mode):
        return None
    modes = backend_cipher_modes(caps, cid)
    if not modes:
        return f"{wrapper} lacks cipher_suite={cid!r}"
    return (f"{wrapper} lacks cipher_suite={cid!r} for TLS {mode} "
        f"(supported modes: {', '.join(sorted(modes))})")


def _check_list_dim(cell: MatrixCell, dim: str, *, server: bool,
    wrapper: str, caps: dict[str, Any], mode: TlsMode) -> str | None:
    from core.capabilities import TLS13_ORTHOGONAL_DIMS

    if mode == "1.2" and dim in TLS13_ORTHOGONAL_DIMS:
        raw = (getattr(cell, dim, "") or "").strip()
        if not raw:
            return None
    tokens = _split_cell_list_tokens(cell, dim, server=server)
    if not tokens:
        return None
    cap_dim = capability_dimension_name(dim)
    for tok in tokens:
        if not backend_supports_token(caps, cap_dim, tok, mode=mode):
            return f"{wrapper} lacks {dim}={tok!r}"
    return None


def _required_server_identity_prefix(cell: MatrixCell) -> str | None:
    """``certs/`` filename prefix the server needs for this matrix cell."""
    from core.identity import get_cert_prefix_for_cipher_suite, get_cert_prefix_for_schemes

    schemes = _split_cell_list_tokens(cell, "signature_schemes", server=True)
    if schemes:
        return get_cert_prefix_for_schemes(schemes)
    cipher = _cell_cipher_id(cell, server=True)
    if not cipher or not cipher_catalog_id_requires_identity_pem(cipher):
        return None
    return get_cert_prefix_for_cipher_suite(cipher)


def _cell_identity_pem_skip_reason(cell: MatrixCell, repo: Path) -> str | None:
    """Pre-run SKIP when ``certs/{prefix}.crt`` + ``.key`` are required but missing."""
    from core.identity import identity_pem_present

    prefix = _required_server_identity_prefix(cell)
    if not prefix:
        return None
    if identity_pem_present(prefix, repo=repo):
        return None
    return f"Missing identity PEM: certs/{prefix}.crt and certs/{prefix}.key"


def _cell_enabled_test_features_skip_reason(cell: MatrixCell, *, server: str,
    client: str, srv_caps: dict[str, Any], cli_caps: dict[str, Any]) -> str | None:
    """Pre-run SKIP when an enabled ``test_features`` token is unsupported on server or client."""
    for feat in sorted(enabled_test_features_from_cell(cell)):
        for role_label, caps in ((f"server ({server})", srv_caps), (f"client ({client})", cli_caps)):
            if not test_feature_wired(caps, feat):
                return f"Feature {feat} is not wired in {role_label} wrapper"
            if not test_feature_supported(caps, feat):
                return f"Feature {feat} is not supported in {role_label} wrapper"
    return None


def _cell_test_feature_skip_reason(cell: MatrixCell, *, server: str,
    client: str, srv_caps: dict[str, Any], cli_caps: dict[str, Any]) -> str | None:
    """
    Pre-run SKIP for PSK/anon cipher suites.

    Order: feature not enabled in ``test_features`` → ``Feature disabled``;
    ``wired: false`` in capabilities → ``Not wired``.
    """
    cid = _cell_cipher_id(cell, server=True) or _cell_cipher_id(cell, server=False)
    if not cid:
        return None
    feat = cipher_required_test_feature(cid)
    if not feat:
        return None
    if feat not in enabled_test_features_from_cell(cell):
        return "Feature disabled"
    for role_label, caps in ((f"server ({server})", srv_caps), (f"client ({client})", cli_caps)):
        if not test_feature_wired(caps, feat):
            return "Not wired"
        if not test_feature_supported(caps, feat):
            return f"Feature {feat} is not supported in {role_label} wrapper"
    return None


def cell_capability_skip_reason(cell: MatrixCell, repo: Path) -> str | None:
    """SKIP when server/client lack a declared token in capabilities.json."""
    server = cell.server
    client = cell.client
    if not server or not client:
        return None
    try:
        srv_caps = load_capabilities(server, repo)
        cli_caps = load_capabilities(client, repo)
    except (FileNotFoundError, ValueError) as e:
        return str(e)

    from core.matrix import effective_cell_tls_mode

    mode_srv = effective_cell_tls_mode(cell, srv_caps, cli_caps)
    mode_cli = mode_srv
    tv = (cell.tls_version or "").strip()
    if tv and ":" in tv:
        lv, rv = parse_asymmetric(tv)
        if lv:
            mode_srv = tls_mode_from_version(lv)
        if rv:
            mode_cli = tls_mode_from_version(rv)

    sem_srv = _tls12_semantic_skip_reason_side(cell, server=True, mode=mode_srv)
    if sem_srv:
        return sem_srv
    sem_cli = _tls12_semantic_skip_reason_side(cell, server=False, mode=mode_cli)
    if sem_cli:
        return sem_cli

    feat_skip = _cell_enabled_test_features_skip_reason(cell, server=server, client=client,
        srv_caps=srv_caps, cli_caps=cli_caps)
    if feat_skip:
        return feat_skip

    feat_skip = _cell_test_feature_skip_reason(cell, server=server, client=client,
        srv_caps=srv_caps, cli_caps=cli_caps)
    if feat_skip:
        return feat_skip

    id_skip = _cell_identity_pem_skip_reason(cell, repo)
    if id_skip:
        return id_skip

    for check in (_check_cipher_side(cell, server=True, wrapper=f"server ({server})", caps=srv_caps, mode=mode_srv),
        _check_cipher_side(cell, server=False, wrapper=f"client ({client})", caps=cli_caps, mode=mode_cli)):
        if check:
            return check

    for dim in ("supported_groups", "signature_schemes", "alpn"):
        for check in (_check_list_dim(cell, dim, server=True, wrapper=f"server ({server})", caps=srv_caps,
                mode=mode_srv),
            _check_list_dim(cell, dim, server=False, wrapper=f"client ({client})", caps=cli_caps, mode=mode_cli)):
            if check:
                return check

    tv_single = (cell.tls_version or "").strip()
    if tv_single and ":" not in tv_single:
        for wrapper, caps, mode in ((f"server ({server})", srv_caps, mode_srv),
            (f"client ({client})", cli_caps, mode_cli)):
            block = caps.get("tls_version")
            if isinstance(block, dict) and block:
                key = "1.2" if mode == "1.2" else "1.3"
                if key not in block:
                    return f"{wrapper} lacks tls_version={key!r}"

    return None

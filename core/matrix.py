"""Matrix axis expansion and per-cell TLS parameter normalization."""

from __future__ import annotations

import re
import sys
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from core.catalog import (
    BackendCapabilities, CAPABILITY_DIMENSIONS, DEFAULT_CIPHER_BY_TLS_MODE,
    NON_MATRIX_OPTION_IDS, NON_TLS_OPTION_IDS, TLS13_ORTHOGONAL_DIMS, TlsMode,
    build_cli_options_catalog, capability_dimension_name, load_backend_capabilities,
    option_choice_tokens, parse_asymmetric, repository_root, tls_mode_from_version)
from core.orchestration import backend_tls_endpoint


def union_cipher_suite_ids_for_wrappers(
    caps_by_wrapper: dict[str, dict[str, Any]], wrapper_ids: Sequence[str], mode: TlsMode | None = None) -> list[str]:
    keys: set[str] = set()
    for wrapper_id in wrapper_ids:
        capabilities = BackendCapabilities(caps_by_wrapper.get(wrapper_id, {}))
        keys.update(capabilities.cipher_ids(mode))

    return sorted(keys)


def default_cipher_for_tls_mode(mode: TlsMode, allowed: set[str] | frozenset[str]) -> str:
    preferred = DEFAULT_CIPHER_BY_TLS_MODE.get(mode, "")
    if preferred and preferred in allowed:
        return preferred

    return sorted(allowed)[0] if allowed else ""


def tls_mode_filter_from_args(args: Any) -> TlsMode | None:
    raw_version = str(getattr(args, "tls_version", "") or "").strip()
    if not raw_version:
        return None

    if ":" in raw_version:
        left, right = parse_asymmetric(raw_version)
        if left and right and tls_mode_from_version(left) == tls_mode_from_version(right):
            return tls_mode_from_version(left)
        return None

    return tls_mode_from_version(raw_version)


def _coerce_cipher_tls13_only(cipher_side: str, ver_side: str, caps: dict[str, Any]) -> str | None:
    if tls_mode_from_version(ver_side) != "1.2":
        return None

    cipher_id = (cipher_side or "").strip()
    if not cipher_id:
        return None

    if BackendCapabilities(caps).cipher_modes(cipher_id) == {"1.3"}:
        return "1.3"

    return None


def _coerce_asymmetric_tls_version(
    cs_str: str, tv_str: str, srv_caps: dict[str, Any], cli_caps: dict[str, Any]) -> str | None:
    cs_left, cs_right = parse_asymmetric(cs_str)
    tv_left, tv_right = parse_asymmetric(tv_str)
    new_left = _coerce_cipher_tls13_only(cs_left, tv_left, srv_caps)
    new_right = _coerce_cipher_tls13_only(cs_right, tv_right, cli_caps)

    if new_left or new_right:
        return f"{new_left or tv_left}:{new_right or tv_right}"

    return None


def load_role_capabilities(server: str, client: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    try:
        srv_caps = load_backend_capabilities(server).raw if server else {}
        cli_caps = load_backend_capabilities(client).raw if client else {}
    except (FileNotFoundError, ValueError):
        return None
    return srv_caps, cli_caps


def _apply_coerced_tls_version(args: Any, new_ver: str | None, warning_msg: str) -> None:
    if not new_ver:
        return
    print(warning_msg, file=sys.stderr)
    setattr(args, "tls_version", new_ver)


def _parse_coerce_tls_inputs(args: Any) -> tuple[str, str, str, str] | None:
    cs_raw = getattr(args, "cipher_suite", None)
    tv_raw = getattr(args, "tls_version", None)
    if cs_raw in (None, "", 0) or tv_raw in (None, "", 0):
        return None
    cs_str = str(cs_raw).strip()
    tv_str = str(tv_raw).strip()
    if not cs_str or not tv_str:
        return None
    server = (getattr(args, "server", None) or "").strip().lower()
    client = (getattr(args, "client", None) or "").strip().lower()
    return cs_str, tv_str, server, client


def coerce_tls_version_for_cipher_capabilities(args: Any, repo: Path | None = None) -> None:
    parsed = _parse_coerce_tls_inputs(args)
    if parsed is None:
        return
    cs_str, tv_str, server, client = parsed
    loaded = load_role_capabilities(server, client)
    if loaded is None:
        return
    srv_caps, cli_caps = loaded

    warning_msg = (
        "[catalog] TLS 1.3-only cipher with --tls-version 1.2: "
        "adjusting protocol version to 1.3 to avoid handshake mismatch.")

    if ":" in cs_str or ":" in tv_str:
        _apply_coerced_tls_version(
            args, _coerce_asymmetric_tls_version(cs_str, tv_str, srv_caps, cli_caps), warning_msg)
        return

    caps = srv_caps if server else cli_caps
    _apply_coerced_tls_version(
        args, _coerce_cipher_tls13_only(cs_str, tv_str, caps), warning_msg)


def _expand_all_subtraction(value: str, base_choices: list[str]) -> list[str] | None:
    match = re.match(r"(?is)^ALL\s*[\\-]\s*(.+)$", value)
    if not match:
        return None

    exclusions = {x.strip() for x in match.group(1).split(",") if x.strip()}
    output = [x for x in base_choices if x not in exclusions]
    if not output:
        raise ValueError(f"ALL minus exclusions leaves empty set: {value!r}")

    return output


def _expand_csv_dimension_tokens(val: str, base_choices: list[str]) -> list[str]:
    parts = [x.strip() for x in val.split(",") if x.strip()]
    if not parts:
        raise ValueError(f"Empty dimension value: {val!r}")
    invalid_parts = [p for p in parts if p not in base_choices]
    if invalid_parts:
        known_str = ", ".join(sorted(set(base_choices)))
        raise ValueError(f"Unknown value(s) {invalid_parts!r}; known: {known_str}")
    return parts


def _expand_dimension_all_forms(val: str, base_choices: list[str]) -> list[str] | None:
    if re.match(r"(?is)^ALL\s*$", val):
        return list(base_choices)
    return _expand_all_subtraction(val, base_choices)


def expand_dimension(value: str, choices: Sequence[str]) -> list[str]:
    base_choices = [str(c).strip() for c in choices if c and str(c).strip()]
    val = (value or "").strip()

    if not base_choices:
        return [val] if val else [""]
    if not val:
        return [""]

    special = _expand_dimension_all_forms(val, base_choices)
    if special is not None:
        return special
    if ":" in val:
        return [val]
    return _expand_csv_dimension_tokens(val, base_choices)


def expand_alpn_matrix_axis(
    value: str, wrapper_ids: Sequence[str], caps_by_wrapper: dict[str, dict[str, Any]], catalog_choices: Sequence[str]) -> list[str]:
    val = (value or "").strip()
    if not val:
        return [""]

    tokens = expand_capability_dimension(
        val, "alpn_protocols", wrapper_ids=wrapper_ids,
        caps_by_wrapper=caps_by_wrapper, catalog_choices=catalog_choices)
    if ":" in val:
        return tokens
    if not tokens or tokens == [""]:
        return [""]

    return [f"{srv}:{cli}" for srv in tokens for cli in tokens]


def _union_capability_keys(
    dimension: str, wrapper_ids: Sequence[str], caps_by_wrapper: dict[str, dict[str, Any]], cipher_mode: TlsMode | None) -> set[str]:
    if dimension == "cipher_suite" and cipher_mode is not None:
        return set(union_cipher_suite_ids_for_wrappers(
            caps_by_wrapper, wrapper_ids, mode=cipher_mode))

    keys: set[str] = set()
    for wrapper_id in wrapper_ids:
        bc = BackendCapabilities(caps_by_wrapper.get(wrapper_id, {}))
        keys.update(bc.dimension_keys(dimension, tls_mode=cipher_mode))

    return keys


def _expand_cap_dim_all_subtraction(
    value: str, dimension: str, wrapper_ids: Sequence[str], caps_by_wrapper: dict[str, dict[str, Any]], catalog_tokens: list[str], cipher_mode: TlsMode | None) -> list[str] | None:
    sub = re.match(r"(?is)^ALL\s*[\\-]\s*(.+)$", value)
    if not sub:
        return None

    exclusions = {x.strip() for x in sub.group(1).split(",") if x.strip()}
    keys = _union_capability_keys(
        dimension, wrapper_ids=wrapper_ids, caps_by_wrapper=caps_by_wrapper, cipher_mode=cipher_mode)
    if not keys:
        keys = set(catalog_tokens)

    output = sorted(k for k in keys if k not in exclusions)
    if not output:
        raise ValueError(f"ALL minus exclusions leaves empty set: {value!r}")

    return output


def _filter_expanded_cipher_suite(
    expanded: list[str], val: str, cipher_mode: TlsMode, wrapper_ids: Sequence[str], caps_by_wrapper: dict[str, dict[str, Any]]) -> list[str]:
    allowed = set(union_cipher_suite_ids_for_wrappers(caps_by_wrapper, wrapper_ids, mode=cipher_mode))
    filtered = [x for x in expanded if x in allowed]

    if filtered:
        return filtered

    if not val:
        default = default_cipher_for_tls_mode(cipher_mode, allowed=allowed)
        return [default] if default else [""]

    if not re.match(r"(?is)^ALL", val):
        return expanded if expanded else [val]

    return []


def _expand_cap_dim_all(
    dimension: str, wrapper_ids: Sequence[str], caps_by_wrapper: dict[str, dict[str, Any]], catalog_tokens: list[str], cipher_mode: TlsMode | None) -> list[str]:
    keys = _union_capability_keys(
        dimension, wrapper_ids=wrapper_ids, caps_by_wrapper=caps_by_wrapper, cipher_mode=cipher_mode)
    return sorted(keys) if keys else list(catalog_tokens)


def _expand_cap_dim_tokens(
    val: str, dimension: str, wrapper_ids: Sequence[str], caps_by_wrapper: dict[str, dict[str, Any]], catalog_tokens: list[str], cipher_mode: TlsMode | None) -> list[str]:
    if ":" in val:
        return [val]
    expanded = expand_dimension(val, catalog_tokens)
    if dimension == "cipher_suite" and cipher_mode is not None:
        return _filter_expanded_cipher_suite(
            expanded, val, cipher_mode, wrapper_ids, caps_by_wrapper)
    return expanded


def expand_capability_dimension(
    value: str, dimension: str, wrapper_ids: Sequence[str], caps_by_wrapper: dict[str, dict[str, Any]], catalog_choices: Sequence[str], tls_mode: TlsMode | None = None) -> list[str]:
    val = (value or "").strip()
    catalog_tokens = [str(c).strip() for c in catalog_choices if c and str(c).strip()]
    cipher_mode = tls_mode if dimension == "cipher_suite" else None

    if re.match(r"(?is)^ALL\s*$", val):
        return _expand_cap_dim_all(
            dimension, wrapper_ids, caps_by_wrapper, catalog_tokens, cipher_mode)

    subtracted = _expand_cap_dim_all_subtraction(
        val, dimension, wrapper_ids, caps_by_wrapper, catalog_tokens, cipher_mode)
    if subtracted is not None:
        return subtracted
    return _expand_cap_dim_tokens(
        val, dimension, wrapper_ids, caps_by_wrapper, catalog_tokens, cipher_mode)


def cell_cipher_id(cell: dict[str, str], server: bool) -> str:
    cipher_suite = (cell.get("cipher_suite") or "").strip()
    if not cipher_suite:
        return ""

    if ":" in cipher_suite:
        left, right = cipher_suite.split(":", 1)
        return (left if server else right).strip()

    return cipher_suite


def effective_cell_tls_mode(cell: dict[str, str], srv_caps: dict[str, Any], cli_caps: dict[str, Any]) -> TlsMode:
    tv = (cell.get("tls_version") or "").strip()
    if tv and ":" not in tv:
        return tls_mode_from_version(tv)

    if tv and ":" in tv:
        left, _ = parse_asymmetric(tv)
        if left:
            return tls_mode_from_version(left)

    srv_cipher = cell_cipher_id(cell, server=True)
    cli_cipher = cell_cipher_id(cell, server=False)
    modes: set[TlsMode] = set()

    for cid, caps in ((srv_cipher, srv_caps), (cli_cipher, cli_caps)):
        if cid:
            modes |= BackendCapabilities(caps).cipher_modes(cid)

    if modes == {"1.2"}:
        return "1.2"

    return "1.3"


def _implicit_tls_version_for_side(cell: dict[str, str], server: bool, caps: dict[str, Any]) -> str:
    cipher_id = cell_cipher_id(cell, server=server)
    if not cipher_id:
        return ""

    modes = BackendCapabilities(caps).cipher_modes(cipher_id)
    if modes == {"1.3"}:
        return "1.3"
    if modes == {"1.2"}:
        return "1.2"

    return ""


def _apply_implicit_tls_version(output: dict[str, str], srv_caps: dict[str, Any], cli_caps: dict[str, Any]) -> None:
    if (output.get("tls_version") or "").strip():
        return

    srv_ver = _implicit_tls_version_for_side(output, server=True, caps=srv_caps)
    cli_ver = _implicit_tls_version_for_side(output, server=False, caps=cli_caps)
    if srv_ver or cli_ver:
        if srv_ver and cli_ver and srv_ver != cli_ver:
            output["tls_version"] = f"{srv_ver}:{cli_ver}"
        else:
            output["tls_version"] = srv_ver or cli_ver


def _clear_unset_tls13_orthogonal_dims(output: dict[str, str], args_template: Any) -> None:
    for dim in TLS13_ORTHOGONAL_DIMS:
        user_raw = str(getattr(args_template, dim, "") or "").strip()
        if not user_raw:
            output[dim] = ""


def _apply_cell_tls_version_coerce(
    output: dict[str, str], server: str, client: str, repo: Path) -> None:
    coerce_ns = SimpleNamespace(
        server=server, client=client,
        cipher_suite=output.get("cipher_suite", ""), tls_version=output.get("tls_version", ""))
    coerce_tls_version_for_cipher_capabilities(coerce_ns, repo)
    bumped_ver = str(getattr(coerce_ns, "tls_version", "") or "").strip()
    if bumped_ver:
        output["tls_version"] = bumped_ver


def normalize_cell_tls_micro_params(cell: dict[str, str], args_template: Any, repo: Path) -> dict[str, str]:
    output = dict(cell)
    port = int(getattr(args_template, "tls_port", 0) or 0)
    if port:
        output["tls_port"] = str(port)

    server = (cell.get("server") or "").strip().lower()
    client = (cell.get("client") or "").strip().lower()
    loaded = load_role_capabilities(server, client)
    if loaded is None:
        return output
    srv_caps, cli_caps = loaded

    _apply_implicit_tls_version(output, srv_caps, cli_caps)
    feats = str(getattr(args_template, "test_features", "") or "").strip()
    if effective_cell_tls_mode(output, srv_caps, cli_caps) == "1.2":
        _clear_unset_tls13_orthogonal_dims(output, args_template)
    output["test_features"] = feats
    _apply_cell_tls_version_coerce(output, server, client, repo)
    return output


def _get_dimension_matrix_values(
    item: dict[str, Any], args: Any, matrix_wrappers: set[str], caps_cache: dict[str, dict[str, Any]], cipher_tls_mode: TlsMode | None) -> list[Any]:
    option_id = item["id"]
    tokens = option_choice_tokens(item) if item.get("choices") else []
    raw_val = str(getattr(args, option_id, "") or "")

    if option_id in CAPABILITY_DIMENSIONS and tokens:
        if option_id == "alpn":
            return expand_alpn_matrix_axis(
                raw_val, wrapper_ids=sorted(matrix_wrappers),
                caps_by_wrapper=caps_cache, catalog_choices=tokens)
        mode = cipher_tls_mode if option_id == "cipher_suite" else None
        return expand_capability_dimension(
            raw_val, capability_dimension_name(option_id),
            wrapper_ids=sorted(matrix_wrappers), caps_by_wrapper=caps_cache,
            catalog_choices=tokens, tls_mode=mode)

    if tokens:
        return expand_dimension(raw_val, tokens)

    return [""] if raw_val in (None, "", 0) else [str(raw_val)]


def matrix_axis_plan(
    args: Any, known_wrappers: frozenset[str], repo: Path | None = None) -> tuple[list[str], list[list[Any]]]:
    root = repo or repository_root()
    wrappers_sorted = sorted(known_wrappers)
    caps_cache = {wid: load_backend_capabilities(wid).raw for wid in known_wrappers}
    catalog = build_cli_options_catalog(root)

    keys = ["server", "client"]
    server_vals = expand_dimension(str(args.server), wrappers_sorted)
    client_vals = expand_dimension(str(args.client), wrappers_sorted)
    vals: list[list[Any]] = [server_vals, client_vals]

    matrix_wrappers = set(server_vals) | set(client_vals)
    cipher_tls_mode = tls_mode_filter_from_args(args)

    for item in sorted(catalog, key=lambda x: str(x.get("id", ""))):
        option_id = item["id"]
        if option_id in NON_TLS_OPTION_IDS or option_id == "tls_port" or option_id in NON_MATRIX_OPTION_IDS:
            continue

        keys.append(option_id)
        vals.append(_get_dimension_matrix_values(
            item, args, matrix_wrappers, caps_cache, cipher_tls_mode))

    return keys, vals


def apply_matrix_tls_endpoints(
    server: str, client: str, server_conf: Any, client_conf: Any, *, repo: Path,
    cell: dict[str, str] | None = None, session: Any | None = None) -> tuple[str, int]:
    _ = client
    port_raw = ((cell or {}).get("tls_port") or "").strip()
    if port_raw:
        tcp_host, _ = backend_tls_endpoint(server, repo)
        tcp_port = int(port_raw)
    elif session is not None:
        tcp_host, tcp_port = session.tls_endpoint(server)
    else:
        tcp_host, tcp_port = backend_tls_endpoint(server, repo)
    server_conf.port = tcp_port
    client_conf.port = tcp_port
    client_conf.server_hostname = "127.0.0.1"
    return tcp_host, tcp_port


def required_backends_from_matrix(
    axis_keys: list[str], combos: list[tuple[Any, ...]], *, args_template: Any,
    repo: Path, known: frozenset[str]) -> tuple[frozenset[str], int]:
    from core.validation import cell_capability_skip_reason

    needed: set[str] = set()
    skips = 0
    for tup in combos:
        cell = {k: str(v) for k, v in zip(axis_keys, tup)}
        cell = normalize_cell_tls_micro_params(cell, args_template, repo)
        if cell_capability_skip_reason(cell, repo):
            skips += 1
            continue
        server = (cell.get("server") or "").strip().lower()
        client = (cell.get("client") or "").strip().lower()
        if server in known:
            needed.add(server)
        if client in known:
            needed.add(client)
    return frozenset(needed), skips

"""Matrix axis expansion and per-cell TLS micro-parameter normalization."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Sequence

from core.capabilities import(CAPABILITY_DIMENSIONS, NON_MATRIX_OPTION_IDS, NON_TLS_OPTION_IDS, TlsMode,
    backend_cipher_modes, capability_dimension_name, default_cipher_for_tls_mode, dimension_keys,
    load_capabilities, load_capabilities_cache, load_options_catalog, option_choice_tokens, repository_root,
    union_cipher_suite_ids_for_wrappers)
from core.utils import asymmetric_role_part, parse_asymmetric, split_csv_tokens
from core.validation import tls_mode_filter_from_args, tls_mode_from_version


def expand_dimension(value: str, choices: Sequence[str]) -> list[str]:
    """
    Expand a CLI dimension into concrete values.

    * Comma list: ``openssl,gnutls`` → listed tokens (each must be in ``choices``).
    * ``ALL`` (case-insensitive): full ``choices`` order.
    * ``ALL \\ a,b`` or ``ALL - a,b``: all choices except listed exclusions.
    * No ``choices``: one row — ``value`` or ``""``.
    * ``SERVER:CLIENT`` asymmetric (contains ``:`` but not ``ALL``-based): one row, unchanged.
    """
    base = [str(c).strip() for c in choices if c and str(c).strip()]
    v = (value or "").strip()

    if not base:
        return [v] if v else [""]

    if not v:
        return [""]

    if re.match(r"(?is)^ALL\s*$", v):
        return list(base)

    sub = re.match(r"(?is)^ALL\s*[\\-]\s*(.+)$", v)
    if sub:
        excl = {x.strip() for x in sub.group(1).split(",") if x.strip()}
        out = [x for x in base if x not in excl]
        if not out:
            raise ValueError(f"ALL minus exclusions leaves empty set: {value!r}")
        return out

    if ":" in v:
        return [v]

    parts = [x.strip() for x in v.split(",") if x.strip()]
    if not parts:
        raise ValueError(f"Empty dimension value: {value!r}")
    bad = [p for p in parts if p not in base]
    if bad:
        raise ValueError(f"Unknown value(s) {bad!r}; known: {', '.join(sorted(set(base)))}")
    return parts


def expand_capability_dimension(value: str, dimension: str, *, wrapper_ids: Sequence[str],
    caps_by_wrapper: dict[str, dict[str, Any]], catalog_choices: Sequence[str],
    tls_mode: TlsMode | None = None) -> list[str]:
    """Expand ALL / lists using per-backend ``capabilities.json`` keys."""
    v = (value or "").strip()
    catalog_tokens = [str(c).strip() for c in catalog_choices if c and str(c).strip()]
    cipher_mode = tls_mode if dimension == "cipher_suite" else None

    if re.match(r"(?is)^ALL\s*$", v):
        keys: set[str] = set()
        if dimension == "cipher_suite" and cipher_mode is not None:
            keys.update(union_cipher_suite_ids_for_wrappers(caps_by_wrapper, wrapper_ids, mode=cipher_mode))
        else:
            for wid in wrapper_ids:
                keys.update(dimension_keys(caps_by_wrapper.get(wid, {}), dimension, tls_mode=cipher_mode))
        if keys:
            return sorted(keys)
        return list(catalog_tokens)

    sub = re.match(r"(?is)^ALL\s*[\\-]\s*(.+)$", v)
    if sub:
        excl = {x.strip() for x in sub.group(1).split(",") if x.strip()}
        keys: set[str] = set()
        if dimension == "cipher_suite" and cipher_mode is not None:
            keys.update(union_cipher_suite_ids_for_wrappers(caps_by_wrapper, wrapper_ids, mode=cipher_mode))
        else:
            for wid in wrapper_ids:
                keys.update(dimension_keys(caps_by_wrapper.get(wid, {}), dimension, tls_mode=cipher_mode))
        if not keys:
            keys = set(catalog_tokens)
        out = sorted(k for k in keys if k not in excl)
        if not out:
            raise ValueError(f"ALL minus exclusions leaves empty set: {value!r}")
        return out

    if ":" in v:
        return [v]

    expanded = expand_dimension(v, catalog_tokens)
    if dimension != "cipher_suite" or cipher_mode is None:
        return expanded
    allowed = set(union_cipher_suite_ids_for_wrappers(caps_by_wrapper, wrapper_ids, mode=cipher_mode))
    filtered = [x for x in expanded if x in allowed]
    if not filtered and not v.strip():
        default = default_cipher_for_tls_mode(cipher_mode, allowed=allowed)
        return [default] if default else [""]
    if not filtered and v.strip() and not re.match(r"(?is)^ALL", v.strip()):
        return expanded if expanded else [v.strip()]
    return filtered


def expand_alpn_matrix_axis(value: str, *, wrapper_ids: Sequence[str],
    caps_by_wrapper: dict[str, dict[str, Any]], catalog_choices: Sequence[str]) -> list[str]:
    """
    Expand ALPN matrix values into ``server:client`` pairs.

    Symmetric comma lists / ``ALL`` become the Cartesian product of server and
    client protocol choices. Values that already contain ``:`` pass through unchanged.
    """
    v = (value or "").strip()
    if not v:
        return [""]
    if ":" in v:
        return expand_capability_dimension(v, "alpn_protocols", wrapper_ids=wrapper_ids,
            caps_by_wrapper=caps_by_wrapper, catalog_choices=catalog_choices)
    tokens = expand_capability_dimension(v, "alpn_protocols", wrapper_ids=wrapper_ids,
        caps_by_wrapper=caps_by_wrapper, catalog_choices=catalog_choices)
    if not tokens or tokens == [""]:
        return [""]
    return [f"{srv}:{cli}" for srv in tokens for cli in tokens]


def _cell_cipher_id(cell: dict[str, str], *, server: bool) -> str:
    cs = (cell.get("cipher_suite") or "").strip()
    if not cs:
        return ""
    if ":" in cs:
        left, right = cs.split(":", 1)
        return (left if server else right).strip()
    return cs


def effective_cell_tls_mode(cell: dict[str, str], srv_caps: dict[str, Any], cli_caps: dict[str, Any]) -> TlsMode:
    """Infer TLS 1.2 vs 1.3 from explicit version or cipher capabilities sections."""
    tv = (cell.get("tls_version") or "").strip()
    if tv and ":" not in tv:
        return tls_mode_from_version(tv)
    if tv and ":" in tv:
        left, _ = parse_asymmetric(tv)
        if left:
            return tls_mode_from_version(left)

    srv_c = _cell_cipher_id(cell, server=True)
    cli_c = _cell_cipher_id(cell, server=False)
    modes: set[TlsMode] = set()
    for cid, caps in ((srv_c, srv_caps), (cli_c, cli_caps)):
        if cid:
            modes |= backend_cipher_modes(caps, cid)
    if modes == {"1.2"}:
        return "1.2"
    if modes == {"1.3"} or not modes:
        return "1.3"
    return "1.3"


def _implicit_tls_version_for_side(cell: dict[str, str], *, server: bool, caps: dict[str, Any]) -> str:
    cid = _cell_cipher_id(cell, server=server)
    if not cid:
        return ""
    modes = backend_cipher_modes(caps, cid)
    if modes == {"1.3"}:
        return "1.3"
    if modes == {"1.2"}:
        return "1.2"
    return ""


def normalize_cell_tls_micro_params(cell: dict[str, str], args_template: Any, repo: Path) -> dict[str, str]:
    """
    Infer ``tls_version`` from cipher ``tls13``/``tls12`` sections; for TLS 1.2 ciphers
    drop orthogonal dims unless the user set them on the CLI.
    """
    from core.capabilities import TLS13_ORTHOGONAL_DIMS

    out = dict(cell)
    port = int(getattr(args_template, "tls_port", 0) or 0)
    if port:
        out["tls_port"] = str(port)
    server = (cell.get("server") or "").strip().lower()
    client = (cell.get("client") or "").strip().lower()
    try:
        srv_caps = load_capabilities(server, repo)
        cli_caps = load_capabilities(client, repo)
    except (FileNotFoundError, ValueError):
        return out

    if not (out.get("tls_version") or "").strip():
        sv = _implicit_tls_version_for_side(out, server=True, caps=srv_caps)
        cv = _implicit_tls_version_for_side(out, server=False, caps=cli_caps)
        if sv or cv:
            if sv and cv and sv != cv:
                out["tls_version"] = f"{sv}:{cv}"
            else:
                out["tls_version"] = sv or cv

    if effective_cell_tls_mode(out, srv_caps, cli_caps) != "1.2":
        out["test_features"] = str(getattr(args_template, "test_features", "") or "").strip()
        return out
    for dim in TLS13_ORTHOGONAL_DIMS:
        user_raw = str(getattr(args_template, dim, "") or "").strip()
        if not user_raw:
            out[dim] = ""
    out["test_features"] = str(getattr(args_template, "test_features", "") or "").strip()
    return out


def matrix_axis_plan(args: Any, *, known_wrappers: frozenset[str],
    repo: Path | None = None) -> tuple[list[str], list[list[Any]]]:
    """Capability-driven matrix axes (ALL/SKIP, TLS 1.2/1.3)."""
    root = repo or repository_root()
    wr = sorted(known_wrappers)
    caps_cache = load_capabilities_cache(known_wrappers, root)
    catalog = load_options_catalog(root)

    keys = ["server", "client"]
    server_vals = expand_dimension(str(args.server), wr)
    client_vals = expand_dimension(str(args.client), wr)
    vals: list[list[Any]] = [server_vals, client_vals]
    matrix_wrappers = set(server_vals) | set(client_vals)
    cipher_tls_mode = tls_mode_filter_from_args(args)

    for item in sorted(catalog, key=lambda x: str(x.get("id", ""))):
        oid = item["id"]
        if oid in NON_TLS_OPTION_IDS or oid == "tls_port" or oid in NON_MATRIX_OPTION_IDS:
            continue
        ch = item.get("choices") or []
        keys.append(oid)
        tokens = option_choice_tokens(item) if ch else []
        raw = str(getattr(args, oid, "") or "")
        if oid in CAPABILITY_DIMENSIONS and tokens:
            if oid == "alpn":
                vals.append(expand_alpn_matrix_axis(raw, wrapper_ids=sorted(matrix_wrappers),
                    caps_by_wrapper=caps_cache, catalog_choices=tokens))
            else:
                vals.append(expand_capability_dimension(raw, capability_dimension_name(oid),
                    wrapper_ids=sorted(matrix_wrappers), caps_by_wrapper=caps_cache, catalog_choices=tokens,
                    tls_mode=cipher_tls_mode if oid == "cipher_suite" else None))
        elif tokens:
            vals.append(expand_dimension(raw, tokens))
        else:
            if raw in (None, "", 0):
                vals.append([""])
            else:
                vals.append([str(raw)])
    return keys, vals

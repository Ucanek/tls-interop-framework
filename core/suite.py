"""YAML suite file loading and CLI exclusivity checks."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

# With ``--suite``, these must not appear on the command line (values come from YAML).
SUITE_MATRIX_CLI = {
    "server": "--server",
    "client": "--client",
    "cipher_suite": "--cipher-suite",
    "supported_groups": "--supported-groups",
    "tls_version": "--tls-version",
    "alpn": "--alpn",
    "test_features": "--test-features"}


def coerce_suite_matrix_value(value: Any, *, key: str = "") -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        parts = [str(x).strip() for x in value if str(x).strip()]
        return ",".join(parts)
    if isinstance(value, dict):
        if key == "test_features":
            enabled = [
                str(k).strip() for k, flag in value.items()
                if str(k).strip() and flag is True]
            return ",".join(enabled)
        raise ValueError("Suite matrix values must be scalars or lists")
    return str(value).strip()


def suite_cases_to_combos(args: argparse.Namespace, axis_keys: list[str]) -> list[tuple[Any, ...]]:
    """Expand explicit ``cases`` list from a suite file (not a Cartesian product)."""
    cases = getattr(args, "suite_cases", None)
    if not cases:
        return []
    combos: list[tuple[Any, ...]] = []
    for case in cases:
        row: dict[str, str] = {}
        for k in axis_keys:
            if k in case:
                row[k] = coerce_suite_matrix_value(case[k], key=k)
            else:
                row[k] = str(getattr(args, k, "") or "")
        combos.append(tuple(row[k] for k in axis_keys))
    return combos


def apply_suite_file(args: argparse.Namespace, suite_path: Path) -> None:
    """Load ``matrix:`` from a YAML suite file into ``args`` (CLI-equivalent strings)."""
    import yaml

    path = suite_path.expanduser()
    if not path.is_file():
        raise ValueError(f"suite {path}: file not found")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ValueError(f"suite {path}: invalid YAML ({e})") from e
    if not isinstance(raw, dict):
        raise ValueError(f"suite {path}: invalid YAML (root must be a mapping)")

    matrix = raw.get("matrix")
    if not isinstance(matrix, dict):
        raise ValueError(f"suite {path}: missing or invalid 'matrix' mapping")

    for key, value in matrix.items():
        dest = key.strip() if isinstance(key, str) else ""
        if not dest or not hasattr(args, dest):
            raise ValueError(f"suite {path}: invalid matrix key {key!r}")
        setattr(args, dest, coerce_suite_matrix_value(value, key=dest))

    cases = raw.get("cases") or raw.get("configurations")
    if cases is None:
        return
    if not isinstance(cases, list) or any(not isinstance(c, dict) for c in cases):
        raise ValueError(f"suite {path}: 'cases' must be a list of mappings")
    args.suite_cases = cases


def matrix_flags_differing_from_defaults(args: argparse.Namespace, parser: argparse.ArgumentParser) -> list[str]:
    """Matrix option dest names whose parsed value differs from the parser default."""
    found: list[str] = []
    for dest in SUITE_MATRIX_CLI:
        if getattr(args, dest, None) != parser.get_default(dest):
            found.append(dest)
    return found


def enforce_suite_cli_exclusivity(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """``--suite`` cannot be combined with matrix flags on the command line."""
    if not getattr(args, "suite", None):
        return
    conflicts = matrix_flags_differing_from_defaults(args, parser)
    if conflicts:
        flags = ", ".join(sorted(SUITE_MATRIX_CLI[d] for d in conflicts))
        parser.error(
            f"argument --suite: not allowed with matrix options on the command line ({flags}); "
            "put them under 'matrix' in the suite file instead")

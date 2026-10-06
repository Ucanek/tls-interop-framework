"""YAML suite file loading and CLI exclusivity checks."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

SUITE_MATRIX_CLI = {
    "server": "--server",
    "client": "--client",
    "cipher_suite": "--cipher-suite",
    "supported_groups": "--supported-groups",
    "tls_version": "--tls-version",
    "alpn": "--alpn",
    "test_features": "--test-features"}


def _coerce_suite_mapping(value: dict[Any, Any], *, key: str) -> str:
    if key != "test_features":
        raise ValueError("Suite matrix values must be scalars or lists")
    return ",".join(
        str(k).strip() for k, flag in value.items() if str(k).strip() and flag is True)


def coerce_suite_matrix_value(value: Any, *, key: str = "") -> str:
    """Coerce YAML matrix values into standard CLI-like strings."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return ",".join(str(x).strip() for x in value if str(x).strip())
    if isinstance(value, dict):
        return _coerce_suite_mapping(value, key=key)
    return str(value).strip()


def suite_cases_to_combos(args: argparse.Namespace, axis_keys: list[str]) -> list[tuple[Any, ...]]:
    """Expand explicit ``cases`` list from a suite file into tuple combinations."""
    cases = getattr(args, "suite_cases", None) or []
    return [
        tuple(
            coerce_suite_matrix_value(case[k], key=k)
            if k in case else str(getattr(args, k, "") or "")
            for k in axis_keys)
        for case in cases]


def _load_suite_mapping(path: Path) -> dict[str, Any]:
    import yaml

    if not path.is_file():
        raise ValueError(f"suite {path}: file not found")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ValueError(f"suite {path}: invalid YAML ({e})") from e
    if not isinstance(raw, dict) or not isinstance(raw.get("matrix"), dict):
        raise ValueError(f"suite {path}: missing or invalid 'matrix' mapping")
    return raw


def _apply_suite_matrix(args: argparse.Namespace, matrix: dict[Any, Any], path: Path) -> None:
    for key, value in matrix.items():
        dest = str(key).strip()
        if not dest or not hasattr(args, dest):
            raise ValueError(f"suite {path}: invalid matrix key {key!r}")
        setattr(args, dest, coerce_suite_matrix_value(value, key=dest))


def _apply_suite_cases(args: argparse.Namespace, raw: dict[str, Any], path: Path) -> None:
    cases = raw.get("cases") or raw.get("configurations")
    if cases is None:
        return
    if not isinstance(cases, list) or any(not isinstance(c, dict) for c in cases):
        raise ValueError(f"suite {path}: 'cases' must be a list of mappings")
    args.suite_cases = cases


def apply_suite_file(args: argparse.Namespace, suite_path: Path) -> None:
    """Load ``matrix:`` and optional ``cases:`` from a YAML suite file into ``args``."""
    path = suite_path.expanduser()
    raw = _load_suite_mapping(path)
    _apply_suite_matrix(args, raw["matrix"], path)
    _apply_suite_cases(args, raw, path)


def matrix_flags_differing_from_defaults(args: argparse.Namespace, parser: argparse.ArgumentParser) -> list[str]:
    """Return matrix option dest names whose parsed value differs from parser defaults."""
    return [dest for dest in SUITE_MATRIX_CLI if getattr(args, dest, None) != parser.get_default(dest)]


def enforce_suite_cli_exclusivity(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Ensure ``--suite`` is not combined with explicit matrix flags on CLI."""
    if not getattr(args, "suite", None):
        return
    conflicts = matrix_flags_differing_from_defaults(args, parser)
    if not conflicts:
        return
    flags = ", ".join(sorted(SUITE_MATRIX_CLI[d] for d in conflicts))
    parser.error(
        f"argument --suite: not allowed with matrix options on the command line ({flags}); "
        "put them under 'matrix' in the suite file instead")

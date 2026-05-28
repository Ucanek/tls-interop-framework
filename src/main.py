#!/usr/bin/env python3
"""Primary and only supported CLI entrypoint for TLS interop runs."""

from __future__ import annotations

import sys
from pathlib import Path

# ``src/`` on path so ``core`` imports work before ``ensure_import_paths``.
_src = Path(__file__).resolve().parent
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

import argparse
import copy
import os
import subprocess
import sys
from itertools import product
from pathlib import Path
from typing import Any

from core.catalog import (
    ASYMMETRIC_HELP_OPTION_IDS,
    OPTION_GROUPS,
    cell_capability_skip_reason,
    discover_wrapper_ids,
    ensure_import_paths,
    load_options_catalog,
    matrix_axis_plan,
    normalize_cell_tls_micro_params,
    print_catalog_options,
    repository_root,
    validate_run_args,
)

ensure_import_paths()
from core.runner import (
    EXIT_SKIP,
    PersistentComposeSession,
    PersistentLocalSession,
    required_backends_from_matrix,
    run_matrix_cell_grpc,
)

# Already registered explicitly in ``build_parser`` (not from capabilities catalog loop).
_PREDEFINED_CLI_OPTION_IDS = frozenset({"tls_port"})

# With ``--suite``, these must not appear on the command line (values come from YAML).
_SUITE_MATRIX_CLI: dict[str, str] = {
    "server": "--server",
    "client": "--client",
    "cipher_suite": "--cipher-suite",
    "supported_groups": "--supported-groups",
    "tls_version": "--tls-version",
}

_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_RED = "\033[91m"
_RESET = "\033[0m"


def _status_for_rc(rc: int) -> tuple[str, str]:
    """Human label and optional ANSI SGR prefix for stdout (TTY only)."""
    if rc == 0:
        return "OK", _GREEN
    if rc == EXIT_SKIP:
        return "SKIP", _YELLOW
    return "FAIL", _RED


def build_parser(repo: Path) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "TLS interop runner: starts backend wrappers via Docker Compose (default) or "
            "--local host subprocesses, then drives tests over gRPC. CLI choices are the "
            "union of all wrapper capabilities.json files. Use comma lists, ALL, or ALL\\ "
            "exclusions on --server/--client and choice-backed options for a Cartesian matrix."
        )
    )
    groups = {
        "basic": parser.add_argument_group(
            "Basic", "Runner, compose defaults, and global TLS listen port."
        ),
        "crypto": parser.add_argument_group(
            "Cryptography", "Ciphers, ECDH groups, and signature algorithms."
        ),
        "protocol": parser.add_argument_group(
            "Protocol", "TLS protocol version (TlsConfig.version)."
        ),
        "security": parser.add_argument_group(
            "Security & PKI", "Trust, hostname, and optional inline PEM material."
        ),
        "debug": parser.add_argument_group(
            "Debug / internals", "Diagnostic knobs (e.g. ALPN, key log)."
        ),
    }

    list_group = groups["basic"].add_mutually_exclusive_group()
    list_group.add_argument(
        "--list-wrappers",
        action="store_true",
        help="Print available wrapper implementations and exit",
    )
    list_group.add_argument(
        "--list-options",
        action="store_true",
        help="Print configurable TLS options (union of capabilities) and exit",
    )
    groups["basic"].add_argument(
        "-s",
        "--suite",
        metavar="FILE",
        default=None,
        help="Cesta k souboru s testovací sadou (.yaml)",
    )
    groups["basic"].add_argument(
        "--server",
        default="openssl",
        help="Server wrapper (comma list, ALL, ALL\\a,b to exclude; default: openssl)",
    )
    groups["basic"].add_argument(
        "--client",
        default="openssl",
        help="Client wrapper (comma list, ALL, ALL\\a,b to exclude; default: openssl)",
    )
    groups["basic"].add_argument(
        "--tls-port",
        type=int,
        default=0,
        help="Override TlsConfig.port (0 = driver default 5555)",
    )
    groups["basic"].add_argument(
        "--local",
        action="store_true",
        help=(
            "Run wrappers as local Python subprocesses (no Docker). Requires openssl, "
            "gnutls-utils, nss-tools on PATH, pip install grpcio, and certs/ (auto-generated)."
        ),
    )
    groups["basic"].add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )
    groups["basic"].add_argument(
        "--dry-run",
        action="store_true",
        help="Expand matrix and print planned backends without starting wrappers",
    )
    groups["basic"].add_argument(
        "--jobs",
        type=int,
        default=1,
        help=(
            "Reserved for future parallel matrix runs (persistent backends run serially). "
            "Default: 1."
        ),
    )

    for item in sorted(load_options_catalog(repo), key=lambda x: str(x.get("id", ""))):
        option_id = item["id"]
        if not isinstance(option_id, str):
            continue
        if option_id in _PREDEFINED_CLI_OPTION_IDS:
            continue
        gname = OPTION_GROUPS.get(option_id)
        if not gname:
            raise ValueError(
                f"Option id {option_id!r} has no argparse group in OPTION_GROUPS"
            )
        cli_name = f"--{option_id.replace('_', '-')}"
        desc = (item.get("description") or "").strip()
        asym = (
            " Use 'SERVER:CLIENT' for asymmetric configuration."
            if option_id in ASYMMETRIC_HELP_OPTION_IDS
            else ""
        )
        matrix_hint = ""
        ch = item.get("choices") or []
        if isinstance(ch, list) and ch:
            matrix_hint = " Matrix: comma list, ALL, or ALL\\token,token to exclude."
        help_text = (desc + asym + matrix_hint).strip() or (
            f"Forwarded to INTEROP_{option_id.upper()} for the driver."
        )
        groups[gname].add_argument(
            cli_name,
            default="",
            help=help_text,
        )
    return parser


def _matrix_flags_present_on_argv(argv: list[str] | None = None) -> list[str]:
    """Return matrix option dest names explicitly passed on the CLI (not defaults)."""
    argsv = argv if argv is not None else sys.argv
    found: list[str] = []
    for dest, flag in _SUITE_MATRIX_CLI.items():
        for token in argsv[1:]:
            if token == flag or token.startswith(flag + "="):
                found.append(dest)
                break
    return found


def _coerce_suite_matrix_value(value: Any) -> str:
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
        raise ValueError(
            "suite matrix values must be scalars or lists, not nested mappings"
        )
    return str(value).strip()


def apply_suite_file(args: argparse.Namespace, suite_path: Path) -> None:
    """Load ``matrix:`` from a YAML suite file into ``args`` (CLI-equivalent strings)."""
    import yaml

    path = suite_path.expanduser()
    if not path.is_file():
        raise ValueError(f"Suite file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid suite YAML {path}: {e}") from e
    if not isinstance(raw, dict):
        raise ValueError(f"Suite file must be a YAML mapping: {path}")
    matrix = raw.get("matrix")
    if matrix is None:
        raise ValueError(f"Suite file must contain a top-level 'matrix' key: {path}")
    if not isinstance(matrix, dict):
        raise ValueError(f"Suite 'matrix' must be a mapping: {path}")

    for key, value in matrix.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError(f"Invalid matrix key in suite file: {key!r}")
        dest = key.strip()
        if not hasattr(args, dest):
            raise ValueError(
                f"Unknown matrix key {dest!r} in suite file "
                f"(not a recognized CLI option)"
            )
        setattr(args, dest, _coerce_suite_matrix_value(value))


def enforce_suite_cli_exclusivity(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> None:
    """``--suite`` cannot be combined with matrix flags on the command line."""
    if not getattr(args, "suite", None):
        return
    conflicts = _matrix_flags_present_on_argv()
    if conflicts:
        flags = ", ".join(sorted(_SUITE_MATRIX_CLI[d] for d in conflicts))
        parser.error(
            f"argument -s/--suite: not allowed with matrix options on the command line "
            f"({flags}); put them under 'matrix' in the suite file instead"
        )


def _cell_summary_label(cell: dict[str, str]) -> str:
    s, c = cell["server"], cell["client"]
    ordered = (
        "tls_version",
        "cipher_suite",
        "supported_groups",
        "signature_schemes",
    )
    parts: list[str] = []
    for k in ordered:
        v = (cell.get(k) or "").strip().replace("\n", " ")
        parts.append(v or "-")
    mid = " / ".join(parts)
    return f"{s} x {c} | {mid}"


def _run_matrix_cell(
    tup: tuple[Any, ...],
    *,
    axis_keys: list[str],
    args_template: argparse.Namespace,
    repo: Path,
    known: frozenset[str],
    session: PersistentComposeSession | PersistentLocalSession | None,
) -> tuple[str, int]:
    cell = {k: str(v) for k, v in zip(axis_keys, tup)}
    cell = normalize_cell_tls_micro_params(cell, args_template, repo)
    label = _cell_summary_label(cell)
    skip = cell_capability_skip_reason(cell, repo)
    if skip:
        if args_template.verbose:
            print(f"SKIP (pre-run): {skip}", file=sys.stderr)
        else:
            short = skip[:120].replace("\n", " ")
            print(f"{label} | SKIP  ({short})")
        return label, EXIT_SKIP

    if session is None:
        return label, 0

    cell_ns = copy.copy(args_template)
    for k in axis_keys:
        setattr(cell_ns, k, cell[k])
    validate_run_args(cell_ns, known_wrappers=known, repo=repo)
    rc = run_matrix_cell_grpc(cell, session, verbose=bool(args_template.verbose))
    return label, rc


def main() -> int:
    repo = repository_root()
    parser = build_parser(repo)
    args = parser.parse_args()
    try:
        enforce_suite_cli_exclusivity(args, parser)
        if getattr(args, "suite", None):
            apply_suite_file(args, Path(args.suite))

        if args.list_wrappers:
            for name in discover_wrapper_ids(repo):
                print(name)
            return 0
        if args.list_options:
            print_catalog_options(repo)
            return 0

        known = frozenset(discover_wrapper_ids(repo))
        axis_keys, axis_vals = matrix_axis_plan(
            args, known_wrappers=known, repo=repo
        )
        n_tests = 1
        for av in axis_vals:
            n_tests *= len(av)
        print(f"Running matrix of {n_tests} tests...")

        combos = list(product(*axis_vals))
        backends, pre_skips = required_backends_from_matrix(
            axis_keys, combos, args_template=args, repo=repo, known=known
        )
        jobs = max(1, int(args.jobs))
        if jobs > 1:
            print(
                "Note: parallel --jobs is disabled with persistent backends; running serially.",
                file=sys.stderr,
            )

        if args.dry_run:
            svc = ", ".join(sorted(backends)) if backends else "(none)"
            mode = "local subprocesses" if args.local else "docker compose"
            print(f"DRY-RUN: would start backend(s) via {mode}: {svc}")
            if backends and not args.local:
                compose = repo / "deploy" / "compose.yaml"
                print(
                    "DRY-RUN compose:",
                    "docker compose",
                    "-f",
                    str(compose),
                    "up -d",
                    *sorted(backends),
                )
            print(f"DRY-RUN: {n_tests} matrix cell(s), {pre_skips} pre-SKIP")
            results = [
                _run_matrix_cell(
                    t,
                    axis_keys=axis_keys,
                    args_template=args,
                    repo=repo,
                    known=known,
                    session=None,
                )
                for t in combos
            ]
        else:
            session: PersistentComposeSession | PersistentLocalSession | None = None
            results: list[tuple[str, int]] = []
            try:
                if backends:
                    if args.local:
                        session = PersistentLocalSession(
                            repo, backends, verbose=bool(args.verbose)
                        )
                    else:
                        session = PersistentComposeSession(
                            repo, backends, verbose=bool(args.verbose)
                        )
                    session.start()
                for tup in combos:
                    results.append(
                        _run_matrix_cell(
                            tup,
                            axis_keys=axis_keys,
                            args_template=args,
                            repo=repo,
                            known=known,
                            session=session,
                        )
                    )
            except TimeoutError as e:
                print(e, file=sys.stderr)
                return 2
            except subprocess.CalledProcessError as e:
                print(f"Backend startup failed: {e}", file=sys.stderr)
                return 2
            except RuntimeError as e:
                print(f"Local mode: {e}", file=sys.stderr)
                return 2
            finally:
                if session is not None:
                    session.stop()

        print("\n--- Results ---")
        use_color = sys.stdout.isatty()
        for label, rc in results:
            text, color = _status_for_rc(rc)
            if use_color:
                print(f"{label} | {color}{text}{_RESET}")
            else:
                print(f"{label} | {text}")
        if any(rc not in (0, EXIT_SKIP) for _, rc in results):
            return 1
        return 0
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

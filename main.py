#!/usr/bin/env python3
"""Primary and only supported CLI entrypoint for TLS interop runs."""

from __future__ import annotations

import argparse
import copy
import queue
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from itertools import product
from pathlib import Path
from typing import Any

from core.catalog import (
    cell_capability_skip_reason, discover_wrapper_ids, ensure_import_paths,
    grpc_port_overrides_from_args, matrix_axis_plan, normalize_cell_tls_micro_params,
    print_catalog_options, repository_root, validate_run_args)

ensure_import_paths()
from core.runner import (
    EXIT_SKIP, EXIT_TIMEOUT, BaseExecutionSession, DebugRunLogs, MAX_PARALLEL_JOBS,
    WrapperSession, WorkerSlotPool, ensure_certs, remove_certs,
    required_backends_from_matrix, run_matrix_cell_grpc)
from core.suite import (
    apply_suite_file, enforce_suite_cli_exclusivity, suite_cases_to_combos)


def status_for_rc(rc: int) -> str:
    if rc == 0:
        return "PASS"
    if rc == EXIT_SKIP:
        return "SKIP"
    if rc == EXIT_TIMEOUT:
        return "TIMEOUT"
    return "FAIL"


def build_parser(_repo: Path) -> argparse.ArgumentParser:
    asym = " Use 'SERVER:CLIENT' for asymmetric configuration."
    matrix = " Matrix: comma list, ALL, or ALL\\token,token to exclude."
    parser = argparse.ArgumentParser(
        description="TLS interop runner: starts backend wrappers as host subprocesses, then drives "
        "tests over gRPC. Use comma lists, ALL, or ALL\\ exclusions on --server/--client and "
        "matrix TLS options for a Cartesian matrix.")
    groups = {
        "basic": parser.add_argument_group("Basic", "Runner and TLS listen port."),
        "crypto": parser.add_argument_group("Cryptography", "Ciphers, ECDH groups, and signature algorithms."),
        "protocol": parser.add_argument_group("Protocol", "TLS protocol version (TlsConfig.version).")}

    list_group = groups["basic"].add_mutually_exclusive_group()
    list_group.add_argument("--list-wrappers", action="store_true",
        help="Print available wrapper implementations and exit")
    list_group.add_argument("--list-options", action="store_true",
        help="Print configurable TLS options (union of capabilities) and exit")
    groups["basic"].add_argument("--suite", metavar="FILE", default=None,
        help="Cesta k souboru s testovací sadou (.yaml)")
    groups["basic"].add_argument("--server", default="openssl",
        help="Server wrapper (comma list, ALL, ALL\\a,b to exclude; default: openssl)")
    groups["basic"].add_argument("--client", default="openssl",
        help="Client wrapper (comma list, ALL, ALL\\a,b to exclude; default: openssl)")
    groups["basic"].add_argument("--tls-port", type=int, default=0,
        help="Override TLS listen/connect port (0 = per-backend default from capabilities.json)")
    groups["basic"].add_argument("--server-grpc-port", type=int, default=0,
        help="Override gRPC port for --server wrapper (0 = capabilities.json; useful with --attach)")
    groups["basic"].add_argument("--client-grpc-port", type=int, default=0,
        help="Override gRPC port for --client wrapper (0 = capabilities.json; useful with --attach)")
    groups["basic"].add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    groups["basic"].add_argument("--attach", action="store_true",
        help="Connect to wrapper gRPC services already running on localhost (do not start subprocesses)")
    groups["basic"].add_argument("--jobs", type=int, default=1, metavar="N",
        help="Max parallel matrix cells (isolated wrapper sets per worker slot; default: 1)")

    groups["crypto"].add_argument("--cipher-suite", default="",
        help="Cipher suite catalog id (per-backend mapping in capabilities.json). "
        "Omitted with --tls-version: one default cipher for that TLS version; use ALL for every "
        "declared cipher." + asym + matrix)
    groups["protocol"].add_argument("--tls-version", default="",
        help="TLS protocol version for the endpoint (TlsConfig.version)." + asym + matrix)
    groups["protocol"].add_argument("--alpn", default="",
        help="ALPN protocol identifiers offered by the endpoint (e.g. h2, http/1.1)."
        + asym + matrix)
    groups["crypto"].add_argument("--supported-groups", default="",
        help="Advertised/allowed key exchange groups (supported_groups extension)."
        + asym + matrix)
    groups["crypto"].add_argument("--signature-schemes", default="",
        help="Advertised TLS signature algorithms." + asym + matrix)
    groups["crypto"].add_argument("--test-features", default="",
        help="Credentials for special ciphers (psk, anonymous). cipher_suite ALL includes "
        "PSK/anon suites; without enabling a feature here, those cells are pre-SKIP "
        "(Feature disabled). Set test_features: psk,anonymous (or YAML map with true values) "
        "to run them." + matrix)
    return parser


def cell_summary_label(cell: dict[str, str]) -> str:
    s, c = cell["server"], cell["client"]
    ordered = ("tls_version", "cipher_suite", "supported_groups", "signature_schemes", "alpn")
    parts = [(cell.get(k) or "").strip().replace("\n", " ") or "-" for k in ordered]
    return f"{s} x {c} | {' / '.join(parts)}"


@dataclass
class WorkerContext:
    """Shared state for one matrix cell run (serial session or parallel worker slot)."""

    axis_keys: list[str]
    args_template: argparse.Namespace
    repo: Path
    known: frozenset[str]
    session: BaseExecutionSession | None = None
    debug_logs: DebugRunLogs | None = None
    slot_pool: WorkerSlotPool | None = None
    slot_queue: queue.Queue[int] | None = None
    console_lock: threading.Lock | None = None


def run_matrix_cell(tup: tuple[Any, ...], ctx: WorkerContext) -> tuple[str, int]:
    cell = {k: str(v) for k, v in zip(ctx.axis_keys, tup)}
    cell = normalize_cell_tls_micro_params(cell, ctx.args_template, ctx.repo)
    label = cell_summary_label(cell)
    skip = cell_capability_skip_reason(cell, ctx.repo)
    if skip:
        skip_s = skip if isinstance(skip, str) else " ".join(str(x) for x in skip)
        if ctx.args_template.verbose:
            print(f"SKIP (pre-run): {skip_s}", file=sys.stderr)
        else:
            print(f"{label} | SKIP  ({skip_s[:120].replace(chr(10), ' ')})")
        return label, EXIT_SKIP

    slot_id: int | None = None
    active_session = ctx.session
    if ctx.slot_pool is not None and ctx.slot_queue is not None:
        slot_id = ctx.slot_queue.get()
        active_session = ctx.slot_pool.session(slot_id)
    elif ctx.session is None:
        raise RuntimeError("missing wrapper session for matrix cell")

    try:
        cell_ns = copy.copy(ctx.args_template)
        for k in ctx.axis_keys:
            setattr(cell_ns, k, cell[k])
        validate_run_args(cell_ns, known_wrappers=ctx.known, repo=ctx.repo)
        rc = run_matrix_cell_grpc(
            cell, active_session, verbose=bool(ctx.args_template.verbose),
            debug_logs=ctx.debug_logs, console_lock=ctx.console_lock)
        return label, rc
    finally:
        if ctx.slot_pool is not None and ctx.slot_queue is not None and slot_id is not None:
            ctx.slot_queue.put(slot_id)


def run_matrix_parallel(
    combos: list[tuple[Any, ...]], *, axis_keys: list[str], args: argparse.Namespace,
    repo: Path, known: frozenset[str], backends: frozenset[str],
    debug_logs: DebugRunLogs | None, jobs: int) -> list[tuple[str, int]]:
    effective_jobs = min(max(1, jobs), len(combos), MAX_PARALLEL_JOBS)
    if effective_jobs < jobs:
        print(f"Note: --jobs {jobs} capped to {effective_jobs} for this matrix")
    slot_pool = WorkerSlotPool(
        repo, backends, effective_jobs, verbose=bool(args.verbose),
        grpc_base_overrides=grpc_port_overrides_from_args(args))
    slot_queue: queue.Queue[int] = queue.Queue()
    for i in range(effective_jobs):
        slot_queue.put(i)
    console_lock = threading.Lock()
    ctx = WorkerContext(
        axis_keys=axis_keys, args_template=args, repo=repo, known=known,
        debug_logs=debug_logs, slot_pool=slot_pool, slot_queue=slot_queue,
        console_lock=console_lock)
    slot_pool.start()
    try:
        with ThreadPoolExecutor(max_workers=effective_jobs) as executor:
            return list(executor.map(lambda tup: run_matrix_cell(tup, ctx), combos))
    finally:
        slot_pool.stop()


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

        if int(args.jobs) < 1:
            parser.error("--jobs must be >= 1")
        if int(args.jobs) > MAX_PARALLEL_JOBS:
            parser.error(f"--jobs must be <= {MAX_PARALLEL_JOBS}")
        if int(args.jobs) > 1 and bool(args.attach):
            parser.error("--jobs > 1 cannot be used with --attach")
        if int(args.jobs) > 1 and int(args.tls_port) != 0:
            parser.error("--jobs > 1 cannot be used with --tls-port")
        grpc_overrides = grpc_port_overrides_from_args(args)
        if int(args.jobs) > 1 and grpc_overrides:
            parser.error("--jobs > 1 cannot be used with --server-grpc-port / --client-grpc-port")

        known = frozenset(discover_wrapper_ids(repo))
        axis_keys, axis_vals = matrix_axis_plan(args, known_wrappers=known, repo=repo)
        if getattr(args, "suite_cases", None):
            for case in args.suite_cases:
                for k in case:
                    if k not in axis_keys:
                        axis_keys.append(k)
            combos = suite_cases_to_combos(args, axis_keys)
            n_tests = len(combos)
        else:
            n_tests = 1
            for av in axis_vals:
                n_tests *= len(av)
            combos = list(product(*axis_vals))
        print(f"Running matrix of {n_tests} tests...")
        debug_logs: DebugRunLogs | None = DebugRunLogs(repo) if combos else None
        if combos:
            ensure_certs(repo, verbose=bool(args.verbose))
        backends, _ = required_backends_from_matrix(
            axis_keys, combos, args_template=args, repo=repo, known=known)

        session: BaseExecutionSession | None = None
        results: list[tuple[str, int]] = []
        parallel_jobs = int(args.jobs)
        try:
            if parallel_jobs > 1 and backends:
                results = run_matrix_parallel(
                    combos, axis_keys=axis_keys, args=args, repo=repo, known=known,
                    backends=backends, debug_logs=debug_logs, jobs=parallel_jobs)
            else:
                if backends:
                    session = WrapperSession(
                        repo, backends, verbose=bool(args.verbose), attach=bool(args.attach),
                        grpc_port_overrides=grpc_overrides)
                    session.start()
                ctx = WorkerContext(
                    axis_keys=axis_keys, args_template=args, repo=repo, known=known,
                    session=session, debug_logs=debug_logs)
                for tup in combos:
                    results.append(run_matrix_cell(tup, ctx))
        except TimeoutError as e:
            print(e, file=sys.stderr)
            return 2
        except subprocess.CalledProcessError as e:
            print(f"Backend startup failed: {e}", file=sys.stderr)
            return 2
        except RuntimeError as e:
            print(f"Wrapper startup failed: {e}", file=sys.stderr)
            return 2
        finally:
            if session is not None:
                session.stop()

        print("\n--- Results ---")
        for label, rc in results:
            print(f"{label} | {status_for_rc(rc)}")
        if any(rc not in (0, EXIT_SKIP) for _, rc in results):
            if debug_logs is not None and debug_logs.ready:
                run_dir = debug_logs.path
                rel = (
                    run_dir.relative_to(repo)
                    if run_dir and run_dir.is_relative_to(repo) else run_dir)
                print(f"Debug logs for this run: {rel}/")
            return 1
        return 0
    except ValueError as e:
        print(e, file=sys.stderr)
        return 2
    finally:
        remove_certs(repo, verbose=bool(args.verbose))


if __name__ == "__main__":
    sys.exit(main())

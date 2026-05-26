"""TLS interop runner: Docker Compose orchestration and gRPC test driver."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Literal, Mapping, TypeAlias

import grpc

from core.catalog import (
    FALLBACK_CIPHER_ID_TO_IANA,
    cell_capability_skip_reason,
    ensure_import_paths,
    norm_token,
    normalize_cell_tls_micro_params,
    parse_asymmetric,
    repository_root,
    tls_version_to_capability_name,
)

ensure_import_paths()

from proto import interop_pb2, interop_pb2_grpc

from wrappers.base import split_asymmetric_csv, wait_tcp_connect

# Distinct from 0 (pass) and 1 (fail) so matrix runners can show SKIP vs OK.
EXIT_SKIP = 77

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"


# Published host ports (must match deploy/compose.yaml).
BACKEND_GRPC_ADDR: dict[str, str] = {
    "openssl": "127.0.0.1:15051",
    "gnutls": "127.0.0.1:15052",
    "nss": "127.0.0.1:15053",
}
BACKEND_TLS_HOST_PORT: dict[str, tuple[str, int]] = {
    "openssl": ("127.0.0.1", 15551),
    "gnutls": ("127.0.0.1", 15552),
    "nss": ("127.0.0.1", 15553),
}
_COMPOSE_BACKEND_SERVICES: frozenset[str] = frozenset(BACKEND_GRPC_ADDR)
_DEFAULT_GRPC_STARTUP_S = 90.0
_GRPC_STARTUP_POLL_S = 0.4


# --- Docker Compose orchestration (persistent backends) ---

def interop_dotenv_path(root: Path) -> Path:
    return root / "deploy" / ".interop.env"


def write_interop_dotenv(path: Path, variables: dict[str, str]) -> None:
    """Writes a Docker Compose ``env_file`` (KEY=value, one per line)."""

    def esc_val(v: str) -> str:
        if "\n" in v or "\r" in v:
            raise ValueError("Env value must not contain newlines")
        if re.fullmatch(r"[A-Za-z0-9_.,:@%+=/-]+", v):
            return v
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for k in sorted(variables):
            f.write(f"{k}={esc_val(variables[k])}\n")
    path.chmod(0o600)


def sanitize_compose_project(name: str) -> str:
    s = "".join(c if c.isalnum() or c in "-_" else "-" for c in name.lower()).strip("-")
    return (s or "interop")[:63]


def required_backends_from_matrix(
    axis_keys: list[str],
    combos: list[tuple[Any, ...]],
    *,
    args_template: Any,
    repo: Path,
    known: frozenset[str],
) -> tuple[frozenset[str], int]:
    """
    Collect backends needed by non-SKIP matrix cells.

    Returns ``(backend_ids, skip_count)``.
    """
    needed: set[str] = set()
    skips = 0
    for tup in combos:
        cell = {k: str(v) for k, v in zip(axis_keys, tup)}
        cell = normalize_cell_tls_micro_params(cell, args_template, repo)
        if cell_capability_skip_reason(cell, repo):
            skips += 1
            continue
        srv = (cell.get("server") or "").strip().lower()
        cli = (cell.get("client") or "").strip().lower()
        if srv in known:
            needed.add(srv)
        if cli in known:
            needed.add(cli)
    return frozenset(needed), skips


def _compose_base_cmd(
    repo: Path,
    project: str,
    *,
    verbose: bool,
) -> list[str]:
    progress: list[str] = [] if verbose else ["--progress", "quiet"]
    return [
        "docker",
        "compose",
        *progress,
        "-p",
        project,
        "-f",
        str(repo / "deploy" / "compose.yaml"),
    ]


class PersistentComposeSession:
    """Start selected backend containers once; matrix loop uses gRPC only."""

    def __init__(
        self,
        repo: Path,
        backends: frozenset[str],
        *,
        verbose: bool = False,
        project: str | None = None,
    ) -> None:
        unknown = backends - _COMPOSE_BACKEND_SERVICES
        if unknown:
            raise ValueError(f"Unknown backend service(s): {sorted(unknown)}")
        self.repo = repo
        self.backends = sorted(backends)
        self.verbose = verbose
        proj_env = (os.environ.get("INTEROP_COMPOSE_PROJECT") or "").strip()
        if project:
            self.project = sanitize_compose_project(project)
        elif proj_env:
            self.project = sanitize_compose_project(proj_env)
        else:
            self.project = sanitize_compose_project(
                "interop-" + "-".join(self.backends)
            )
        self.metadata: dict[str, interop_pb2.LibraryMetadata] = {}

    def grpc_addr(self, backend: str) -> str:
        key = (backend or "").strip().lower()
        try:
            return BACKEND_GRPC_ADDR[key]
        except KeyError as e:
            raise ValueError(f"no gRPC publish map for backend {backend!r}") from e

    def _compose_env(self) -> dict[str, str]:
        env = os.environ.copy()
        if "gnutls" in self.backends and "nss" in self.backends:
            env["INTEROP_GNUTLS_NSS_PAIR"] = "1"
        else:
            env["INTEROP_GNUTLS_NSS_PAIR"] = "0"
        return env

    def up(self) -> None:
        """``docker compose build`` then ``up -d`` for selected backends only."""
        if not self.backends:
            return
        compose = _compose_base_cmd(self.repo, self.project, verbose=self.verbose)
        env = self._compose_env()
        services = list(self.backends)
        if self.verbose:
            print(
                f"{YELLOW}[Compose] Starting backends: {', '.join(services)}{RESET}"
            )
        subprocess.run(
            compose + ["build"] + ([] if self.verbose else ["-q"]),
            cwd=self.repo,
            env=env,
            stdin=subprocess.DEVNULL,
            check=True,
        )
        subprocess.run(
            compose + ["up", "-d", *services],
            cwd=self.repo,
            env=env,
            stdin=subprocess.DEVNULL,
            check=True,
        )

    def down(self) -> None:
        compose = _compose_base_cmd(self.repo, self.project, verbose=self.verbose)
        subprocess.run(
            compose + ["down", "--remove-orphans"],
            cwd=self.repo,
            env=self._compose_env(),
            stdin=subprocess.DEVNULL,
            check=False,
        )

    def wait_grpc_ready(
        self,
        timeout_s: float = _DEFAULT_GRPC_STARTUP_S,
    ) -> None:
        """Retry until every selected backend accepts gRPC on the host-published port."""
        addrs = sorted({self.grpc_addr(b) for b in self.backends})
        if not addrs:
            return
        deadline = time.monotonic() + timeout_s
        pending = set(addrs)
        while time.monotonic() < deadline and pending:
            for addr in list(pending):
                if _wait_grpc_channel_ready(
                    addr, deadline=deadline, verbose=self.verbose
                ):
                    pending.discard(addr)
            if pending:
                time.sleep(_GRPC_STARTUP_POLL_S)
        if pending:
            raise TimeoutError(
                f"gRPC not reachable within {timeout_s}s: {', '.join(sorted(pending))}"
            )

    def load_metadata(self) -> None:
        for backend in self.backends:
            addr = self.grpc_addr(backend)
            ch = grpc.insecure_channel(addr)
            try:
                stub = interop_pb2_grpc.TlsInteropWrapperStub(ch)
                self.metadata[backend] = stub.GetMetadata(interop_pb2.Empty())
            finally:
                try:
                    ch.close()
                except Exception:
                    pass

    def start(self) -> None:
        self.up()
        self.wait_grpc_ready()
        self.load_metadata()

    def stop(self) -> None:
        self.down()


def _pick_cell_scalar(cell: dict[str, str], field: str, *, server: bool) -> str:
    raw = (cell.get(field) or "").strip()
    if not raw:
        return ""
    if ":" in raw:
        left, right = parse_asymmetric(raw)
        return left if server else right
    return raw


def _pick_cell_list(cell: dict[str, str], field: str, *, server: bool) -> list[str]:
    raw = (cell.get(field) or "").strip()
    if not raw:
        return []
    if ":" in raw:
        left, right = split_asymmetric_csv(raw)
        part = left if server else right
    else:
        part = raw
    return [p.strip() for p in part.split(",") if p.strip()]


def tls_config_from_cell(cell: dict[str, str], role: int) -> interop_pb2.TlsConfig:
    """Build ``TlsConfig`` for one matrix role from a normalized cell dict."""
    server = role == interop_pb2.SERVER
    cfg = interop_pb2.TlsConfig()
    ver = _pick_cell_scalar(cell, "tls_version", server=server)
    if ver:
        cfg.version = ver
    else:
        cfg.version = "1.3"
    cs = _pick_cell_scalar(cell, "cipher_suite", server=server)
    if cs:
        cfg.cipher_suite = cs
    port_raw = _pick_cell_scalar(cell, "tls_port", server=server)
    if port_raw:
        cfg.port = int(port_raw)
    elif (cell.get("tls_port") or "").strip() == "":
        cfg.port = 5555
    cfg.supported_groups.extend(
        _pick_cell_list(cell, "supported_groups", server=server)
    )
    cfg.signature_schemes.extend(
        _pick_cell_list(cell, "signature_schemes", server=server)
    )
    cfg.alpn_protocols.extend(_pick_cell_list(cell, "alpn_protocols", server=server))
    return cfg


def run_matrix_cell_grpc(
    cell: dict[str, str],
    session: PersistentComposeSession,
    *,
    verbose: bool,
) -> int:
    """Run one matrix cell over persistent backends (gRPC only, no Compose)."""
    server = (cell.get("server") or "").strip().lower()
    client = (cell.get("client") or "").strip().lower()
    print(f"========== {server}x{client} ==========")

    server_conf = tls_config_from_cell(cell, interop_pb2.SERVER)
    client_conf = tls_config_from_cell(cell, interop_pb2.CLIENT)
    if server == client:
        client_conf.server_hostname = "localhost"
    else:
        client_conf.server_hostname = server
    if client_conf.port <= 0:
        client_conf.port = server_conf.port if server_conf.port > 0 else 5555

    tcp_host, tcp_port = BACKEND_TLS_HOST_PORT.get(
        server, ("127.0.0.1", 15551)
    )
    if server_conf.port > 0 and server_conf.port != 5555:
        if verbose:
            print(
                f"{YELLOW}[Driver] Note: persistent mode expects TLS port 5555 inside "
                f"containers (got {server_conf.port}); host check uses {tcp_port}{RESET}",
                file=sys.stderr,
            )

    driver = InteropDriver(
        session.grpc_addr(server),
        session.grpc_addr(client),
        verbose=verbose,
    )
    driver.server_metadata = session.metadata.get(server)
    driver.client_metadata = session.metadata.get(client)

    if skip := driver.scenario_skip_reason_for_configs(server_conf, client_conf):
        if verbose:
            print(f"{YELLOW}[Driver] SKIP: {skip}{RESET}")
        else:
            short = skip[:120].replace("\n", " ")
            print(f"{YELLOW}○{RESET}  interop  ({short})")
        return EXIT_SKIP

    driver._last_skip_reason = None
    driver._last_failure = None
    spinner: _QuietSpinner | None = None
    if not verbose and sys.stderr.isatty():
        spinner = _QuietSpinner()
        spinner.start()
    try:
        ok = driver.run_test_with_configs(
            server_conf,
            client_conf,
            tcp_host=tcp_host,
            tcp_port=tcp_port,
        )
    finally:
        if spinner:
            spinner.stop()

    if driver._last_skip_reason:
        if verbose:
            print(f"{YELLOW}[Driver] SKIP: {driver._last_skip_reason}{RESET}")
            return EXIT_SKIP
        short = driver._last_skip_reason[:200].replace("\n", " ").strip()
        print(f"{YELLOW}○{RESET}  interop  ({short})")
        return EXIT_SKIP
    if verbose:
        return 0 if ok else 1
    detail = ""
    if not ok and driver._last_failure:
        detail = (driver._last_failure[2] or "").replace("\n", " ").strip()[:220]
    suf = f"  ({detail})" if detail else ""
    mark = f"{GREEN}✓{RESET}" if ok else f"{RED}✗{RESET}"
    print(f"{mark}  interop{suf}")
    return 0 if ok else 1

# --- gRPC test driver ---

SUCCESS = interop_pb2.OperationResponse.SUCCESS
FAILURE = interop_pb2.OperationResponse.FAILURE

_TCP_AFTER_ESTABLISH_S = 20.0
_TRANSMIT_GAP_S = 1.0
_DEFAULT_GRPC_WAIT_S = 180.0
_TEST_PAYLOAD = b"INTEROP_SECRET_TOKEN"

# --- TlsConfig from INTEROP_* (catalog ids ↔ capabilities.json keys)
_FieldKind: TypeAlias = Literal["str", "bool", "int", "list", "bytes"]

_TLS_ENV_FIELDS: dict[str, tuple[str, _FieldKind]] = {
    "tls_version": ("version", "str"),
    "cipher_suite": ("cipher_suite", "str"),
    "tls_port": ("port", "int"),
    "certificate_pem": ("certificate", "bytes"),
    "private_key_pem": ("private_key", "bytes"),
    "ca_file": ("ca_file", "str"),
    "keylog_file": ("keylog_file", "str"),
    "supported_groups": ("supported_groups", "list"),
    "signature_schemes": ("signature_schemes", "list"),
    "alpn_protocols": ("alpn_protocols", "list"),
}


def _interop_env_raw(option_id: str) -> str:
    return (os.environ.get(f"INTEROP_{option_id.upper()}", "") or "").strip()


def _parse_tls_bool(raw: str) -> bool:
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _load_tls_pem_bytes(raw: str) -> bytes:
    if not raw:
        return b""
    if os.path.isfile(raw):
        with open(raw, "rb") as f:
            return f.read()
    return raw.encode("utf-8")


_ASYM_LIST_FIELDS = frozenset({"supported_groups", "signature_schemes"})
_ASYM_STR_FIELDS = frozenset({"cipher_suite", "version"})


def _apply_tls_env_field(
    cfg: interop_pb2.TlsConfig, field: str, kind: _FieldKind, raw: str
) -> None:
    if kind == "str":
        if field in _ASYM_STR_FIELDS and ":" in raw:
            left, _ = parse_asymmetric(raw)
            setattr(cfg, field, left)
        else:
            setattr(cfg, field, raw)
    elif kind == "bool":
        setattr(cfg, field, _parse_tls_bool(raw))
    elif kind == "int":
        setattr(cfg, field, int(raw))
    elif kind == "list":
        if field in _ASYM_LIST_FIELDS and ":" in raw:
            left, _ = split_asymmetric_csv(raw)
            getattr(cfg, field).extend(left)
        else:
            getattr(cfg, field).extend([p.strip() for p in raw.split(",") if p.strip()])
    else:
        setattr(cfg, field, _load_tls_pem_bytes(raw))


def tls_config_from_env() -> interop_pb2.TlsConfig:
    """Loads ``TlsConfig`` from ``INTEROP_*`` environment variables."""
    cfg = interop_pb2.TlsConfig()
    for oid, (field, kind) in _TLS_ENV_FIELDS.items():
        raw = _interop_env_raw(oid)
        if not raw:
            continue
        _apply_tls_env_field(cfg, field, kind, raw)
    if not cfg.version.strip():
        cfg.version = "1.3"
    if cfg.port <= 0:
        cfg.port = 5555
    return cfg


def _role_config(base: interop_pb2.TlsConfig, role: int) -> interop_pb2.TlsConfig:
    cfg = interop_pb2.TlsConfig()
    cfg.CopyFrom(base)
    server = role == interop_pb2.SERVER

    def pick_env_str(option_id: str, field: str) -> None:
        raw = _interop_env_raw(option_id)
        if not raw:
            return
        left, right = parse_asymmetric(raw)
        setattr(cfg, field, left if server else right)

    def pick_env_list(option_id: str, field: str) -> None:
        raw = _interop_env_raw(option_id)
        if not raw:
            return
        left, right = split_asymmetric_csv(raw)
        parts = left if server else right
        seq = getattr(cfg, field)
        del seq[:]
        seq.extend(parts)

    pick_env_str("tls_version", "version")
    pick_env_str("cipher_suite", "cipher_suite")
    pick_env_list("supported_groups", "supported_groups")
    pick_env_list("signature_schemes", "signature_schemes")

    if not (cfg.version or "").strip():
        cfg.version = "1.3"
    return cfg


def _fill_tls_hostname_and_port(conf: interop_pb2.TlsConfig, tls_hostname: str) -> None:
    if not (conf.server_hostname or "").strip():
        conf.server_hostname = (tls_hostname or "localhost").strip() or "localhost"
    if conf.port <= 0:
        conf.port = 5555


def _wait_grpc_channel_ready(address: str, *, deadline: float, verbose: bool) -> bool:
    channel = grpc.insecure_channel(address)
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        grpc.channel_ready_future(channel).result(timeout=min(3.0, remaining))
        if verbose:
            print(f"{GREEN}[Driver] gRPC reachable: {address}{RESET}")
        return True
    except (grpc.FutureTimeoutError, Exception):
        return False
    finally:
        try:
            channel.close()
        except Exception:
            pass


def _wait_grpc_peers(
    server_grpc: str,
    client_grpc: str,
    *,
    timeout_s: float,
    verbose: bool,
) -> None:
    deadline = time.monotonic() + timeout_s
    if verbose:
        print(
            f"{YELLOW}[Driver] Waiting for gRPC peers (up to {timeout_s:g}s): "
            f"{server_grpc} and {client_grpc}{RESET}"
        )
    got_server = got_client = False
    while time.monotonic() < deadline and not (got_server and got_client):
        if not got_server:
            got_server = _wait_grpc_channel_ready(
                server_grpc, deadline=deadline, verbose=verbose
            )
        if not got_client:
            got_client = _wait_grpc_channel_ready(
                client_grpc, deadline=deadline, verbose=verbose
            )
        if got_server and got_client:
            return
        time.sleep(0.35)
    missing = [a for ok, a in ((got_server, server_grpc), (got_client, client_grpc)) if not ok]
    raise TimeoutError(f"gRPC not reachable within {timeout_s}s: {', '.join(missing)}")


def _operation_response_detail(resp: interop_pb2.OperationResponse) -> str:
    msg = (resp.message or "").strip()
    logs = (resp.logs or "").strip()
    if msg and logs:
        return f"{msg}\n{logs}"
    return msg or logs or "no message"


def _env_float(key: str, default: float) -> float:
    raw = (os.environ.get(key) or "").strip() or None
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_truthy_positive(key: str) -> bool:
    return os.environ.get(key, "").strip().lower() in ("1", "true", "yes")


class _QuietSpinner:
    _FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._stop.clear()

        def loop() -> None:
            i = 0
            n = len(self._FRAMES)
            while not self._stop.is_set():
                c = self._FRAMES[i % n]
                sys.stderr.write(f"\r\033[36m{c}\033[0m\033[K")
                sys.stderr.flush()
                i += 1
                time.sleep(0.08)

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=0.35)
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()


class InteropDriver:
    def __init__(
        self,
        server_addr: str,
        client_addr: str,
        verbose: bool = False,
    ) -> None:
        self._verbose = verbose
        self._last_failure: tuple[str, int, str] | None = None
        self._last_skip_reason: str | None = None
        self.server_metadata: interop_pb2.LibraryMetadata | None = None
        self.client_metadata: interop_pb2.LibraryMetadata | None = None
        self._channels: list[grpc.Channel] = []
        if server_addr == client_addr:
            ch = grpc.insecure_channel(server_addr)
            self._channels.append(ch)
            stub = interop_pb2_grpc.TlsInteropWrapperStub(ch)
            self.server_stub = stub
            self.client_stub = stub
        else:
            ch_s = grpc.insecure_channel(server_addr)
            ch_c = grpc.insecure_channel(client_addr)
            self._channels.extend([ch_s, ch_c])
            self.server_stub = interop_pb2_grpc.TlsInteropWrapperStub(ch_s)
            self.client_stub = interop_pb2_grpc.TlsInteropWrapperStub(ch_c)

    def _vprint(self, *args: Any, **kwargs: Any) -> None:
        if self._verbose:
            print(*args, **kwargs)

    def _log_metadata(self, label: str, metadata: interop_pb2.LibraryMetadata) -> None:
        role_names: Mapping[int, str] = {
            interop_pb2.CLIENT: "CLIENT",
            interop_pb2.SERVER: "SERVER",
        }
        roles_str = [role_names.get(r, str(r)) for r in metadata.roles]
        self._vprint(f"[Driver] {label}: {metadata.component_name} {metadata.version}")
        self._vprint(f"         roles={roles_str}")
        versions = [c.name for c in metadata.supported_versions]
        suf = "..." if len(versions) > 5 else ""
        self._vprint(f"         supported_versions={versions[:5]}{suf}")

    def _metadata_can_negotiate_version(
        self,
        metadata: interop_pb2.LibraryMetadata | None,
        capability_name: str,
        role: int,
    ) -> bool:
        if metadata is None:
            return True
        if metadata.roles and role not in metadata.roles:
            return False
        caps = list(metadata.supported_versions)
        if not caps:
            return True
        return any(
            c.name == capability_name and interop_pb2.NEGOTIATE in c.flags for c in caps
        )

    def scenario_skip_reason_for_configs(
        self,
        server_conf: interop_pb2.TlsConfig,
        client_conf: interop_pb2.TlsConfig,
    ) -> str | None:
        """Skip run if peer metadata disagrees with role ``TlsConfig`` values."""
        if self.server_metadata is None or self.client_metadata is None:
            return None
        srv = server_conf
        cli = client_conf
        return self._scenario_skip_reason_impl(srv, cli)

    def scenario_skip_reason(self, cfg: interop_pb2.TlsConfig) -> str | None:
        """Skip run if peer metadata disagrees with env ``TlsConfig`` (no scenario id)."""
        if self.server_metadata is None or self.client_metadata is None:
            return None
        srv = _role_config(cfg, interop_pb2.SERVER)
        cli = _role_config(cfg, interop_pb2.CLIENT)
        return self._scenario_skip_reason_impl(srv, cli)

    def _scenario_skip_reason_impl(
        self,
        srv: interop_pb2.TlsConfig,
        cli: interop_pb2.TlsConfig,
    ) -> str | None:
        cap_srv = tls_version_to_capability_name(srv.version)
        cap_cli = tls_version_to_capability_name(cli.version)
        if not self._metadata_can_negotiate_version(
            self.server_metadata, cap_srv, interop_pb2.SERVER
        ):
            cn = self.server_metadata.component_name
            return f"server ({cn}) cannot negotiate {cap_srv} per GetMetadata"
        if not self._metadata_can_negotiate_version(
            self.client_metadata, cap_cli, interop_pb2.CLIENT
        ):
            cn = self.client_metadata.component_name
            return f"client ({cn}) cannot negotiate {cap_cli} per GetMetadata"
        if (ciph := (srv.cipher_suite or "").strip()):
            cn_s = self.server_metadata.component_name
            if not self._metadata_supports_cipher(self.server_metadata, ciph):
                return f"server ({cn_s}) cannot offer cipher '{ciph}' per GetMetadata"
        if (ciph := (cli.cipher_suite or "").strip()):
            cn_c = self.client_metadata.component_name
            if not self._metadata_supports_cipher(self.client_metadata, ciph):
                return f"client ({cn_c}) cannot offer cipher '{ciph}' per GetMetadata"
        if (grp := list(srv.supported_groups)):
            cn_s = self.server_metadata.component_name
            if not self._metadata_supports_groups(self.server_metadata, grp):
                return f"server ({cn_s}) lacks group(s) {grp} per GetMetadata"
        if (grp := list(cli.supported_groups)):
            cn_c = self.client_metadata.component_name
            if not self._metadata_supports_groups(self.client_metadata, grp):
                return f"client ({cn_c}) lacks group(s) {grp} per GetMetadata"
        return None

    def _metadata_supports_cipher(
        self, metadata: interop_pb2.LibraryMetadata | None, catalog_cipher: str
    ) -> bool:
        if metadata is None or not (catalog_cipher or "").strip():
            return True
        cat = catalog_cipher.strip().lower().replace(" ", "")
        iana = (FALLBACK_CIPHER_ID_TO_IANA.get(cat) or "").strip()
        aliases = {norm_token(catalog_cipher), norm_token(iana)} - {""}
        for cap in metadata.cipher_suites:
            nm_raw = cap.name or ""
            if norm_token(nm_raw) in aliases:
                return True
            iana_fold = iana.upper().replace("_", "").replace("-", "")
            if iana and iana_fold in nm_raw.upper().replace("_", "").replace("-", ""):
                return True
            if nm_raw.upper().startswith("TLS_") and cat in nm_raw.lower().replace("-", ""):
                return True
        return False

    def _metadata_supports_groups(
        self, metadata: interop_pb2.LibraryMetadata | None, group_tokens: list[str]
    ) -> bool:
        if metadata is None or not group_tokens:
            return True
        avail = {norm_token(c.name) for c in metadata.groups}
        for g in group_tokens:
            gt = norm_token(g)
            if gt in avail:
                continue
            if not any(gt in m or m in gt or gt == m for m in avail):
                return False
        return True

    def _check_response(self, resp: interop_pb2.OperationResponse, label: str) -> bool:
        detail = _operation_response_detail(resp)
        if resp.status == SUCCESS and detail.lower().startswith("skip:"):
            self._last_skip_reason = detail[5:].strip() or "wrapper reported unsupported option"
            if self._verbose:
                print(f"{YELLOW}[Driver] {label}: SKIP - {self._last_skip_reason}{RESET}")
            return False
        if resp.status == SUCCESS:
            if self._verbose and (resp.logs or "").strip():
                for line in resp.logs.strip().split("\n"):
                    self._vprint(f"[Driver] {label} (wrapper cmd): {line}")
            return True
        self._last_failure = (label, resp.status, detail)
        if self._verbose:
            lab = "FAILURE" if resp.status == FAILURE else "ERROR"
            print(f"{RED}[Driver] {label}: {lab} - {self._last_failure[2]}{RESET}")
        return False

    def _execute_establish(
        self,
        stub: interop_pb2_grpc.TlsInteropWrapperStub,
        role: int,
        cfg: interop_pb2.TlsConfig,
    ) -> interop_pb2.OperationResponse:
        return stub.ExecuteOperation(
            interop_pb2.OperationRequest(
                type=interop_pb2.OperationRequest.ESTABLISH,
                role=role,
                config=cfg,
            )
        )

    def _cleanup(self) -> None:
        self._vprint("[Driver] Cleaning up...")
        close_req = interop_pb2.OperationRequest(type=interop_pb2.OperationRequest.CLOSE)
        for stub, role in [(self.server_stub, "server"), (self.client_stub, "client")]:
            try:
                self._check_response(stub.ExecuteOperation(close_req), f"CLOSE {role}")
            except Exception as e:
                msg = f"[Driver] CLOSE {role} exception: {e}"
                print(msg if self._verbose else f"{RED}FAIL{RESET}  CLOSE {role}: {e}")

    def run_test(self, tls_hostname: str) -> bool:
        """ESTABLISH server → client → TCP wait → TRANSMIT (env-based ``TlsConfig``)."""
        self._last_skip_reason = None
        base_conf = tls_config_from_env()
        _fill_tls_hostname_and_port(base_conf, tls_hostname)
        server_conf = _role_config(base_conf, interop_pb2.SERVER)
        client_conf = _role_config(base_conf, interop_pb2.CLIENT)
        if (base_conf.server_hostname or "").strip():
            client_conf.server_hostname = base_conf.server_hostname
        tcp_host, tcp_port = "127.0.0.1", int(server_conf.port or 5555)
        return self.run_test_with_configs(
            server_conf,
            client_conf,
            tcp_host=tcp_host,
            tcp_port=tcp_port,
        )

    def run_test_with_configs(
        self,
        server_conf: interop_pb2.TlsConfig,
        client_conf: interop_pb2.TlsConfig,
        *,
        tcp_host: str,
        tcp_port: int,
    ) -> bool:
        """ESTABLISH server → client → host TCP check → TRANSMIT → CLOSE (wrapper idle)."""
        self._last_skip_reason = None
        ver = (server_conf.version or "").strip() or "default"
        try:
            self._vprint(f"[Driver] Round-trip (TLS {ver})")
            self._vprint("[Driver] Establishing connection...")
            r = self._execute_establish(self.server_stub, interop_pb2.SERVER, server_conf)
            if not self._check_response(r, "ESTABLISH server"):
                return False
            r = self._execute_establish(self.client_stub, interop_pb2.CLIENT, client_conf)
            if not self._check_response(r, "ESTABLISH client"):
                return False

            ok_peer, _ = wait_tcp_connect(
                tcp_host, int(tcp_port), timeout_s=_TCP_AFTER_ESTABLISH_S
            )
            if not ok_peer:
                self._vprint(
                    f"{RED}[Driver] Timeout waiting for TCP {tcp_host}:{tcp_port}{RESET}"
                )
                self._last_failure = (
                    "wait_tcp",
                    FAILURE,
                    f"TCP {tcp_host}:{tcp_port} not accepting after ESTABLISH",
                )
                return False

            self._vprint(f"[Driver] Transmitting: {_TEST_PAYLOAD.decode()}")
            r_tx = self.client_stub.ExecuteOperation(
                interop_pb2.OperationRequest(
                    type=interop_pb2.OperationRequest.TRANSMIT,
                    role=interop_pb2.CLIENT,
                    payload=_TEST_PAYLOAD,
                )
            )
            if not self._check_response(r_tx, "TRANSMIT client"):
                return False

            time.sleep(_TRANSMIT_GAP_S)
            r_srv = self.server_stub.ExecuteOperation(
                interop_pb2.OperationRequest(
                    type=interop_pb2.OperationRequest.TRANSMIT,
                    role=interop_pb2.SERVER,
                )
            )
            if not self._check_response(r_srv, "TRANSMIT server"):
                return False

            if _TEST_PAYLOAD in r_srv.output_data:
                self._vprint(f"{GREEN}>>> PASSED: payload echoed (TLS {ver}) <<<{RESET}")
                return True
            self._vprint(f"{RED}>>> FAILED: echo mismatch <<<{RESET}")
            self._last_failure = (
                "verify",
                FAILURE,
                "server output did not contain echoed payload",
            )
            return False
        finally:
            self._cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="TLS interop driver (configuration from INTEROP_* and TLS_* env)."
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose logging (compact progress otherwise when stderr is a TTY)",
    )
    args = parser.parse_args()

    verbose = args.verbose or _env_truthy_positive("INTEROP_VERBOSE")
    server_grpc = os.environ.get("TLS_SERVER_GRPC", "localhost:50051")
    client_grpc = os.environ.get("TLS_CLIENT_GRPC", "localhost:50051")
    tls_hostname = os.environ.get("TLS_HOSTNAME", "localhost")

    driver = InteropDriver(server_grpc, client_grpc, verbose=verbose)

    try:
        _wait_grpc_peers(
            server_grpc,
            client_grpc,
            timeout_s=_env_float("INTEROP_GRPC_WAIT_SEC", _DEFAULT_GRPC_WAIT_S),
            verbose=verbose,
        )
    except TimeoutError as e:
        print(f"{RED}[Driver] {e}{RESET}")
        return 1

    if verbose:
        print("[Driver] Fetching metadata...")
    try:
        driver.server_metadata = driver.server_stub.GetMetadata(interop_pb2.Empty())
        driver.client_metadata = driver.client_stub.GetMetadata(interop_pb2.Empty())
        driver._log_metadata("Server", driver.server_metadata)
        driver._log_metadata("Client", driver.client_metadata)
    except Exception as e:
        print(f"{RED}[Driver] GetMetadata failed: {e}{RESET}")
        return 1

    cfg = tls_config_from_env()
    _fill_tls_hostname_and_port(cfg, tls_hostname)
    if skip := driver.scenario_skip_reason(cfg):
        if verbose:
            print(f"{YELLOW}[Driver] SKIP: {skip}{RESET}")
        else:
            short = skip[:72]
            print(f"{YELLOW}○{RESET}  interop{('  (' + short + ')') if short else ''}")
        return EXIT_SKIP

    driver._last_failure = None
    spinner: _QuietSpinner | None = None
    if not verbose and sys.stderr.isatty():
        spinner = _QuietSpinner()
        spinner.start()
    try:
        ok = driver.run_test(tls_hostname)
    finally:
        if spinner:
            spinner.stop()

    if driver._last_skip_reason:
        if verbose:
            print(f"{YELLOW}[Driver] SKIP: {driver._last_skip_reason}{RESET}")
            return EXIT_SKIP
        short = driver._last_skip_reason[:200].replace("\n", " ").strip()
        print(f"{YELLOW}○{RESET}  interop  ({short})")
        return EXIT_SKIP
    if verbose:
        return 0 if ok else 1
    detail = ""
    if not ok and driver._last_failure:
        detail = (driver._last_failure[2] or "").replace("\n", " ").strip()[:220]
    suf = f"  ({detail})" if detail else ""
    mark = f"{GREEN}✓{RESET}" if ok else f"{RED}✗{RESET}"
    print(f"{mark}  interop{suf}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

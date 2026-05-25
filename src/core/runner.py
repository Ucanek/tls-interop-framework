"""TLS interop runner: Docker Compose orchestration and gRPC test driver."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Literal, Mapping, TypeAlias

import grpc

from core.catalog import (
    FALLBACK_CIPHER_ID_TO_IANA,
    NON_TLS_OPTION_IDS,
    ensure_import_paths,
    load_options_catalog,
    norm_token,
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


# --- Docker Compose orchestration ---

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


def compose_driver_overlay_path(dotenv_abs: Path) -> Path:
    """Small merge file so ``driver`` gets ``env_file`` without ``compose run --env-file``."""
    dq = str(dotenv_abs).replace("\\", "/").replace('"', '\\"')
    yaml_text = (
        "services:\n"
        "  driver:\n"
        "    env_file:\n"
        f'      - "{dq}"\n'
    )
    fd, tmp = tempfile.mkstemp(suffix=".interop-driver.yml", prefix="interop-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(yaml_text)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return Path(tmp)


def sanitize_compose_project(name: str) -> str:
    s = "".join(c if c.isalnum() or c in "-_" else "-" for c in name.lower()).strip("-")
    return (s or "interop")[:63]


def compose_run(
    args: Any,
    repo: Path,
    *,
    compose_project_override: str | None = None,
    driver_dotenv_path: Path | None = None,
) -> int:
    matrix = repo / "deploy" / "compose.yaml"
    proj_env = (os.environ.get("INTEROP_COMPOSE_PROJECT") or "").strip()
    if compose_project_override:
        project = sanitize_compose_project(compose_project_override)
    elif proj_env:
        project = sanitize_compose_project(proj_env)
    else:
        project = f"interop-{args.server}-{args.client}"
    env = os.environ.copy()
    env["SERVER_WRAPPER"] = args.server
    env["CLIENT_WRAPPER"] = args.client
    env["INTEROP_GNUTLS_NSS_PAIR"] = (
        "1" if args.server == "gnutls" and args.client == "nss" else "0"
    )
    env.setdefault("TLS_SERVER_GRPC", "server_node:50051")
    env.setdefault("TLS_CLIENT_GRPC", "client_node:50051")
    env.setdefault("TLS_HOSTNAME", "server_node")
    env["INTEROP_VERBOSE"] = "1" if args.verbose else "0"

    dotenv_vars: dict[str, str] = {}

    for item in load_options_catalog(repo or repository_root()):
        oid = item["id"]
        if oid in NON_TLS_OPTION_IDS:
            continue
        val = getattr(args, oid)
        if val in (None, "", 0):
            continue
        if oid == "tls_port" and val == 0:
            continue
        key = f"INTEROP_{oid.upper()}"
        sval = str(val).strip()
        dotenv_vars[key] = sval

    dotenv_vars["TLS_SERVER_GRPC"] = env["TLS_SERVER_GRPC"]
    dotenv_vars["TLS_CLIENT_GRPC"] = env["TLS_CLIENT_GRPC"]
    dotenv_vars["TLS_HOSTNAME"] = env["TLS_HOSTNAME"]
    dotenv_vars["INTEROP_VERBOSE"] = env["INTEROP_VERBOSE"]

    dotenv_raw = (os.environ.get("INTEROP_DRIVER_DOTENV") or "").strip()
    if driver_dotenv_path is not None:
        interop_dotenv_abs = driver_dotenv_path.resolve()
    elif dotenv_raw:
        raw_p = Path(dotenv_raw)
        interop_dotenv_abs = (
            raw_p.resolve() if raw_p.is_absolute() else (repo / raw_p).resolve()
        )
    else:
        interop_dotenv_abs = interop_dotenv_path(repo).resolve()

    overlay_path: Path | None = None
    print(f"========== {args.server}x{args.client} ==========")
    try:
        overlay_path = compose_driver_overlay_path(interop_dotenv_abs)
        progress: list[str] = (
            [] if args.verbose else ["--progress", "quiet"]
        )
        compose = [
            "docker",
            "compose",
            *progress,
            "-p",
            project,
            "-f",
            str(matrix),
            "-f",
            str(overlay_path),
        ]
        down = compose + ["down", "--remove-orphans"]
        build = compose + ["build"] + ([] if args.verbose else ["-q"])
        run_cmd = compose + ["run", "--rm", "-T", "driver"]

        if args.dry_run:
            print("DRY-RUN compose commands:")
            if proj_env:
                print(f"# INTEROP_COMPOSE_PROJECT={proj_env!r}")
            if dotenv_raw:
                print(f"# INTEROP_DRIVER_DOTENV={dotenv_raw!r}")
            print(f"# would write driver env_file {interop_dotenv_abs}")
            print(f"# merge overlay {overlay_path}")
            print(" ".join(down))
            print(" ".join(build))
            print(" ".join(run_cmd))
            return 0

        write_interop_dotenv(interop_dotenv_abs, dotenv_vars)

        subprocess.run(down, cwd=repo, env=env, stdin=subprocess.DEVNULL, check=False)
        rc = 1
        try:
            subprocess.run(
                build, cwd=repo, env=env, stdin=subprocess.DEVNULL, check=True
            )
            run_res = subprocess.run(
                run_cmd, cwd=repo, env=env, stdin=subprocess.DEVNULL, check=False
            )
            drc = int(run_res.returncode)
            if drc == 0:
                rc = 0
            elif drc == EXIT_SKIP:
                rc = EXIT_SKIP
        except subprocess.CalledProcessError:
            rc = 1
        finally:
            subprocess.run(
                down, cwd=repo, env=env, stdin=subprocess.DEVNULL, check=False
            )
        return rc
    finally:
        if overlay_path is not None:
            try:
                overlay_path.unlink()
            except OSError:
                pass

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
        self.server_stub = interop_pb2_grpc.TlsInteropWrapperStub(
            grpc.insecure_channel(server_addr)
        )
        self.client_stub = interop_pb2_grpc.TlsInteropWrapperStub(
            grpc.insecure_channel(client_addr)
        )
        self._verbose = verbose
        self._last_failure: tuple[str, int, str] | None = None
        self._last_skip_reason: str | None = None
        self.server_metadata: interop_pb2.LibraryMetadata | None = None
        self.client_metadata: interop_pb2.LibraryMetadata | None = None

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

    def scenario_skip_reason(self, cfg: interop_pb2.TlsConfig) -> str | None:
        """Skip run if peer metadata disagrees with env ``TlsConfig`` (no scenario id)."""
        if self.server_metadata is None or self.client_metadata is None:
            return None
        srv = _role_config(cfg, interop_pb2.SERVER)
        cli = _role_config(cfg, interop_pb2.CLIENT)
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
        """ESTABLISH server → client → TCP wait → TRANSMIT (payload + echo check)."""
        self._last_skip_reason = None
        base_conf = tls_config_from_env()
        _fill_tls_hostname_and_port(base_conf, tls_hostname)
        ver = (base_conf.version or "").strip() or "default"
        server_conf = _role_config(base_conf, interop_pb2.SERVER)
        client_conf = _role_config(base_conf, interop_pb2.CLIENT)
        try:
            self._vprint(f"[Driver] Round-trip (TLS from env: {ver})")
            self._vprint("[Driver] Establishing connection...")
            r = self._execute_establish(self.server_stub, interop_pb2.SERVER, server_conf)
            if not self._check_response(r, "ESTABLISH server"):
                return False
            r = self._execute_establish(self.client_stub, interop_pb2.CLIENT, client_conf)
            if not self._check_response(r, "ESTABLISH client"):
                return False

            peer = (base_conf.server_hostname or "").strip() or "localhost"
            ok_peer, _ = wait_tcp_connect(
                peer, int(base_conf.port), timeout_s=_TCP_AFTER_ESTABLISH_S
            )
            if not ok_peer:
                self._vprint(
                    f"{RED}[Driver] Timeout waiting for TCP {peer}:{base_conf.port}{RESET}"
                )
                self._last_failure = (
                    "wait_tcp",
                    FAILURE,
                    f"TCP {peer}:{base_conf.port} not accepting after ESTABLISH",
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

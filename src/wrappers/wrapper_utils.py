"""
Shared utility helpers for TLS interop wrappers.

Also ensures repository root is on sys.path (dev: ``src/wrappers``; Docker: ``/app``).
"""

import fcntl
import os
import re
import shlex
import subprocess
import sys
import time

from proto import interop_pb2


def _discover_repo_root():
    here = os.path.dirname(os.path.abspath(__file__))
    for root in (
        os.path.abspath(os.path.join(here, "..", "..")),
        here,
    ):
        if os.path.isdir(os.path.join(root, "proto")):
            return root
    return os.path.abspath(os.path.join(here, "..", ".."))


_REPO_ROOT = _discover_repo_root()
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

FAIL_LOG_TAIL = 600


def parse_version_line(out):
    """Extract a short version string (e.g. '3.0.2') from CLI stdout/stderr."""
    text = (out or "").strip()
    first_line = text.split("\n")[0].strip() if text else ""
    match = re.search(r"\d+\.\d+(?:\.\d+)?", first_line)
    return match.group(0) if match else (first_line[:40] if first_line else "unknown")


def tls_mode_12_or_13(config):
    """Map TlsConfig.version to '1.2' or '1.3' (aligned with driver aliases)."""
    if config is None:
        return "1.3"
    v = (config.version or "").strip().lower()
    if v in ("1.2", "1.2.0", "tls1.2", "tls1_2"):
        return "1.2"
    if v in ("1.3", "1.3.0", "tls1.3", "tls1_3"):
        return "1.3"
    upper = (config.version or "").strip().upper().replace(" ", "")
    if upper == "TLS1.2":
        return "1.2"
    if upper == "TLS1.3":
        return "1.3"
    return "1.3"


def make_non_blocking(fd):
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


def format_executed_command(cmd, cwd=None):
    """Shell-safe one-liner for logs."""
    line = shlex.join(str(x) for x in cmd)
    if cwd is not None:
        return f"cwd={shlex.quote(os.path.abspath(cwd))} {line}"
    return line


def popen_stdio_merged(cmd, *, cwd=None):
    p = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=cwd,
    )
    if p.stdout:
        make_non_blocking(p.stdout)
    return p


def tail_merged_output(proc, limit=FAIL_LOG_TAIL):
    """Last ``limit`` chars of merged stdout/stderr for failure diagnostics."""
    if proc is None or proc.stdout is None:
        return ""
    try:
        raw = (proc.stdout.read() or b"").decode(errors="replace")[-limit:]
        return raw.strip().replace("\n", " ")
    except OSError:
        return ""


def format_client_connect_failure(
    proc,
    base="Client process exited (connection failed)",
):
    detail = tail_merged_output(proc)
    return f"{base} | {detail}" if detail else base


def transmit_payload_bytes(payload, role):
    """Newline suffix; HTTP-like POST prefix when the client sends."""
    data = payload + b"\n"
    if role == interop_pb2.CLIENT:
        data = b"POST / HTTP/1.0\r\n\r\n" + data
    return data


def read_transmit_stdout(proc, role, *, server_poll=False):
    """
    Read echoed data after TRANSMIT.
    ``server_poll=True``: short polling loop (buffered server tools, e.g. NSS selfserv).
    """
    try:
        if server_poll and role == interop_pb2.SERVER:
            time.sleep(0.8)
            out_data = b""
            for _ in range(25):
                try:
                    chunk = proc.stdout.read()
                    if chunk:
                        out_data += chunk
                except (BlockingIOError, OSError):
                    pass
                time.sleep(0.1)
            return out_data
        return proc.stdout.read() or b""
    except OSError:
        return b""

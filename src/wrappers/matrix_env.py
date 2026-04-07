"""
Docker matrix integration: env vars set by deploy/matrix.yaml and scripts/run.sh (docker).

Keep the variable name in sync with YAML/shell (search for GNUTLS_NSS_PAIR_ENV).
"""

from __future__ import annotations

import os
import socket

# Must match deploy/matrix.yaml and scripts/run.sh (export_matrix_env_for_pair).
GNUTLS_NSS_PAIR_ENV = "INTEROP_GNUTLS_NSS_PAIR"

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def gnutls_nss_pair_enabled() -> bool:
    """GnuTLS server × NSS client row in the compose matrix."""
    return os.environ.get(GNUTLS_NSS_PAIR_ENV, "0").strip().lower() in _TRUTHY


def tstclnt_host_and_extra_argv(hostname: str, port: int) -> tuple[str, list[str]]:
    """
    Return (value for tstclnt -h, extra argv inserted after -p).

    Normally: connect to the configured hostname and pass ``-a <same>`` so SNI matches
    (needed for virtual-host style servers).

    For GnuTLS×NSS in Docker: TCP goes to a resolved IP while DNS SNI would still carry
    the service name; GnuTLS 3.8+ rejects that. Resolve the hostname to an address,
    use it for ``-h``, and omit ``-a``. Fallback to hostname + ``-a`` if lookup fails.
    """
    h = hostname or "localhost"
    p = int(port)
    if not gnutls_nss_pair_enabled():
        return h, ["-a", h]
    try:
        for fam in (socket.AF_INET, socket.AF_INET6):
            infos = socket.getaddrinfo(h, p, family=fam, type=socket.SOCK_STREAM)
            if infos:
                return str(infos[0][4][0]), []
    except OSError:
        pass
    return h, ["-a", h]

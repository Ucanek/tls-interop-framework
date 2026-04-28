"""
GnuTLS wrapper: gnutls-serv / gnutls-cli for the TLS interop matrix.

Client uses --disable-sni to avoid DISALLOWED_NAME when the peer is an IP or Docker
service name; priorities pin TLS 1.2 vs 1.3 per TlsConfig.version.
"""
import os

from wrapper_utils import (
    format_executed_command,
    popen_stdio_merged,
    tls_mode_12_or_13,
)
from wrapper_template import BaseTemplateWrapper, serve_insecure


class GnuTLSWrapper(BaseTemplateWrapper):
    @property
    def _component_name(self) -> str:
        return "GnuTLS"

    def _version_command(self) -> list[str]:
        return ["gnutls-cli", "--version"]

    def _start_server(self, config):
        cmd = [
            "gnutls-serv",
            "-p",
            str(config.port),
            "-a",
            "--x509certfile",
            "cert.pem",
            "--x509keyfile",
            "key.pem",
            "--priority",
            "NORMAL:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1",
            "-q",
            "--echo",
        ]
        cwd = os.getcwd()
        return (
            popen_stdio_merged(cmd, cwd=cwd),
            format_executed_command(cmd, cwd),
            "GnuTLS Server started",
        )

    def _start_client(self, config):
        host = config.server_hostname or "localhost"
        if tls_mode_12_or_13(config) == "1.2":
            prio = "NORMAL:-VERS-ALL:+VERS-TLS1.2"
        else:
            prio = "NORMAL:-VERS-ALL:+VERS-TLS1.3"
        cmd = [
            "gnutls-cli",
            "-p",
            str(config.port),
            "--disable-sni",
            "--verify-hostname",
            host,
            "--x509cafile",
            "cert.pem",
            "--priority",
            prio,
            host,
        ]
        cwd = os.getcwd()
        return (
            popen_stdio_merged(cmd, cwd=cwd),
            format_executed_command(cmd, cwd),
            "GnuTLS Client connected",
        )

    def _server_transmit_poll(self) -> bool:
        return True


if __name__ == "__main__":
    serve_insecure(GnuTLSWrapper, "GnuTLS")

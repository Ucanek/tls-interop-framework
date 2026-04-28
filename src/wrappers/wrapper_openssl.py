import os

from wrapper_utils import (
    format_executed_command,
    popen_stdio_merged,
    tls_mode_12_or_13,
)
from wrapper_template import BaseTemplateWrapper, serve_insecure


class OpenSSLWrapper(BaseTemplateWrapper):
    @property
    def _component_name(self) -> str:
        return "OpenSSL"

    def _version_command(self) -> list[str]:
        return ["openssl", "version"]

    def _start_server(self, config):
        tls_flag = "-tls1_2" if tls_mode_12_or_13(config) == "1.2" else "-tls1_3"
        cmd = [
            "openssl",
            "s_server",
            "-accept",
            f"0.0.0.0:{config.port}",
            "-cert",
            "cert.pem",
            "-key",
            "key.pem",
            tls_flag,
            "-quiet",
        ]
        cwd = os.getcwd()
        return popen_stdio_merged(cmd, cwd=cwd), format_executed_command(cmd, cwd), "Server started"

    def _start_client(self, config):
        tls_flag = "-tls1_2" if tls_mode_12_or_13(config) == "1.2" else "-tls1_3"
        cmd = [
            "openssl",
            "s_client",
            "-connect",
            f"{config.server_hostname}:{config.port}",
            tls_flag,
            "-quiet",
        ]
        cwd = os.getcwd()
        return popen_stdio_merged(cmd, cwd=cwd), format_executed_command(cmd, cwd), "Client connected"


if __name__ == "__main__":
    serve_insecure(OpenSSLWrapper, "OpenSSL")

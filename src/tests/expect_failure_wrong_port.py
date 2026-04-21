"""Server on configured port; client connects to another port — expect client ESTABLISH to fail."""
from proto import interop_pb2

_GREEN = "\033[92m"
_RED = "\033[91m"
_RESET = "\033[0m"
_SUCCESS = interop_pb2.OperationResponse.SUCCESS


def run(driver, tls_hostname):
    good_conf = driver._default_config(tls_hostname, "1.3")
    bad_conf = interop_pb2.TlsConfig(
        version=good_conf.version,
        server_hostname=good_conf.server_hostname,
        port=good_conf.port + 1,
    )
    try:
        driver._vprint("[Driver] Scenario: expect failure (wrong port)")
        driver._vprint("[Driver] Establishing server...")
        r = driver.server_stub.ExecuteOperation(
            interop_pb2.OperationRequest(
                type=interop_pb2.OperationRequest.ESTABLISH,
                role=interop_pb2.SERVER,
                config=good_conf,
            )
        )
        if not driver._check_response(r, "ESTABLISH server"):
            return False

        driver._vprint(
            f"[Driver] Establishing client (port {bad_conf.port}, no listener)..."
        )
        r = driver.client_stub.ExecuteOperation(
            interop_pb2.OperationRequest(
                type=interop_pb2.OperationRequest.ESTABLISH,
                role=interop_pb2.CLIENT,
                config=bad_conf,
            )
        )
        if r.status == _SUCCESS:
            driver._vprint(
                f"{_RED}>>> SCENARIO FAILED: Expected client to fail, got SUCCESS <<<{_RESET}"
            )
            driver._last_failure = (
                "ESTABLISH client",
                _SUCCESS,
                "expected TLS failure (wrong port)",
            )
            return False
        driver._vprint(
            f"{_GREEN}>>> SCENARIO PASSED: Client failed as expected ({r.message or r.status}) <<<{_RESET}"
        )
        return True
    finally:
        driver._cleanup()

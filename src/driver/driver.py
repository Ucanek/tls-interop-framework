import argparse
import os
import sys
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import grpc
import interop_pb2
import interop_pb2_grpc

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

SUCCESS = interop_pb2.OperationResponse.SUCCESS
FAILURE = interop_pb2.OperationResponse.FAILURE
ERROR = interop_pb2.OperationResponse.ERROR

# scenario name -> TlsConfig.version used by that scenario (mapped to GetMetadata capability names)
_SCENARIO_TLS_REQUIREMENT = {
    "establish_transmit_close": "1.3",
    "expect_failure_wrong_hostname": "1.3",
}


def _tls_config_version_to_capability_name(version_str):
    """Map driver TlsConfig.version to Capability.name from wrappers (e.g. TLS1.3)."""
    if version_str is None or str(version_str).strip() == "":
        return "TLS1.3"
    low = str(version_str).strip().lower()
    if low in ("1.2", "1.2.0", "tls1.2", "tls1_2"):
        return "TLS1.2"
    if low in ("1.3", "1.3.0", "tls1.3", "tls1_3"):
        return "TLS1.3"
    upper = str(version_str).strip().upper().replace(" ", "")
    if upper in ("TLS1.2", "TLS1.3"):
        return upper
    return "TLS1.3"


class InteropDriver:
    def __init__(self, server_addr, client_addr):
        self.server_stub = interop_pb2_grpc.TlsInteropWrapperStub(
            grpc.insecure_channel(server_addr)
        )
        self.client_stub = interop_pb2_grpc.TlsInteropWrapperStub(
            grpc.insecure_channel(client_addr)
        )
        self._last_failure = None
        self.server_metadata = None
        self.client_metadata = None

    def _log_metadata(self, label, metadata):
        role_names = {1: "CLIENT", 2: "SERVER"}
        roles_str = [role_names.get(r, str(r)) for r in metadata.roles]
        print(f"[Driver] {label}: {metadata.component_name} {metadata.version}")
        print(f"         roles={roles_str}")
        versions = [c.name for c in metadata.supported_versions]
        print(f"         supported_versions={versions[:5]}{'...' if len(versions) > 5 else ''}")

    def _metadata_can_negotiate_version(self, metadata, capability_name, role):
        """True if role is allowed and TLS version is listed with NEGOTIATE; empty supported_versions => allow."""
        if metadata is None:
            return True
        if metadata.roles and role not in metadata.roles:
            return False
        caps = list(metadata.supported_versions)
        if not caps:
            return True
        for c in caps:
            if c.name == capability_name and interop_pb2.NEGOTIATE in c.flags:
                return True
        return False

    def scenario_skip_reason(self, scenario_name):
        """If scenario should be skipped from GetMetadata, return reason; else None."""
        need_tls = _SCENARIO_TLS_REQUIREMENT.get(scenario_name)
        if need_tls is None or self.server_metadata is None or self.client_metadata is None:
            return None
        cap_name = _tls_config_version_to_capability_name(need_tls)
        if not self._metadata_can_negotiate_version(
            self.server_metadata, cap_name, interop_pb2.SERVER
        ):
            return (
                f"server ({self.server_metadata.component_name}) cannot negotiate {cap_name} "
                "per GetMetadata"
            )
        if not self._metadata_can_negotiate_version(
            self.client_metadata, cap_name, interop_pb2.CLIENT
        ):
            return (
                f"client ({self.client_metadata.component_name}) cannot negotiate {cap_name} "
                "per GetMetadata"
            )
        return None

    def _check_response(self, resp, label):
        """Return True if status is SUCCESS, else set _last_failure and return False."""
        if resp.status == SUCCESS:
            return True
        self._last_failure = (label, resp.status, resp.message or resp.logs)
        status_name = "FAILURE" if resp.status == FAILURE else "ERROR"
        print(f"{RED}[Driver] {label}: {status_name} - {resp.message or resp.logs or 'no message'}{RESET}")
        return False

    def _cleanup(self):
        print("[Driver] Cleaning up...")
        for stub, role in [(self.server_stub, "server"), (self.client_stub, "client")]:
            try:
                r = stub.ExecuteOperation(
                    interop_pb2.OperationRequest(type=interop_pb2.OperationRequest.CLOSE)
                )
                self._check_response(r, f"CLOSE {role}")
            except Exception as e:
                print(f"[Driver] CLOSE {role} exception: {e}")

    def _default_config(self, tls_hostname):
        return interop_pb2.TlsConfig(
            version="1.3",
            server_hostname=tls_hostname,
            port=5555,
        )

    def run_establish_transmit_close(self, tls_hostname):
        """Scenario: establish TLS, transmit payload, verify data, then close. Expect SUCCESS."""
        conf = self._default_config(tls_hostname)
        test_message = b"INTEROP_SECRET_TOKEN"
        try:
            print("[Driver] Scenario: establish → transmit → close")
            print("[Driver] Establishing connection...")
            r = self.server_stub.ExecuteOperation(
                interop_pb2.OperationRequest(
                    type=interop_pb2.OperationRequest.ESTABLISH,
                    role=interop_pb2.SERVER,
                    config=conf,
                )
            )
            if not self._check_response(r, "ESTABLISH server"):
                return False
            r = self.client_stub.ExecuteOperation(
                interop_pb2.OperationRequest(
                    type=interop_pb2.OperationRequest.ESTABLISH,
                    role=interop_pb2.CLIENT,
                    config=conf,
                )
            )
            if not self._check_response(r, "ESTABLISH client"):
                return False

            time.sleep(0.5)
            print(f"[Driver] Transmitting: {test_message.decode()}")
            r = self.client_stub.ExecuteOperation(
                interop_pb2.OperationRequest(
                    type=interop_pb2.OperationRequest.TRANSMIT,
                    role=interop_pb2.CLIENT,
                    payload=test_message,
                )
            )
            if not self._check_response(r, "TRANSMIT client"):
                return False

            time.sleep(1)
            r = self.server_stub.ExecuteOperation(
                interop_pb2.OperationRequest(
                    type=interop_pb2.OperationRequest.TRANSMIT,
                    role=interop_pb2.SERVER,
                )
            )
            if not self._check_response(r, "TRANSMIT server"):
                return False

            if test_message in r.output_data:
                print(f"{GREEN}>>> SCENARIO PASSED: Data successfully transmitted <<<{RESET}")
                return True
            print(f"{RED}>>> SCENARIO FAILED: Data corruption <<<{RESET}")
            return False
        finally:
            self._cleanup()

    def run_expect_failure_wrong_hostname(self, tls_hostname):
        """Scenario: server listens; client connects with wrong hostname. Expect client ESTABLISH to fail."""
        good_conf = self._default_config(tls_hostname)
        bad_conf = interop_pb2.TlsConfig(
            version="1.3",
            server_hostname="wrong-hostname.invalid",
            port=good_conf.port,
        )
        try:
            print("[Driver] Scenario: expect failure (wrong hostname)")
            print("[Driver] Establishing server...")
            r = self.server_stub.ExecuteOperation(
                interop_pb2.OperationRequest(
                    type=interop_pb2.OperationRequest.ESTABLISH,
                    role=interop_pb2.SERVER,
                    config=good_conf,
                )
            )
            if not self._check_response(r, "ESTABLISH server"):
                return False

            print("[Driver] Establishing client (wrong hostname)...")
            r = self.client_stub.ExecuteOperation(
                interop_pb2.OperationRequest(
                    type=interop_pb2.OperationRequest.ESTABLISH,
                    role=interop_pb2.CLIENT,
                    config=bad_conf,
                )
            )
            if r.status == SUCCESS:
                print(f"{RED}>>> SCENARIO FAILED: Expected client to fail, got SUCCESS <<<{RESET}")
                return False
            print(f"{GREEN}>>> SCENARIO PASSED: Client failed as expected ({r.message or r.status}) <<<{RESET}")
            return True
        finally:
            self._cleanup()

    def run_scenario(self, name, tls_hostname):
        """Run one scenario. Returns True if passed or skipped (capability filter)."""
        scenarios = {
            "establish_transmit_close": self.run_establish_transmit_close,
            "expect_failure_wrong_hostname": self.run_expect_failure_wrong_hostname,
        }
        if name not in scenarios:
            print(f"{RED}[Driver] Unknown scenario: {name}{RESET}")
            return False
        skip = self.scenario_skip_reason(name)
        if skip:
            print(f"{YELLOW}[Driver] SKIP {name}: {skip}{RESET}")
            return True
        return scenarios[name](tls_hostname)

    def run_all_scenarios(self, tls_hostname):
        """Run all scenarios. Returns True iff all passed."""
        names = ["establish_transmit_close", "expect_failure_wrong_hostname"]
        results = []
        for name in names:
            results.append(self.run_scenario(name, tls_hostname))
        return all(results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TLS Interop driver")
    parser.add_argument(
        "--scenario",
        default="all",
        choices=["all", "establish_transmit_close", "expect_failure_wrong_hostname"],
        help="Scenario to run (default: all)",
    )
    args = parser.parse_args()

    server_grpc = os.environ.get("TLS_SERVER_GRPC", "localhost:50051")
    client_grpc = os.environ.get("TLS_CLIENT_GRPC", "localhost:50051")
    tls_hostname = os.environ.get("TLS_HOSTNAME", "localhost")

    driver = InteropDriver(server_grpc, client_grpc)

    print("[Driver] Fetching metadata...")
    try:
        driver.server_metadata = driver.server_stub.GetMetadata(interop_pb2.Empty())
        driver.client_metadata = driver.client_stub.GetMetadata(interop_pb2.Empty())
        driver._log_metadata("Server", driver.server_metadata)
        driver._log_metadata("Client", driver.client_metadata)
    except Exception as e:
        print(f"{RED}[Driver] GetMetadata failed: {e}{RESET}")
        sys.exit(1)

    if args.scenario == "all":
        ok = driver.run_all_scenarios(tls_hostname)
    else:
        ok = driver.run_scenario(args.scenario, tls_hostname)

    sys.exit(0 if ok else 1)

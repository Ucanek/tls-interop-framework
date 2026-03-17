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
RESET = "\033[0m"

SUCCESS = interop_pb2.OperationResponse.SUCCESS
FAILURE = interop_pb2.OperationResponse.FAILURE
ERROR = interop_pb2.OperationResponse.ERROR


class InteropDriver:
    def __init__(self, server_addr, client_addr):
        self.server_stub = interop_pb2_grpc.TlsInteropWrapperStub(
            grpc.insecure_channel(server_addr)
        )
        self.client_stub = interop_pb2_grpc.TlsInteropWrapperStub(
            grpc.insecure_channel(client_addr)
        )
        self._last_failure = None

    def _log_metadata(self, label, metadata):
        role_names = {1: "CLIENT", 2: "SERVER"}
        roles_str = [role_names.get(r, str(r)) for r in metadata.roles]
        print(f"[Driver] {label}: {metadata.component_name} {metadata.version}")
        print(f"         roles={roles_str}")
        versions = [c.name for c in metadata.supported_versions]
        print(f"         supported_versions={versions[:5]}{'...' if len(versions) > 5 else ''}")

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
        """Run one scenario by name. Returns True if passed."""
        scenarios = {
            "establish_transmit_close": self.run_establish_transmit_close,
            "expect_failure_wrong_hostname": self.run_expect_failure_wrong_hostname,
        }
        if name not in scenarios:
            print(f"{RED}[Driver] Unknown scenario: {name}{RESET}")
            return False
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
        server_meta = driver.server_stub.GetMetadata(interop_pb2.Empty())
        client_meta = driver.client_stub.GetMetadata(interop_pb2.Empty())
        driver._log_metadata("Server", server_meta)
        driver._log_metadata("Client", client_meta)
    except Exception as e:
        print(f"{RED}[Driver] GetMetadata failed: {e}{RESET}")
        sys.exit(1)

    if args.scenario == "all":
        ok = driver.run_all_scenarios(tls_hostname)
    else:
        ok = driver.run_scenario(args.scenario, tls_hostname)

    sys.exit(0 if ok else 1)

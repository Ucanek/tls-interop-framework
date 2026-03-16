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


class InteropDriver:
    def __init__(self, server_addr, client_addr):
        self.server_stub = interop_pb2_grpc.TlsInteropWrapperStub(
            grpc.insecure_channel(server_addr)
        )
        self.client_stub = interop_pb2_grpc.TlsInteropWrapperStub(
            grpc.insecure_channel(client_addr)
        )

    def run_full_test(self, tls_hostname="localhost"):
        conf = interop_pb2.TlsConfig(
            version="1.3",
            server_hostname=tls_hostname,
            port=5555,
        )
        test_message = b"INTEROP_SECRET_TOKEN"

        try:
            print("[Driver] Establishing connection...")
            self.server_stub.ExecuteOperation(
                interop_pb2.OperationRequest(
                    type=interop_pb2.OperationRequest.ESTABLISH,
                    role=interop_pb2.SERVER,
                    config=conf,
                )
            )
            self.client_stub.ExecuteOperation(
                interop_pb2.OperationRequest(
                    type=interop_pb2.OperationRequest.ESTABLISH,
                    role=interop_pb2.CLIENT,
                    config=conf,
                )
            )

            print(f"[Driver] Transmitting: {test_message.decode()}")
            self.client_stub.ExecuteOperation(
                interop_pb2.OperationRequest(
                    type=interop_pb2.OperationRequest.TRANSMIT,
                    role=interop_pb2.CLIENT,
                    payload=test_message,
                )
            )

            time.sleep(1)
            resp = self.server_stub.ExecuteOperation(
                interop_pb2.OperationRequest(
                    type=interop_pb2.OperationRequest.TRANSMIT,
                    role=interop_pb2.SERVER,
                )
            )

            if test_message in resp.output_data:
                print(f"{GREEN}>>> TEST PASSED: Data successfully transmitted! <<<{RESET}")
            else:
                print(f"{RED}>>> TEST FAILED: Data corruption! <<<{RESET}")

        finally:
            print("[Driver] Cleaning up...")
            self.server_stub.ExecuteOperation(
                interop_pb2.OperationRequest(type=interop_pb2.OperationRequest.CLOSE)
            )
            self.client_stub.ExecuteOperation(
                interop_pb2.OperationRequest(type=interop_pb2.OperationRequest.CLOSE)
            )


if __name__ == "__main__":
    server_grpc = os.environ.get("TLS_SERVER_GRPC", "localhost:50051")
    client_grpc = os.environ.get("TLS_CLIENT_GRPC", "localhost:50051")
    tls_hostname = os.environ.get("TLS_HOSTNAME", "localhost")
    driver = InteropDriver(server_grpc, client_grpc)
    driver.run_full_test(tls_hostname=tls_hostname)

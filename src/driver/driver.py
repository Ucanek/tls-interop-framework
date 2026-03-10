import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

import grpc
import interop_pb2
import interop_pb2_grpc
import time

GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'

class InteropDriver:
    def __init__(self, server_addr, client_addr):
        # We use two separate channels for true interoperability
        self.server_stub = interop_pb2_grpc.TlsInteropWrapperStub(grpc.insecure_channel(server_addr))
        self.client_stub = interop_pb2_grpc.TlsInteropWrapperStub(grpc.insecure_channel(client_addr))

    def run_full_test(self):
        # Configuration for the TLS session
        conf = interop_pb2.TlsConfig(
            version="1.3", 
            server_hostname="localhost", # This will change to 'server_node' in Docker
            port=5555
        )
        test_message = b"INTEROP_SECRET_TOKEN"

        try:
            print("[Driver] Establishing connection...")
            self.server_stub.ExecuteOperation(interop_pb2.OperationRequest(type=0, role=interop_pb2.SERVER, config=conf))
            self.client_stub.ExecuteOperation(interop_pb2.OperationRequest(type=0, role=interop_pb2.CLIENT, config=conf))

            print(f"[Driver] Transmitting: {test_message.decode()}")
            self.client_stub.ExecuteOperation(interop_pb2.OperationRequest(type=1, role=interop_pb2.CLIENT, payload=test_message))

            time.sleep(1)
            resp = self.server_stub.ExecuteOperation(interop_pb2.OperationRequest(type=1, role=interop_pb2.SERVER))

            if test_message in resp.output_data:
                print(f"{GREEN}>>> ✅ TEST PASSED: Data successfully transmitted! <<<{RESET}")
            else:
                print(f"{RED}>>> ❌ TEST FAILED: Data corruption! <<<{RESET}")

        finally:
            print("[Driver] Cleaning up...")
            self.server_stub.ExecuteOperation(interop_pb2.OperationRequest(type=2))
            self.client_stub.ExecuteOperation(interop_pb2.OperationRequest(type=2))

if __name__ == '__main__':
    # For now, both server and client point to the same local wrapper
    driver = InteropDriver('localhost:50051', 'localhost:50051')
    driver.run_full_test()
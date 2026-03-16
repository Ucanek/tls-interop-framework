#!/bin/bash
# Run the interoperability test without Docker. Requires: Python 3, grpcio, openssl CLI.
# Generate certs first: ./scripts/gen_certs.sh (from repo root).

set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -f cert.pem || ! -f key.pem ]]; then
  echo "Missing cert.pem or key.pem. Run: ./scripts/gen_certs.sh"
  exit 1
fi

python3 -c "import grpc, interop_pb2" 2>/dev/null || {
  echo "Error: cannot import grpc or interop_pb2. Install in a venv:"
  echo "  pip install grpcio grpcio-tools 'protobuf>=4.21'"
  echo "  python -m grpc_tools.protoc -I proto --python_out=. --grpc_python_out=. proto/interop.proto"
  echo "  (keep generated interop_pb2.py and interop_pb2_grpc.py in repo root)"
  exit 1
}

cleanup() {
  echo "[run_local] Stopping wrappers..."
  kill "$PID1" "$PID2" 2>/dev/null || true
  wait "$PID1" "$PID2" 2>/dev/null || true
}
trap cleanup EXIT

echo "[run_local] Starting server wrapper (gRPC 50051)..."
python3 src/wrappers/wrapper_openssl.py &
PID1=$!
sleep 1

echo "[run_local] Starting client wrapper (gRPC 50052)..."
GRPC_PORT=50052 python3 src/wrappers/wrapper_openssl.py &
PID2=$!
sleep 2

echo "[run_local] Running driver..."
TLS_SERVER_GRPC=localhost:50051 TLS_CLIENT_GRPC=localhost:50052 TLS_HOSTNAME=localhost \
  python3 src/driver/driver.py

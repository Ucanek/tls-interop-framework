#!/bin/bash
# Run the interop test in Docker and then stop all containers.
# Usage: ./scripts/run_docker.sh [compose-file]
#   Default: deploy/docker-compose.yaml (OpenSSL server, GnuTLS client)
#   Matrix (parameterized): export SERVER_WRAPPER=… CLIENT_WRAPPER=… then
#     ./scripts/run_docker.sh deploy/combos/matrix.yaml

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMPOSE_FILE="${1:-deploy/docker-compose.yaml}"

echo "[run_docker] Running driver (compose: $COMPOSE_FILE)..."
EXIT=0
docker compose -f "$COMPOSE_FILE" run --rm --build driver || EXIT=$?

echo "[run_docker] Stopping all containers..."
docker compose -f "$COMPOSE_FILE" down --remove-orphans

exit "$EXIT"

#!/bin/bash
# Single entry point for local prep, tests, and Docker matrix runs.
#
#   ./scripts/run.sh                    # all 9 Docker combos (deploy/matrix.yaml)
#   ./scripts/run.sh docker [args]      # same; see "Selecting pairs" below
#   Selecting pairs (docker / default):
#     (no args)                         all 9 combos
#     openssl nss                       one combo (two words)
#     openssl-nss                       one combo (hyphen)
#     nss-nss,gnutls-openssl            several combos, comma-separated srv-cli
#   ./scripts/run.sh local              # host test (OpenSSL×OpenSSL, no Docker)
#   ./scripts/run.sh certs              # cert.pem / key.pem
#   ./scripts/run.sh protoc             # regenerate interop_pb2*.py
#   ./scripts/run.sh capability-test    # driver capability filter self-check
#   ./scripts/run.sh ci                 # protoc + certs + capability + local + docker (like CI)
#   ./scripts/run.sh help

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

MATRIX="deploy/matrix.yaml"
# INTEROP_GNUTLS_NSS_PAIR must match GNUTLS_NSS_PAIR_ENV in src/wrappers/matrix_env.py

usage() {
  cat <<'EOF'
./scripts/run.sh [command] [args]

  (no command)     All 9 Docker matrix combos
  docker|combos   Same; optional: --all | <srv> <cli> | srv-cli | srv-cli,srv-cli,...
  local           Host test (OpenSSL wrappers + driver)
  certs           Generate cert.pem / key.pem (gen_certs.sh)
  protoc          Regenerate interop_pb2*.py from proto/
  capability-test Run scripts/test_capability_filter.py
  ci              protoc, certs, capability-test, local, docker (full pipeline)
  help            This text
EOF
}

cmd_protoc() {
  python3 -m grpc_tools.protoc -I proto --python_out=. --grpc_python_out=. proto/interop.proto
}

cmd_certs() {
  "$SCRIPT_DIR/gen_certs.sh"
}

cmd_capability() {
  python3 "$SCRIPT_DIR/test_capability_filter.py"
}

cmd_local() {
  if [[ ! -f cert.pem || ! -f key.pem ]]; then
    echo "Missing cert.pem or key.pem. Run: ./scripts/run.sh certs" >&2
    exit 1
  fi

  python3 -c "import grpc, interop_pb2" 2>/dev/null || {
    echo "Error: cannot import grpc or interop_pb2. Install in a venv:" >&2
    echo "  pip install 'grpcio>=1.80.0' 'grpcio-tools>=1.80.0' 'protobuf>=4.21'" >&2
    echo "  ./scripts/run.sh protoc" >&2
    exit 1
  }

  cleanup() {
    echo "[run] local: stopping wrappers..."
    kill "$PID1" "$PID2" 2>/dev/null || true
    wait "$PID1" "$PID2" 2>/dev/null || true
  }
  trap cleanup EXIT

  echo "[run] local: stopping any existing wrappers..."
  pkill -f "wrapper_openssl|wrapper_gnutls" 2>/dev/null || true
  sleep 2

  echo "[run] local: starting server wrapper (gRPC 50051)..."
  python3 src/wrappers/wrapper_openssl.py &
  PID1=$!
  sleep 1

  echo "[run] local: starting client wrapper (gRPC 50052)..."
  GRPC_PORT=50052 python3 src/wrappers/wrapper_openssl.py &
  PID2=$!
  sleep 2

  echo "[run] local: running driver..."
  TLS_SERVER_GRPC=localhost:50051 TLS_CLIENT_GRPC=localhost:50052 TLS_HOSTNAME=localhost \
    python3 src/driver/driver.py
}

# --- Docker matrix ---

FAILED=()
PASSED=()

export_matrix_env_for_pair() {
  local srv="$1" cli="$2"
  export SERVER_WRAPPER="$srv" CLIENT_WRAPPER="$cli"
  if [[ "$srv" == gnutls && "$cli" == nss ]]; then
    export INTEROP_GNUTLS_NSS_PAIR=1
  else
    export INTEROP_GNUTLS_NSS_PAIR=0
  fi
}

run_combo() {
  local srv="$1" cli="$2"
  local name="${srv}×${cli}"
  local project="interop-${srv}-${cli}"
  echo ""
  echo "========== $name =========="
  export_matrix_env_for_pair "$srv" "$cli"
  docker compose -p "$project" -f "$MATRIX" down --remove-orphans 2>/dev/null || true
  if docker compose -p "$project" -f "$MATRIX" run --rm --build driver 2>&1; then
    PASSED+=("$name")
    docker compose -p "$project" -f "$MATRIX" down --remove-orphans 2>/dev/null || true
    return 0
  else
    FAILED+=("$name")
    docker compose -p "$project" -f "$MATRIX" down --remove-orphans 2>/dev/null || true
    return 1
  fi
}

MATRIX_PAIRS=(
  "openssl openssl"
  "openssl gnutls"
  "openssl nss"
  "gnutls openssl"
  "gnutls gnutls"
  "gnutls nss"
  "nss openssl"
  "nss gnutls"
  "nss nss"
)

_trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

_valid_wrapper() {
  case "$1" in openssl | gnutls | nss) return 0 ;; *) return 1 ;; esac
}

_matrix_summary() {
  echo ""
  echo "========== Summary =========="
  echo "Passed: ${#PASSED[@]} (${PASSED[*]:-none})"
  echo "Failed: ${#FAILED[@]} (${FAILED[*]:-none})"
  [[ ${#FAILED[@]} -eq 0 ]] && return 0 || return 1
}

# One srv-cli chunk from a comma-separated list (names must not contain '-')
run_matrix_segment() {
  local seg="$(_trim "$1")"
  [[ -z "$seg" ]] && return 0
  if [[ "$seg" == *' '* ]] || [[ "$seg" != *-* ]] || [[ "${seg#*-}" == *-* ]]; then
    echo "Invalid pair (use server-client): $1" >&2
    exit 1
  fi
  local srv="${seg%%-*}" cli="${seg#*-}"
  if ! _valid_wrapper "$srv" || ! _valid_wrapper "$cli"; then
    echo "Unknown wrapper (use openssl, gnutls, nss): '$srv' '$cli'" >&2
    exit 1
  fi
  run_combo "$srv" "$cli" || true
}

cmd_docker_matrix() {
  if [[ "${1:-}" == "--all" ]]; then
    shift
  fi
  if [[ "${1:-}" == -* ]]; then
    echo "Unknown option: $1" >&2
    exit 1
  fi

  if [[ $# -eq 0 ]]; then
    for pair in "${MATRIX_PAIRS[@]}"; do
      set -- $pair
      run_combo "$1" "$2" || true
    done
    _matrix_summary && exit 0 || exit 1
  fi

  # Exactly one pair as two words (no comma in the whole invocation)
  if [[ $# -eq 2 ]] && [[ "$*" != *','* ]]; then
    if ! _valid_wrapper "$1" || ! _valid_wrapper "$2"; then
      echo "Unknown wrapper: '$1' / '$2'" >&2
      exit 1
    fi
    run_combo "$1" "$2"
    exit $?
  fi

  # Exactly one pair as server-client (single hyphen, no comma)
  if [[ $# -eq 1 ]] && [[ "$1" == *-* ]] && [[ "$1" != *','* ]]; then
    local a b c
    IFS='-' read -r a b c <<<"$1"
    if [[ -n "$c" || -z "${b:-}" ]]; then
      echo "Unknown combo name: $1 (use e.g. openssl-nss or openssl nss)" >&2
      exit 1
    fi
    if ! _valid_wrapper "$a" || ! _valid_wrapper "$b"; then
      echo "Unknown wrapper in: $1" >&2
      exit 1
    fi
    run_combo "$a" "$b"
    exit $?
  fi

  # Comma-separated srv-cli list
  if [[ "$*" == *','* ]]; then
    local rest chunk
    rest="$*"
    while [[ -n "$rest" ]]; do
      if [[ "$rest" == *','* ]]; then
        chunk="${rest%%,*}"
        rest="${rest#*,}"
      else
        chunk="$rest"
        rest=""
      fi
      run_matrix_segment "$chunk"
    done
    _matrix_summary && exit 0 || exit 1
  fi

  echo "Usage: $0 [docker] [--all] | <server> <client> | <server>-<client> | srv-cli,srv-cli,..." >&2
  exit 1
}

cmd_ci() {
  cmd_protoc
  cmd_certs
  cmd_capability
  cmd_local
  cmd_docker_matrix
}

main() {
  if [[ $# -eq 0 ]]; then
    cmd_docker_matrix
    return
  fi
  case "$1" in
    help | -h | --help)
      usage
      exit 0
      ;;
    local)
      shift
      cmd_local "$@"
      ;;
    certs)
      shift
      cmd_certs "$@"
      ;;
    protoc)
      shift
      cmd_protoc "$@"
      ;;
    ci)
      shift
      cmd_ci "$@"
      ;;
    capability-test)
      shift
      cmd_capability "$@"
      ;;
    docker | combos)
      shift
      cmd_docker_matrix "$@"
      ;;
    *)
      cmd_docker_matrix "$@"
      ;;
  esac
}

main "$@"

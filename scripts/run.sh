#!/bin/bash
# Entry point: Docker matrix (default), CI-like pipeline, capability self-check.
# Matrix args (same with or without leading "docker"): no args = all 9 combos;
# openssl nss | openssl-nss | nss-nss,gnutls-openssl (comma-separated srv-cli).
# Hidden commands (CI / tooling): protoc, certs, docker.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

MATRIX="deploy/matrix.yaml"
# INTEROP_GNUTLS_NSS_PAIR must match GNUTLS_NSS_PAIR_ENV in src/wrappers/matrix_env.py

# Matches driver.py: INTEROP_VERBOSE truthy => show docker compose build output.
interop_is_verbose() {
  case "$(printf '%s' "${INTEROP_VERBOSE:-}" | tr '[:upper:]' '[:lower:]')" in
    1 | true | yes) return 0 ;;
    *) return 1 ;;
  esac
}

usage() {
  cat <<'EOF'
./scripts/run.sh [arguments]

  (no arguments)   All 9 Docker matrix combinations
  <srv> <cli>      One combination (e.g. openssl nss)
  <srv>-<cli>      Same (e.g. openssl-nss)
  srv-cli,...      Several combinations, comma-separated

  capability-test  Driver capability filter self-check
  ci               Full pipeline (protoc, certs, tests, docker matrix)
  -v / --verbose   Detailed driver log + docker build output (or INTEROP_VERBOSE=1); default: quiet + ✓/✗ per scenario
  help             This text
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
  local build_flags=()
  if ! interop_is_verbose; then
    build_flags=(-q)
  fi
  local rc=1
  # Do not merge stderr into stdout: driver uses stderr for quiet-mode spinner (needs isatty).
  if docker compose -p "$project" -f "$MATRIX" build "${build_flags[@]}" \
    && docker compose -p "$project" -f "$MATRIX" run --rm driver; then
    rc=0
  fi
  if [[ "$rc" -eq 0 ]]; then
    PASSED+=("$name")
    docker compose -p "$project" -f "$MATRIX" down --remove-orphans 2>/dev/null || true
    return 0
  fi
  FAILED+=("$name")
  docker compose -p "$project" -f "$MATRIX" down --remove-orphans 2>/dev/null || true
  return 1
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
  while [[ "${1:-}" == "-v" || "${1:-}" == "--verbose" ]]; do
    export INTEROP_VERBOSE=1
    shift
  done
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

  echo "Usage: $0 <server> <client> | <server>-<client> | srv-cli,srv-cli,... (no arguments = all combinations)" >&2
  exit 1
}

cmd_ci() {
  while [[ "${1:-}" == "-v" || "${1:-}" == "--verbose" ]]; do
    export INTEROP_VERBOSE=1
    shift
  done
  cmd_protoc
  cmd_certs
  cmd_capability
  cmd_docker_matrix
}

main() {
  while [[ "${1:-}" == "-v" || "${1:-}" == "--verbose" ]]; do
    export INTEROP_VERBOSE=1
    shift
  done
  if [[ $# -eq 0 ]]; then
    cmd_docker_matrix
    return
  fi
  case "$1" in
    help | -h | --help)
      usage
      exit 0
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

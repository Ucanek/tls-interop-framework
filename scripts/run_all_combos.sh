#!/bin/bash
# Run server×client Docker combos via one parameterized compose (deploy/combos/matrix.yaml).
#
#   ./scripts/run_all_combos.sh                    # 9 combos (CI default; gnutls×nss sets INTEROP_GNUTLS_NSS_PAIR)
#   ./scripts/run_all_combos.sh --all              # same as default (kept for compatibility)
#   ./scripts/run_all_combos.sh openssl nss
#   ./scripts/run_all_combos.sh gnutls-gnutls

set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MATRIX="deploy/combos/matrix.yaml"
# INTEROP_GNUTLS_NSS_PAIR must match GNUTLS_NSS_PAIR_ENV in src/wrappers/matrix_env.py

FAILED=()
PASSED=()

# Exports SERVER_WRAPPER, CLIENT_WRAPPER, and matrix workaround flags for compose interpolation.
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
  # Clear same-project leftovers (e.g. deps still running after a previous `compose run`).
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

if [[ -n "${1:-}" ]]; then
  if [[ "$1" == "--all" ]]; then
    shift
    RUN_ALL=1
  elif [[ "$1" == -* ]]; then
    echo "Unknown option: $1" >&2
    exit 1
  else
    if [[ -n "${2:-}" ]]; then
      run_combo "$1" "$2"
      exit $?
    fi
    if [[ "$1" != *-* ]]; then
      echo "Usage: $0 [--all] | <server> <client> | <server>-<client>" >&2
      exit 1
    fi
    IFS='-' read -r a b c <<<"$1"
    if [[ -n "$c" || -z "${b:-}" ]]; then
      echo "Unknown combo name: $1 (use e.g. openssl-nss or openssl nss)" >&2
      exit 1
    fi
    run_combo "$a" "$b"
    exit $?
  fi
fi

PAIRS=(
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

# --all is a no-op (all pairs always run); kept so old CI/scripts do not break.
[[ "${RUN_ALL:-}" == 1 ]] || true

for pair in "${PAIRS[@]}"; do
  set -- $pair
  run_combo "$1" "$2" || true
done

echo ""
echo "========== Summary =========="
echo "Passed: ${#PASSED[@]} (${PASSED[*]:-none})"
echo "Failed: ${#FAILED[@]} (${FAILED[*]:-none})"
[[ ${#FAILED[@]} -eq 0 ]] && exit 0 || exit 1

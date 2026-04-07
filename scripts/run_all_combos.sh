#!/bin/bash
# Run server×client Docker combos via one parameterized compose (deploy/combos/matrix.yaml).
#
#   ./scripts/run_all_combos.sh                    # 8 combos (CI default; skips gnutls×nss)
#   ./scripts/run_all_combos.sh --all              # all 9 including gnutls×nss (may fail)
#   ./scripts/run_all_combos.sh openssl nss
#   ./scripts/run_all_combos.sh gnutls-gnutls

set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MATRIX="deploy/combos/matrix.yaml"
FAILED=()
PASSED=()
SKIPPED=()

run_combo() {
  local srv="$1" cli="$2"
  local name="${srv}×${cli}"
  local project="interop-${srv}-${cli}"
  echo ""
  echo "========== $name =========="
  export SERVER_WRAPPER="$srv" CLIENT_WRAPPER="$cli"
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

# CI / default: skip gnutls-nss (NSS tstclnt ↔ gnutls-serv handshake: illegal_parameter)
PAIRS=(
  "openssl openssl"
  "openssl gnutls"
  "openssl nss"
  "gnutls openssl"
  "gnutls gnutls"
  "nss openssl"
  "nss gnutls"
  "nss nss"
)

if [[ "${RUN_ALL:-}" == 1 ]]; then
  PAIRS+=("gnutls nss")
else
  SKIPPED+=("gnutls×nss")
fi

for pair in "${PAIRS[@]}"; do
  set -- $pair
  run_combo "$1" "$2" || true
done

echo ""
echo "========== Summary =========="
echo "Passed: ${#PASSED[@]} (${PASSED[*]:-none})"
echo "Failed: ${#FAILED[@]} (${FAILED[*]:-none})"
if [[ ${#SKIPPED[@]} -gt 0 ]]; then
  echo "Skipped (known limitation): ${SKIPPED[*]} — see docs/KNOWN_LIMITATIONS.md"
fi
[[ ${#FAILED[@]} -eq 0 ]] && exit 0 || exit 1

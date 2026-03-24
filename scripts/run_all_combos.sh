#!/bin/bash
# Run server×client Docker combos (each combo = own compose in deploy/combos/).
#
#   ./scripts/run_all_combos.sh              # 8 combos (CI default; skips gnutls×nss)
#   ./scripts/run_all_combos.sh --all      # all 9 including gnutls×nss (may fail)
#   ./scripts/run_all_combos.sh openssl nss
#   ./scripts/run_all_combos.sh gnutls-gnutls

set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMBOS_DIR="deploy/combos"
FAILED=()
PASSED=()
SKIPPED=()

run_combo() {
  local file="$1"
  local name
  name=$(basename "$file" .yaml | tr '-' '×')
  echo ""
  echo "========== $name =========="
  if docker compose -f "$file" run --rm --build driver 2>&1; then
    PASSED+=("$name")
    return 0
  else
    FAILED+=("$name")
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
      FILE="$COMBOS_DIR/$1-$2.yaml"
    else
      FILE="$COMBOS_DIR/$1.yaml"
    fi
    if [[ ! -f "$FILE" ]]; then
      echo "Compose file not found: $FILE" >&2
      echo "Usage: $0 [--all] | [server client] | [combo-name]" >&2
      exit 1
    fi
    EXIT=0
    run_combo "$FILE" || EXIT=$?
    docker compose -f "$FILE" down --remove-orphans 2>/dev/null || true
    exit "$EXIT"
  fi
fi

# CI / default: skip gnutls-nss (NSS tstclnt ↔ gnutls-serv handshake: illegal_parameter)
COMBOS=(
  "$COMBOS_DIR/openssl-openssl.yaml"
  "$COMBOS_DIR/openssl-gnutls.yaml"
  "$COMBOS_DIR/openssl-nss.yaml"
  "$COMBOS_DIR/gnutls-openssl.yaml"
  "$COMBOS_DIR/gnutls-gnutls.yaml"
  "$COMBOS_DIR/nss-openssl.yaml"
  "$COMBOS_DIR/nss-gnutls.yaml"
  "$COMBOS_DIR/nss-nss.yaml"
)

if [[ "${RUN_ALL:-}" == 1 ]]; then
  COMBOS+=("$COMBOS_DIR/gnutls-nss.yaml")
else
  SKIPPED+=("gnutls×nss")
fi

for f in "${COMBOS[@]}"; do
  run_combo "$f" || true
  docker compose -f "$f" down --remove-orphans --quiet 2>/dev/null || true
done

echo ""
echo "========== Summary =========="
echo "Passed: ${#PASSED[@]} (${PASSED[*]:-none})"
echo "Failed: ${#FAILED[@]} (${FAILED[*]:-none})"
if [[ ${#SKIPPED[@]} -gt 0 ]]; then
  echo "Skipped (known limitation): ${SKIPPED[*]} — see docs/KNOWN_LIMITATIONS.md"
fi
[[ ${#FAILED[@]} -eq 0 ]] && exit 0 || exit 1

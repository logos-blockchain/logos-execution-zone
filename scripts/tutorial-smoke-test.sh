#!/usr/bin/env bash
# Tutorial smoke test: verifies the README wallet quickstart flow works.
# Run from the repo root after building the sequencer and wallet.
#
# Usage:
#   RISC0_DEV_MODE=1 bash scripts/tutorial-smoke-test.sh
#
# Requirements:
#   - wallet binary on PATH
#   - sequencer running on localhost:3040

set -euo pipefail

WALLET_HOME=$(mktemp -d)
export NSSA_WALLET_HOME_DIR="$WALLET_HOME"
WALLET_PASSWORD="smoketest-password-123"

cleanup() { rm -rf "$WALLET_HOME"; }
trap cleanup EXIT

log()  { echo "[smoke] $*"; }
fail() { echo "[FAIL]  $*" >&2; exit 1; }

wallet_cmd() {
    echo "$WALLET_PASSWORD" | wallet "$@"
}

log "=== LEZ Tutorial Smoke Test ==="
log "Wallet home: $WALLET_HOME"

# Step 1: health check
log "Step 1: wallet check-health"
wallet_cmd check-health | grep -q "All looks good" \
    || fail "check-health failed"
log "  OK"

# Step 2: create sender account
log "Step 2: wallet account new public"
ACCOUNT_OUT=$(wallet_cmd account new public 2>&1)
SENDER_ID=$(echo "$ACCOUNT_OUT" | grep -oP 'Public/\S+' | head -1)
[ -n "$SENDER_ID" ] || fail "could not parse account_id from output"
log "  Created: $SENDER_ID"

# Step 3: verify uninitialized
log "Step 3: account get (expect: Uninitialized)"
wallet_cmd account get --account-id "$SENDER_ID" 2>&1 \
    | grep -qi "uninitialized" \
    || fail "expected account to be uninitialized"
log "  OK"

# Step 4: init account
log "Step 4: auth-transfer init"
wallet_cmd auth-transfer init --account-id "$SENDER_ID" 2>&1 \
    | grep -qi "submitted" \
    || fail "auth-transfer init did not submit"
log "  OK"

# Step 5: faucet claim
log "Step 5: pinata claim"
wallet_cmd pinata claim --to "$SENDER_ID" 2>&1 \
    | grep -qi "submitted" \
    || fail "pinata claim failed"
log "  OK"

# Step 6: verify balance > 0
log "Step 6: account get (expect: balance > 0)"
BAL_OUT=$(wallet_cmd account get --account-id "$SENDER_ID" 2>&1)
echo "$BAL_OUT" | grep -qE '"balance":[1-9]' \
    || fail "expected balance > 0, got: $BAL_OUT"
log "  OK"

# Step 7: create recipient and send transfer
log "Step 7: transfer to new account"
RECIP_OUT=$(wallet_cmd account new public 2>&1)
RECIPIENT_ID=$(echo "$RECIP_OUT" | grep -oP 'Public/\S+' | head -1)
[ -n "$RECIPIENT_ID" ] || fail "could not parse recipient account_id"
log "  Recipient: $RECIPIENT_ID"

wallet_cmd auth-transfer send \
    --from "$SENDER_ID" \
    --to   "$RECIPIENT_ID" \
    --amount 10 2>&1 \
    | grep -qi "submitted" \
    || fail "auth-transfer send failed"
log "  OK"

log ""
log "=== ALL STEPS PASSED ==="

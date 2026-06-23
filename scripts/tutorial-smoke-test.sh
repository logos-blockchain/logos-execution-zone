#!/usr/bin/env bash
# Tutorial smoke test: verifies the README wallet quickstart flow works.
# Run from the repo root after building the sequencer and wallet.
#
# Usage:
#   RISC0_DEV_MODE=1 bash scripts/tutorial-smoke-test.sh
#   WALLET_BIN=./target/release/wallet RISC0_DEV_MODE=1 bash scripts/tutorial-smoke-test.sh
#
# Requirements:
#   - wallet binary built (cargo build --release -p wallet), or set WALLET_BIN
#     to its path explicitly. Falls back to `cargo run -p wallet --` if unset.
#   - sequencer running on localhost:3040

set -euo pipefail

WALLET_HOME=$(mktemp -d)
export LEE_WALLET_HOME_DIR="$WALLET_HOME"
WALLET_PASSWORD="smoketest-password-123"
WALLET_BIN="${WALLET_BIN:-}"

cleanup() { rm -rf "$WALLET_HOME"; }
trap cleanup EXIT

log()  { echo "[smoke] $*"; }
fail() { echo "[FAIL]  $*" >&2; exit 1; }

# Runs a wallet subcommand and captures combined stdout+stderr into a
# variable instead of piping directly into grep. Piping wallet_cmd's
# internal `echo password | wallet ...` pipeline straight into an
# outer `grep -q` interacts badly with `set -o pipefail`: SIGPIPE from
# grep's early exit propagates back through the inner pipe and the
# outer command can report failure even though wallet succeeded and
# produced the expected output. Capturing first avoids the nested-pipe
# + pipefail interaction entirely.
wallet_cmd() {
    if [ -n "$WALLET_BIN" ]; then
        echo "$WALLET_PASSWORD" | "$WALLET_BIN" "$@"
    else
        echo "$WALLET_PASSWORD" | cargo run --quiet -p wallet -- "$@"
    fi
}

log "=== LEZ Tutorial Smoke Test ==="
log "Wallet home: $WALLET_HOME"

# Step 1: health check
log "Step 1: wallet check-health"
HEALTH_OUT=$(wallet_cmd check-health 2>&1)
echo "$HEALTH_OUT" | grep -q "All looks good" \
    || fail "check-health failed: $HEALTH_OUT"
log "  OK"

# Step 2: create sender account
log "Step 2: wallet account new public"
ACCOUNT_OUT=$(wallet_cmd account new public 2>&1)
SENDER_ID=$(echo "$ACCOUNT_OUT" | grep -oP 'Public/\S+' | head -1)
[ -n "$SENDER_ID" ] || fail "could not parse account_id from output: $ACCOUNT_OUT"
log "  Created: $SENDER_ID"

# Step 3: verify uninitialized
log "Step 3: account get (expect: Uninitialized)"
GET_OUT=$(wallet_cmd account get --account-id "$SENDER_ID" 2>&1)
echo "$GET_OUT" | grep -qi "uninitialized" \
    || fail "expected account to be uninitialized, got: $GET_OUT"
log "  OK"

# Step 4: init account
log "Step 4: auth-transfer init"
INIT_OUT=$(wallet_cmd auth-transfer init --account-id "$SENDER_ID" 2>&1)
echo "$INIT_OUT" | grep -qi "Transaction hash" \
    || fail "auth-transfer init did not submit: $INIT_OUT"
log "  OK"

# Step 5: faucet claim
log "Step 5: pinata claim"
CLAIM_OUT=$(wallet_cmd pinata claim --to "$SENDER_ID" 2>&1)
echo "$CLAIM_OUT" | grep -qi "Transaction hash" \
    || fail "pinata claim failed: $CLAIM_OUT"
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
[ -n "$RECIPIENT_ID" ] || fail "could not parse recipient account_id: $RECIP_OUT"
log "  Recipient: $RECIPIENT_ID"

SEND_OUT=$(wallet_cmd auth-transfer send \
    --from "$SENDER_ID" \
    --to   "$RECIPIENT_ID" \
    --amount 10 2>&1)
echo "$SEND_OUT" | grep -qi "Transaction hash" \
    || fail "auth-transfer send failed: $SEND_OUT"
log "  OK"

log ""
log "=== ALL STEPS PASSED ==="

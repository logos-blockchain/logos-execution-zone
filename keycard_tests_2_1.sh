#!/usr/bin/env bash
# keycard_tests_2.sh — comprehensive token + AMM keycard integration tests.
#
# Prerequisites:
#   1. Run wallet_with_keycard.sh once to install dependencies.
#   2. Reset the local chain so all accounts are uninitialized.
#   3. Keycard reader inserted with card loaded.
#
# Keycard path layout:
#   path 2  → LEZ token definition  (keycard)
#   path 3  → LEZ token supply      (keycard)
#   path 4  → LEE token definition  (keycard)
#   path 5  → LEE token supply      (keycard)
#   path 6  → LEZ holding           (keycard — transfers, mint, burn, swap, liquidity)
#   path 7  → LEE holding           (keycard — swap, add/remove liquidity)
#   path 8  → LP  holding           (keycard — add/remove liquidity)
#   path 9  → ATA owner             (keycard — ATA create, send, burn)
#
# Non-keycard accounts:
#   pub-receiver   → public  account (target for keycard → public  token transfer)
#   priv-receiver  → private account (target for keycard → private token transfer)
#   amm-lez-fund   → public LEZ holding used to seed the AMM pool
#   amm-lee-fund   → public LEE holding used to seed the AMM pool
#   (LP holding for amm new is created fresh each run — no persistent label)

source venv/bin/activate
export KEYCARD_PIN=111111

# =============================================================================
# Create non-keycard wallet accounts
# =============================================================================
echo ""
echo "=== Create non-keycard accounts ==="
wallet account new public  --label pub-receiver  2>/dev/null || true

wallet account new public  --label amm-lez-fund  2>/dev/null || true
wallet account new public  --label amm-lee-fund  2>/dev/null || true
wallet account new public  --label amm-lp-fund   2>/dev/null || true

# =============================================================================
# (1) Create LEZ token — definition AND supply via keycard paths
# =============================================================================
echo ""
echo "=== (1) Create LEZ token (keycard def=path2, supply=path1) ==="
wallet token new \
  --definition-key-path "m/44'/60'/0'/0/2" \
  --supply-key-path     "m/44'/60'/0'/0/3" \
  --name LEZ \
  --total-supply 100000
echo "LEZ token created"

# =============================================================================
# (2) Create LEE token — definition AND supply via keycard paths
# =============================================================================
echo ""
echo "=== (2) Create LEE token (keycard def=path4, supply=path3) ==="
wallet token new \
  --definition-key-path "m/44'/60'/0'/0/4" \
  --supply-key-path     "m/44'/60'/0'/0/5" \
  --name LEE \
  --total-supply 100000
echo "LEE token created"

sleep 15

LEZ_DEF_ID=$(wallet account id --key-path "m/44'/60'/0'/0/2")
LEE_DEF_ID=$(wallet account id --key-path "m/44'/60'/0'/0/4")
echo "LEZ definition ID: $LEZ_DEF_ID"
echo "LEE definition ID: $LEE_DEF_ID"

echo "Keycard path 2 (LEZ definition) state:"
wallet account get --key-path "m/44'/60'/0'/0/2"
echo "Keycard path 3 (LEZ supply) state:"
wallet account get --key-path "m/44'/60'/0'/0/3"
echo "Keycard path 4 (LEE definition) state:"
wallet account get --key-path "m/44'/60'/0'/0/4"
echo "Keycard path 5 (LEE supply) state:"
wallet account get --key-path "m/44'/60'/0'/0/5"

# =============================================================================
# Initialize token holding accounts
# =============================================================================
echo ""
echo "=== Initialize token holding accounts ==="

# Keycard path 6: LEZ holding
wallet token init \
  --definition-account-id "Public/$LEZ_DEF_ID" \
  --holder-key-path "m/44'/60'/0'/0/6"
echo "LEZ holding initialized for keycard path 4"

# Keycard path 7: LEE holding
wallet token init \
  --definition-account-id "Public/$LEE_DEF_ID" \
  --holder-key-path "m/44'/60'/0'/0/7"
echo "LEE holding initialized for keycard path 5"

# pub-receiver: public LEZ holding (for token transfer test)
wallet token init \
  --definition-account-id "Public/$LEZ_DEF_ID" \
  --holder-account-label  pub-receiver
echo "LEZ holding initialized for pub-receiver"

# AMM seed accounts
wallet token init \
  --definition-account-id "Public/$LEZ_DEF_ID" \
  --holder-account-label  amm-lez-fund
wallet token init \
  --definition-account-id "Public/$LEE_DEF_ID" \
  --holder-account-label  amm-lee-fund
echo "AMM seed holdings initialized"

# =============================================================================
# Fund keycard holdings and AMM seed accounts from supply
# =============================================================================
echo ""
echo "=== Fund keycard holdings and AMM seed accounts ==="

wallet token send \
  --from-key-path "m/44'/60'/0'/0/3" \
  --to-key-path   "m/44'/60'/0'/0/6" \
  --amount 20000
echo "Transferred 20000 LEZ → keycard path 4"

wallet token send \
  --from-key-path "m/44'/60'/0'/0/5" \
  --to-key-path   "m/44'/60'/0'/0/7" \
  --amount 20000
echo "Transferred 20000 LEE → keycard path 5"

wallet token send \
  --from-key-path "m/44'/60'/0'/0/3" \
  --to-label      amm-lez-fund \
  --amount 10000
echo "Transferred 10000 LEZ → amm-lez-fund"

wallet token send \
  --from-key-path "m/44'/60'/0'/0/5" \
  --to-label      amm-lee-fund \
  --amount 10000
echo "Transferred 10000 LEE → amm-lee-fund"

sleep 15

echo "Keycard path 6 (LEZ holding) state (balance should be 20000):"
wallet account get --key-path "m/44'/60'/0'/0/6"
echo "Keycard path 7 (LEE holding) state (balance should be 20000):"
wallet account get --key-path "m/44'/60'/0'/0/7"
echo "amm-lez-fund state (balance should be 10000):"
wallet account get --account-label amm-lez-fund
echo "amm-lee-fund state (balance should be 10000):"
wallet account get --account-label amm-lee-fund

# =============================================================================
# (3) Token transfer: keycard path 6 (LEZ) → public account
# =============================================================================
echo ""
echo "=== (3) Token transfer: keycard path 6 → pub-receiver (public) ==="
wallet token send \
  --from-key-path "m/44'/60'/0'/0/6" \
  --to-label      pub-receiver \
  --amount 1000
echo "Transferred 1000 LEZ: keycard path 6 → pub-receiver"

sleep 15

echo "Keycard path 6 (LEZ) state (balance should be 19000):"
wallet account get --key-path "m/44'/60'/0'/0/6"
echo "pub-receiver state (balance should be 1000):"
wallet account get --account-label pub-receiver

# =============================================================================
# (4) Token transfer: keycard path 6 (LEZ) → private account (shielded)
# =============================================================================
echo ""
echo "=== (4) Token transfer: keycard path 6 → priv-receiver (private, shielded) ==="
PRIV_RECEIVER=$(wallet account new private | grep -o 'Private/[^[:space:]]*' | head -1)
echo "Fresh private receiver account: $PRIV_RECEIVER"

wallet token send \
  --from-key-path "m/44'/60'/0'/0/6" \
  --to            "$PRIV_RECEIVER" \
  --amount 500
echo "Shielded transfer of 500 LEZ: keycard path 6 → $PRIV_RECEIVER"

wallet account sync-private

sleep 15

echo "Keycard path 6 (LEZ) state (balance should be 18500):"
wallet account get --key-path "m/44'/60'/0'/0/6"
echo "priv-receiver state (balance should be 500):"
wallet account get --account-id "$PRIV_RECEIVER"

# =============================================================================
# (5) Token mint with keycard — definition signed by keycard path 2
# =============================================================================
echo ""
echo "=== (5) Token mint: keycard def path 2 mints 2000 LEZ to keycard path 6 ==="
wallet token mint \
  --definition-key-path "m/44'/60'/0'/0/2" \
  --holder-key-path     "m/44'/60'/0'/0/6" \
  --amount 2000
echo "Minted 2000 LEZ to keycard path 4"

sleep 15

echo "Keycard path 2 (LEZ definition) state (total supply should have increased):"
wallet account get --key-path "m/44'/60'/0'/0/2"
echo "Keycard path 6 (LEZ holding) state (balance should be 20500):"
wallet account get --key-path "m/44'/60'/0'/0/6"

# =============================================================================
# (6) Token burn with keycard — holder is keycard path 6
# =============================================================================
echo ""
echo "=== (6) Token burn: keycard path 6 burns 500 LEZ ==="
wallet token burn \
  --definition      "Public/$LEZ_DEF_ID" \
  --holder-key-path "m/44'/60'/0'/0/6" \
  --amount 500
echo "Burned 500 LEZ from keycard path 4"

sleep 15

echo "Keycard path 2 (LEZ definition) state (total supply should reflect burn):"
wallet account get --key-path "m/44'/60'/0'/0/2"
echo "Keycard path 6 (LEZ holding) state (balance should be 20000):"
wallet account get --key-path "m/44'/60'/0'/0/6"
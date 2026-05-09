#!/usr/bin/env bash
# keycard_tests_2.sh — comprehensive token + AMM keycard integration tests.
#
# Prerequisites:
#   1. Run wallet_with_keycard.sh once to install dependencies.
#   2. Reset the local chain so all accounts are uninitialized.
#   3. Keycard reader inserted with card loaded.
#
# Keycard path layout:
#   path 0  → LEZ token definition  (keycard)
#   path 1  → LEZ token supply      (keycard)
#   path 2  → LEE token definition  (keycard)
#   path 3  → LEE token supply      (keycard)
#   path 4  → LEZ holding           (keycard — transfers, mint, burn, swap, liquidity)
#   path 5  → LEE holding           (keycard — swap, add/remove liquidity)
#   path 6  → LP  holding           (keycard — add/remove liquidity)
#   path 7  → ATA owner             (keycard — ATA create, send, burn)
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
# Keycard setup
# =============================================================================
echo ""
echo "=== Keycard setup ==="
wallet keycard available
wallet keycard load --mnemonic "fashion degree mountain wool question damp current pond grow dolphin chronic then"

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
echo "=== (1) Create LEZ token (keycard def=path0, supply=path1) ==="
wallet token new \
  --definition-key-path "m/44'/60'/0'/0/0" \
  --supply-key-path     "m/44'/60'/0'/0/1" \
  --name LEZ \
  --total-supply 100000
echo "LEZ token created"

# =============================================================================
# (2) Create LEE token — definition AND supply via keycard paths
# =============================================================================
echo ""
echo "=== (2) Create LEE token (keycard def=path2, supply=path3) ==="
wallet token new \
  --definition-key-path "m/44'/60'/0'/0/2" \
  --supply-key-path     "m/44'/60'/0'/0/3" \
  --name LEE \
  --total-supply 100000
echo "LEE token created"

sleep 15

LEZ_DEF_ID=$(wallet account id --key-path "m/44'/60'/0'/0/0")
LEE_DEF_ID=$(wallet account id --key-path "m/44'/60'/0'/0/2")
echo "LEZ definition ID: $LEZ_DEF_ID"
echo "LEE definition ID: $LEE_DEF_ID"

echo "Keycard path 0 (LEZ definition) state:"
wallet account get --key-path "m/44'/60'/0'/0/0"
echo "Keycard path 1 (LEZ supply) state:"
wallet account get --key-path "m/44'/60'/0'/0/1"
echo "Keycard path 2 (LEE definition) state:"
wallet account get --key-path "m/44'/60'/0'/0/2"
echo "Keycard path 3 (LEE supply) state:"
wallet account get --key-path "m/44'/60'/0'/0/3"

# =============================================================================
# Initialize token holding accounts
# =============================================================================
echo ""
echo "=== Initialize token holding accounts ==="

# Keycard path 4: LEZ holding
wallet token init \
  --definition-account-id "Public/$LEZ_DEF_ID" \
  --holder-key-path "m/44'/60'/0'/0/4"
echo "LEZ holding initialized for keycard path 4"

# Keycard path 5: LEE holding
wallet token init \
  --definition-account-id "Public/$LEE_DEF_ID" \
  --holder-key-path "m/44'/60'/0'/0/5"
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
  --from-key-path "m/44'/60'/0'/0/1" \
  --to-key-path   "m/44'/60'/0'/0/4" \
  --amount 20000
echo "Transferred 20000 LEZ → keycard path 4"

wallet token send \
  --from-key-path "m/44'/60'/0'/0/3" \
  --to-key-path   "m/44'/60'/0'/0/5" \
  --amount 20000
echo "Transferred 20000 LEE → keycard path 5"

wallet token send \
  --from-key-path "m/44'/60'/0'/0/1" \
  --to-label      amm-lez-fund \
  --amount 10000
echo "Transferred 10000 LEZ → amm-lez-fund"

wallet token send \
  --from-key-path "m/44'/60'/0'/0/3" \
  --to-label      amm-lee-fund \
  --amount 10000
echo "Transferred 10000 LEE → amm-lee-fund"

sleep 15

echo "Keycard path 4 (LEZ holding) state (balance should be 20000):"
wallet account get --key-path "m/44'/60'/0'/0/4"
echo "Keycard path 5 (LEE holding) state (balance should be 20000):"
wallet account get --key-path "m/44'/60'/0'/0/5"
echo "amm-lez-fund state (balance should be 10000):"
wallet account get --account-label amm-lez-fund
echo "amm-lee-fund state (balance should be 10000):"
wallet account get --account-label amm-lee-fund

# =============================================================================
# (3) Token transfer: keycard path 4 (LEZ) → public account
# =============================================================================
echo ""
echo "=== (3) Token transfer: keycard path 4 → pub-receiver (public) ==="
wallet token send \
  --from-key-path "m/44'/60'/0'/0/4" \
  --to-label      pub-receiver \
  --amount 1000
echo "Transferred 1000 LEZ: keycard path 4 → pub-receiver"

sleep 15

echo "Keycard path 4 (LEZ) state (balance should be 19000):"
wallet account get --key-path "m/44'/60'/0'/0/4"
echo "pub-receiver state (balance should be 1000):"
wallet account get --account-label pub-receiver

# =============================================================================
# (4) Token transfer: keycard path 4 (LEZ) → private account (shielded)
# =============================================================================
echo ""
echo "=== (4) Token transfer: keycard path 4 → priv-receiver (private, shielded) ==="
PRIV_RECEIVER=$(wallet account new private | grep -o 'Private/[^[:space:]]*' | head -1)
echo "Fresh private receiver account: $PRIV_RECEIVER"

wallet token send \
  --from-key-path "m/44'/60'/0'/0/4" \
  --to            "$PRIV_RECEIVER" \
  --amount 500
echo "Shielded transfer of 500 LEZ: keycard path 4 → $PRIV_RECEIVER"

wallet account sync-private

sleep 15

echo "Keycard path 4 (LEZ) state (balance should be 18500):"
wallet account get --key-path "m/44'/60'/0'/0/4"
echo "priv-receiver state (balance should be 500):"
wallet account get --account-id "$PRIV_RECEIVER"

# =============================================================================
# (5) Token mint with keycard — definition signed by keycard path 0
# =============================================================================
echo ""
echo "=== (5) Token mint: keycard def path 0 mints 2000 LEZ to keycard path 4 ==="
wallet token mint \
  --definition-key-path "m/44'/60'/0'/0/0" \
  --holder-key-path     "m/44'/60'/0'/0/4" \
  --amount 2000
echo "Minted 2000 LEZ to keycard path 4"

sleep 15

echo "Keycard path 0 (LEZ definition) state (total supply should have increased):"
wallet account get --key-path "m/44'/60'/0'/0/0"
echo "Keycard path 4 (LEZ holding) state (balance should be 20500):"
wallet account get --key-path "m/44'/60'/0'/0/4"

# =============================================================================
# (6) Token burn with keycard — holder is keycard path 4
# =============================================================================
echo ""
echo "=== (6) Token burn: keycard path 4 burns 500 LEZ ==="
wallet token burn \
  --definition      "Public/$LEZ_DEF_ID" \
  --holder-key-path "m/44'/60'/0'/0/4" \
  --amount 500
echo "Burned 500 LEZ from keycard path 4"

sleep 15

echo "Keycard path 0 (LEZ definition) state (total supply should reflect burn):"
wallet account get --key-path "m/44'/60'/0'/0/0"
echo "Keycard path 4 (LEZ holding) state (balance should be 20000):"
wallet account get --key-path "m/44'/60'/0'/0/4"

# =============================================================================
# (7) Create AMM pool for LEZ/LEE — without keycard
# =============================================================================
echo ""
echo "=== (7) Create AMM pool for LEZ/LEE (without keycard) ==="

wallet amm new \
  --user-holding-a-label amm-lez-fund \
  --user-holding-b-label amm-lee-fund \
  --user-holding-lp-label amm-lp-fund \
  --balance-a 10000 \
  --balance-b 10000
echo "AMM pool created for LEZ/LEE"

sleep 15

echo "amm-lez-fund state (balance should be 0 — contributed to pool):"
wallet account get --account-label amm-lez-fund
echo "amm-lee-fund state (balance should be 0 — contributed to pool):"
wallet account get --account-label amm-lee-fund
echo "Initial LP holding state (should hold initial LP tokens):"
wallet account get --account-label amm-lp-fund
LP_DEF_ID=$(wallet account get --account-label amm-lp-fund | grep -o '"definition_id":"[^"]*"' | awk -F'"' '{print $4}')
echo "LP token definition ID: $LP_DEF_ID"

# =============================================================================
# (8) Swap tokens owned by keycard accounts
#     keycard path 5 (LEE) sells 500 LEE; keycard path 4 (LEZ) receives LEZ
# =============================================================================
echo ""
echo "=== (8) Swap: keycard path 5 sells 500 LEE, keycard path 4 receives LEZ ==="
wallet amm swap-exact-input \
  --user-holding-a-key-path "m/44'/60'/0'/0/4" \
  --user-holding-b-key-path "m/44'/60'/0'/0/5" \
  --amount-in      500 \
  --min-amount-out 1 \
  --token-definition "$LEE_DEF_ID"
echo "Swap LEE → LEZ complete via keycard"

sleep 15

echo "Keycard path 4 (LEZ holding) state (balance should have increased):"
wallet account get --key-path "m/44'/60'/0'/0/4"
echo "Keycard path 5 (LEE holding) state (balance should have decreased by 500):"
wallet account get --key-path "m/44'/60'/0'/0/5"

# =============================================================================
# (9) Add liquidity — keycard accounts for holding A (path 4), B (path 5), LP (path 6)
# =============================================================================
echo ""
echo "=== (9) Initialize LP holding (keycard path 6) before add-liquidity ==="
wallet token init \
  --definition-account-id "Public/$LP_DEF_ID" \
  --holder-key-path "m/44'/60'/0'/0/6"
echo "Keycard path 6 (LP holding) initialized"

sleep 15

echo "Keycard path 6 (LP holding) state (after init):"
wallet account get --key-path "m/44'/60'/0'/0/6"

echo ""
echo "=== (9) Add liquidity (keycard path 4=LEZ, path 5=LEE, path 6=LP) ==="
wallet amm add-liquidity \
  --user-holding-a-key-path  "m/44'/60'/0'/0/4" \
  --user-holding-b-key-path  "m/44'/60'/0'/0/5" \
  --user-holding-lp-key-path "m/44'/60'/0'/0/6" \
  --max-amount-a  1000 \
  --max-amount-b  1000 \
  --min-amount-lp 1
echo "Add liquidity complete via keycard"

sleep 15

echo "Keycard path 4 (LEZ holding) state (balance should have decreased):"
wallet account get --key-path "m/44'/60'/0'/0/4"
echo "Keycard path 5 (LEE holding) state (balance should have decreased):"
wallet account get --key-path "m/44'/60'/0'/0/5"
echo "Keycard path 6 (LP holding) state (should have received LP tokens):"
wallet account get --key-path "m/44'/60'/0'/0/6"

# =============================================================================
# (10) Remove liquidity — keycard accounts for holding A (path 4), B (path 5), LP (path 6)
# =============================================================================
echo ""
echo "=== (10) Remove liquidity (keycard path 4=LEZ, path 5=LEE, path 6=LP) ==="
wallet amm remove-liquidity \
  --user-holding-a-key-path  "m/44'/60'/0'/0/4" \
  --user-holding-b-key-path  "m/44'/60'/0'/0/5" \
  --user-holding-lp-key-path "m/44'/60'/0'/0/6" \
  --balance-lp   500 \
  --min-amount-a 1 \
  --min-amount-b 1
echo "Remove liquidity complete via keycard"

sleep 15

echo "Keycard path 4 (LEZ holding) state (balance should have increased):"
wallet account get --key-path "m/44'/60'/0'/0/4"
echo "Keycard path 5 (LEE holding) state (balance should have increased):"
wallet account get --key-path "m/44'/60'/0'/0/5"
echo "Keycard path 6 (LP holding) state (balance should have decreased):"
wallet account get --key-path "m/44'/60'/0'/0/6"

# =============================================================================
# (11) ATA create — keycard path 7 as owner for LEZ
# =============================================================================
echo ""
echo "=== (11) ATA create: keycard path 7 as owner, LEZ token ==="
ATA_OWNER_ID=$(wallet account id --key-path "m/44'/60'/0'/0/7")
echo "ATA owner (keycard path 7): $ATA_OWNER_ID"

wallet ata create \
  --key-path         "m/44'/60'/0'/0/7" \
  --token-definition "$LEZ_DEF_ID"
echo "ATA created for keycard path 7 / LEZ"

sleep 15

LEZ_ATA_ID=$(wallet ata address --owner "$ATA_OWNER_ID" --token-definition "$LEZ_DEF_ID")
echo "Keycard path 7 LEZ ATA ID: $LEZ_ATA_ID"
echo "ATA state (should be initialized with zero balance):"
wallet account get --account-id "Public/$LEZ_ATA_ID"

# Fund the ATA from LEZ supply (path 1) — setup for tests 12 and 13
wallet token send \
  --from-key-path "m/44'/60'/0'/0/1" \
  --to            "Public/$LEZ_ATA_ID" \
  --amount 3000
echo "Funded keycard path 7 ATA with 3000 LEZ"

sleep 15

echo "ATA state after funding (balance should be 3000):"
wallet account get --account-id "Public/$LEZ_ATA_ID"

# =============================================================================
# (12) ATA send — keycard path 7's ATA → pub-receiver's ATA
# =============================================================================
echo ""
echo "=== (12) ATA send: keycard path 7's ATA → pub-receiver's ATA ==="
PUB_RECEIVER_ID=$(wallet account id --account-label pub-receiver)
wallet ata create \
  --owner           "Public/$PUB_RECEIVER_ID" \
  --token-definition "$LEZ_DEF_ID"
echo "ATA created for pub-receiver / LEZ"

sleep 15

PUB_RECEIVER_ATA_ID=$(wallet ata address --owner "$PUB_RECEIVER_ID" --token-definition "$LEZ_DEF_ID")
echo "pub-receiver LEZ ATA ID: $PUB_RECEIVER_ATA_ID"
echo "pub-receiver ATA state (should be initialized with zero balance):"
wallet account get --account-id "Public/$PUB_RECEIVER_ATA_ID"

wallet ata send \
  --from-key-path    "m/44'/60'/0'/0/7" \
  --token-definition "$LEZ_DEF_ID" \
  --to               "$PUB_RECEIVER_ATA_ID" \
  --amount           500
echo "Sent 500 LEZ: keycard path 7 ATA → pub-receiver ATA"

sleep 15

echo "Keycard path 7 ATA state (balance should be 2500):"
wallet account get --account-id "Public/$LEZ_ATA_ID"
echo "pub-receiver ATA state (balance should be 500):"
wallet account get --account-id "Public/$PUB_RECEIVER_ATA_ID"

# =============================================================================
# (13) ATA burn — keycard path 7's ATA burns 200 LEZ
# =============================================================================
echo ""
echo "=== (13) ATA burn: keycard path 7's ATA burns 200 LEZ ==="
wallet ata burn \
  --key-path         "m/44'/60'/0'/0/7" \
  --token-definition "$LEZ_DEF_ID" \
  --amount           200
echo "Burned 200 LEZ from keycard path 7 ATA"

sleep 15

echo "Keycard path 7 ATA state (balance should be 2300):"
wallet account get --account-id "Public/$LEZ_ATA_ID"
echo "LEZ definition state (total supply should reflect burn):"
wallet account get --key-path "m/44'/60'/0'/0/0"

echo ""
echo "=== All keycard token + AMM + ATA tests finished ==="

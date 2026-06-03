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
# Keycard setup
# =============================================================================
echo ""
echo "=== Keycard setup ==="
wallet keycard available
export KEYCARD_MNEMONIC="fashion degree mountain wool question damp current pond grow dolphin chronic then"
wallet keycard load
unset KEYCARD_MNEMONIC

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
echo "=== (1) Create LEZ token (keycard def=path2, supply=path3) ==="
wallet token new \
  --definition-account-id "m/44'/60'/0'/0/2" \
  --supply-account-id     "m/44'/60'/0'/0/3" \
  --name LEZ \
  --total-supply 100000
echo "LEZ token created"

# =============================================================================
# (2) Create LEE token — definition AND supply via keycard paths
# =============================================================================
echo ""
echo "=== (2) Create LEE token (keycard def=path4, supply=path5) ==="
wallet token new \
  --definition-account-id "m/44'/60'/0'/0/4" \
  --supply-account-id     "m/44'/60'/0'/0/5" \
  --name LEE \
  --total-supply 100000
echo "LEE token created"

sleep 15

LEZ_DEF_ID=$(wallet account id --account-id "m/44'/60'/0'/0/2")
LEE_DEF_ID=$(wallet account id --account-id "m/44'/60'/0'/0/4")
echo "LEZ definition ID: $LEZ_DEF_ID"
echo "LEE definition ID: $LEE_DEF_ID"

echo "Keycard path 2 (LEZ definition) state:"
wallet account get --account-id "m/44'/60'/0'/0/2"
echo "Keycard path 3 (LEZ supply) state:"
wallet account get --account-id "m/44'/60'/0'/0/3"
echo "Keycard path 4 (LEE definition) state:"
wallet account get --account-id "m/44'/60'/0'/0/4"
echo "Keycard path 5 (LEE supply) state:"
wallet account get --account-id "m/44'/60'/0'/0/5"

# =============================================================================
# Initialize token holding accounts
# =============================================================================
echo ""
echo "=== Initialize token holding accounts ==="

# Keycard path 6: LEZ holding (mint 0 to initialize)
wallet token mint \
  --definition "m/44'/60'/0'/0/2" \
  --holder     "m/44'/60'/0'/0/6" \
  --amount 0
echo "LEZ holding initialized for keycard path 6"

# Keycard path 7: LEE holding (different definition — safe to submit immediately)
wallet token mint \
  --definition "m/44'/60'/0'/0/4" \
  --holder     "m/44'/60'/0'/0/7" \
  --amount 0
echo "LEE holding initialized for keycard path 7"

# Wait for path2 (LEZ def) and path4 (LEE def) nonces to be confirmed before reusing them
sleep 15

# pub-receiver: public LEZ holding
wallet token mint \
  --definition "m/44'/60'/0'/0/2" \
  --holder     pub-receiver \
  --amount 0
echo "LEZ holding initialized for pub-receiver"

# amm-lee-fund: LEE holding (different definition — safe to submit with pub-receiver)
wallet token mint \
  --definition "m/44'/60'/0'/0/4" \
  --holder     amm-lee-fund \
  --amount 0
echo "LEE holding initialized for amm-lee-fund"

# Wait for path2 nonce to be confirmed before the third LEZ mint
sleep 15

# amm-lez-fund: LEZ holding
wallet token mint \
  --definition "m/44'/60'/0'/0/2" \
  --holder     amm-lez-fund \
  --amount 0
echo "AMM seed holdings initialized"

# =============================================================================
# Fund keycard holdings and AMM seed accounts from supply
# =============================================================================
echo ""
echo "=== Fund keycard holdings and AMM seed accounts ==="

wallet token send \
  --from   "m/44'/60'/0'/0/3" \
  --to     "m/44'/60'/0'/0/6" \
  --amount 20000
echo "Transferred 20000 LEZ → keycard path 6"

wallet token send \
  --from   "m/44'/60'/0'/0/5" \
  --to     "m/44'/60'/0'/0/7" \
  --amount 20000
echo "Transferred 20000 LEE → keycard path 7"

# Wait for path3 and path5 nonces to be confirmed before reusing them
sleep 15

wallet token send \
  --from   "m/44'/60'/0'/0/3" \
  --to     amm-lez-fund \
  --amount 10000
echo "Transferred 10000 LEZ → amm-lez-fund"

wallet token send \
  --from   "m/44'/60'/0'/0/5" \
  --to     amm-lee-fund \
  --amount 10000
echo "Transferred 10000 LEE → amm-lee-fund"

sleep 15

echo "Keycard path 6 (LEZ holding) state (balance should be 20000):"
wallet account get --account-id "m/44'/60'/0'/0/6"
echo "Keycard path 7 (LEE holding) state (balance should be 20000):"
wallet account get --account-id "m/44'/60'/0'/0/7"
echo "amm-lez-fund state (balance should be 10000):"
wallet account get --account-id amm-lez-fund
echo "amm-lee-fund state (balance should be 10000):"
wallet account get --account-id amm-lee-fund

# =============================================================================
# (3) Token transfer: keycard path 6 (LEZ) → public account
# =============================================================================
echo ""
echo "=== (3) Token transfer: keycard path 6 → pub-receiver (public) ==="
wallet token send \
  --from   "m/44'/60'/0'/0/6" \
  --to     pub-receiver \
  --amount 1000
echo "Transferred 1000 LEZ: keycard path 6 → pub-receiver"

sleep 15

echo "Keycard path 6 (LEZ) state (balance should be 19000):"
wallet account get --account-id "m/44'/60'/0'/0/6"
echo "pub-receiver state (balance should be 1000):"
wallet account get --account-id pub-receiver

# =============================================================================
# (4) Token transfer: keycard path 6 (LEZ) → private account (shielded)
# =============================================================================
echo ""
echo "=== (4) Token transfer: keycard path 6 → priv-receiver (private, shielded) ==="
PRIV_RECEIVER=$(wallet account new private | grep -o 'Private/[^[:space:]]*' | head -1)
echo "Fresh private receiver account: $PRIV_RECEIVER"

wallet token send \
  --from   "m/44'/60'/0'/0/6" \
  --to     "$PRIV_RECEIVER" \
  --amount 500
echo "Shielded transfer of 500 LEZ: keycard path 6 → $PRIV_RECEIVER"

wallet account sync-private

sleep 15

echo "Keycard path 6 (LEZ) state (balance should be 18500):"
wallet account get --account-id "m/44'/60'/0'/0/6"
echo "priv-receiver state (balance should be 500):"
wallet account get --account-id "$PRIV_RECEIVER"

# =============================================================================
# (5) Token transfer: private account → keycard path 6 (deshielded)
#     Uses priv-receiver from test (4) which holds 500 LEZ.
#     The private sender is handled by the ZK circuit; the keycard recipient
#     does not sign — resolve() derives its account ID from the card only.
# =============================================================================
echo ""
echo "=== (5) Token transfer: priv-receiver (private) → keycard path 6 (deshielded) ==="

wallet token send \
  --from   "$PRIV_RECEIVER" \
  --to     "m/44'/60'/0'/0/6" \
  --amount 300
echo "Deshielded transfer of 300 LEZ: $PRIV_RECEIVER → keycard path 6"

wallet account sync-private

sleep 15

echo "priv-receiver state (balance should be 200):"
wallet account get --account-id "$PRIV_RECEIVER"
echo "Keycard path 6 (LEZ) state (balance should be 18800):"
wallet account get --account-id "m/44'/60'/0'/0/6"

# =============================================================================
# (6) Token mint with keycard — definition signed by keycard path 2
# =============================================================================
echo ""
echo "=== (6) Token mint: keycard def path 2 mints 2000 LEZ to keycard path 6 ==="
wallet token mint \
  --definition "m/44'/60'/0'/0/2" \
  --holder     "m/44'/60'/0'/0/6" \
  --amount 2000
echo "Minted 2000 LEZ to keycard path 6"

sleep 15

echo "Keycard path 2 (LEZ definition) state (total supply should have increased):"
wallet account get --account-id "m/44'/60'/0'/0/2"
echo "Keycard path 6 (LEZ holding) state (balance should be 20800):"
wallet account get --account-id "m/44'/60'/0'/0/6"

# =============================================================================
# (7) Token burn with keycard — holder is keycard path 6
# =============================================================================
echo ""
echo "=== (7) Token burn: keycard path 6 burns 500 LEZ ==="
wallet token burn \
  --definition "Public/$LEZ_DEF_ID" \
  --holder     "m/44'/60'/0'/0/6" \
  --amount 500
echo "Burned 500 LEZ from keycard path 6"

sleep 15

echo "Keycard path 2 (LEZ definition) state (total supply should reflect burn):"
wallet account get --account-id "m/44'/60'/0'/0/2"
echo "Keycard path 6 (LEZ holding) state (balance should be 20300):"
wallet account get --account-id "m/44'/60'/0'/0/6"

# =============================================================================
# (8) Create AMM pool for LEZ/LEE — without keycard
# =============================================================================
echo ""
echo "=== (8) Create AMM pool for LEZ/LEE (without keycard) ==="

wallet amm new \
  --user-holding-a  amm-lez-fund \
  --user-holding-b  amm-lee-fund \
  --user-holding-lp amm-lp-fund \
  --balance-a 10000 \
  --balance-b 10000
echo "AMM pool created for LEZ/LEE"

sleep 15

echo "amm-lez-fund state (balance should be 0 — contributed to pool):"
wallet account get --account-id amm-lez-fund
echo "amm-lee-fund state (balance should be 0 — contributed to pool):"
wallet account get --account-id amm-lee-fund
echo "Initial LP holding state (should hold initial LP tokens):"
wallet account get --account-id amm-lp-fund
LP_DEF_ID=$(wallet account get --account-id amm-lp-fund | grep -o '"definition_id":"[^"]*"' | awk -F'"' '{print $4}')
echo "LP token definition ID: $LP_DEF_ID"

# =============================================================================
# (9) Swap tokens owned by keycard accounts
#     keycard path 7 (LEE) sells 500 LEE; keycard path 6 (LEZ) receives LEZ
# =============================================================================
echo ""
echo "=== (9) Swap: keycard path 7 sells 500 LEE, keycard path 6 receives LEZ ==="
wallet amm swap-exact-input \
  --user-holding-a "m/44'/60'/0'/0/6" \
  --user-holding-b "m/44'/60'/0'/0/7" \
  --amount-in      500 \
  --min-amount-out 1 \
  --token-definition "$LEE_DEF_ID"
echo "Swap LEE → LEZ complete via keycard"

sleep 15

echo "Keycard path 6 (LEZ holding) state (balance should have increased):"
wallet account get --account-id "m/44'/60'/0'/0/6"
echo "Keycard path 7 (LEE holding) state (balance should have decreased by 500):"
wallet account get --account-id "m/44'/60'/0'/0/7"

# =============================================================================
# (10) Add liquidity — keycard accounts for holding A (path 6), B (path 7), LP (path 8)
# =============================================================================
echo ""
echo "=== (10) Add liquidity (keycard path 6=LEZ, path 7=LEE, path 8=LP) ==="
wallet amm add-liquidity \
  --user-holding-a  "m/44'/60'/0'/0/6" \
  --user-holding-b  "m/44'/60'/0'/0/7" \
  --user-holding-lp "m/44'/60'/0'/0/8" \
  --max-amount-a  1000 \
  --max-amount-b  1000 \
  --min-amount-lp 1
echo "Add liquidity complete via keycard"

sleep 15

echo "Keycard path 6 (LEZ holding) state (balance should have decreased):"
wallet account get --account-id "m/44'/60'/0'/0/6"
echo "Keycard path 7 (LEE holding) state (balance should have decreased):"
wallet account get --account-id "m/44'/60'/0'/0/7"
echo "Keycard path 8 (LP holding) state (should have received LP tokens):"
wallet account get --account-id "m/44'/60'/0'/0/8"

# =============================================================================
# (11) Remove liquidity — keycard accounts for holding A (path 6), B (path 7), LP (path 8)
# =============================================================================
echo ""
echo "=== (11) Remove liquidity (keycard path 6=LEZ, path 7=LEE, path 8=LP) ==="
wallet amm remove-liquidity \
  --user-holding-a  "m/44'/60'/0'/0/6" \
  --user-holding-b  "m/44'/60'/0'/0/7" \
  --user-holding-lp "m/44'/60'/0'/0/8" \
  --balance-lp   500 \
  --min-amount-a 1 \
  --min-amount-b 1
echo "Remove liquidity complete via keycard"

sleep 15

echo "Keycard path 6 (LEZ holding) state (balance should have increased):"
wallet account get --account-id "m/44'/60'/0'/0/6"
echo "Keycard path 7 (LEE holding) state (balance should have increased):"
wallet account get --account-id "m/44'/60'/0'/0/7"
echo "Keycard path 8 (LP holding) state (balance should have decreased):"
wallet account get --account-id "m/44'/60'/0'/0/8"

# =============================================================================
# (12) ATA create — keycard path 9 as owner for LEZ
# =============================================================================
echo ""
echo "=== (12) ATA create: keycard path 9 as owner, LEZ token ==="
ATA_OWNER_ID=$(wallet account id --account-id "m/44'/60'/0'/0/9")
echo "ATA owner (keycard path 9): $ATA_OWNER_ID"

wallet ata create \
  --owner          "m/44'/60'/0'/0/9" \
  --token-definition "$LEZ_DEF_ID"
echo "ATA created for keycard path 9 / LEZ"

sleep 15

LEZ_ATA_ID=$(wallet ata address --owner "$ATA_OWNER_ID" --token-definition "$LEZ_DEF_ID")
echo "Keycard path 9 LEZ ATA ID: $LEZ_ATA_ID"
echo "ATA state (should be initialized with zero balance):"
wallet account get --account-id "Public/$LEZ_ATA_ID"

# Fund the ATA from LEZ supply (path 3) — setup for tests 12 and 13
wallet token send \
  --from   "m/44'/60'/0'/0/3" \
  --to     "Public/$LEZ_ATA_ID" \
  --amount 3000
echo "Funded keycard path 9 ATA with 3000 LEZ"

sleep 15

echo "ATA state after funding (balance should be 3000):"
wallet account get --account-id "Public/$LEZ_ATA_ID"

# =============================================================================
# (13) ATA send — keycard path 9's ATA → pub-receiver's ATA
# =============================================================================
echo ""
echo "=== (13) ATA send: keycard path 9's ATA → pub-receiver's ATA ==="
PUB_RECEIVER_ID=$(wallet account id --account-id pub-receiver)
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
  --from             "m/44'/60'/0'/0/9" \
  --token-definition "$LEZ_DEF_ID" \
  --to               "$PUB_RECEIVER_ATA_ID" \
  --amount           500
echo "Sent 500 LEZ: keycard path 9 ATA → pub-receiver ATA"

sleep 15

echo "Keycard path 9 ATA state (balance should be 2500):"
wallet account get --account-id "Public/$LEZ_ATA_ID"
echo "pub-receiver ATA state (balance should be 500):"
wallet account get --account-id "Public/$PUB_RECEIVER_ATA_ID"

# =============================================================================
# (14) ATA burn — keycard path 9's ATA burns 200 LEZ
# =============================================================================
echo ""
echo "=== (14) ATA burn: keycard path 9's ATA burns 200 LEZ ==="
wallet ata burn \
  --holder           "m/44'/60'/0'/0/9" \
  --token-definition "$LEZ_DEF_ID" \
  --amount           200
echo "Burned 200 LEZ from keycard path 9 ATA"

sleep 15

echo "Keycard path 9 ATA state (balance should be 2300):"
wallet account get --account-id "Public/$LEZ_ATA_ID"
echo "LEZ definition state (total supply should reflect burn):"
wallet account get --account-id "m/44'/60'/0'/0/2"

echo ""
echo "=== All keycard token + AMM + ATA tests finished ==="

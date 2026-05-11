source venv/bin/activate
export KEYCARD_PIN=111111


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
#     keycard path 7 (LEE) sells 500 LEE; keycard path 6 (LEZ) receives LEZ
# =============================================================================
echo ""
echo "=== (8) Swap: keycard path 7 sells 500 LEE, keycard path 6 receives LEZ ==="
wallet amm swap-exact-input \
  --user-holding-a-key-path "m/44'/60'/0'/0/6" \
  --user-holding-b-key-path "m/44'/60'/0'/0/7" \
  --amount-in      500 \
  --min-amount-out 1 \
  --token-definition "$LEE_DEF_ID"
echo "Swap LEE → LEZ complete via keycard"

sleep 15

echo "Keycard path 6 (LEZ holding) state (balance should have increased):"
wallet account get --key-path "m/44'/60'/0'/0/6"
echo "Keycard path 7 (LEE holding) state (balance should have decreased by 500):"
wallet account get --key-path "m/44'/60'/0'/0/7"

# =============================================================================
# (9) Add liquidity — keycard accounts for holding A (path 6), B (path 7), LP (path 8)
# =============================================================================
echo ""
echo "=== (9) Initialize LP holding (keycard path 8) before add-liquidity ==="
wallet token init \
  --definition-account-id "Public/$LP_DEF_ID" \
  --holder-key-path "m/44'/60'/0'/0/8"
echo "Keycard path 8 (LP holding) initialized"

sleep 15

echo "Keycard path 8 (LP holding) state (after init):"
wallet account get --key-path "m/44'/60'/0'/0/8"

echo ""
echo "=== (9) Add liquidity (keycard path 6=LEZ, path 7=LEE, path 8=LP) ==="
wallet amm add-liquidity \
  --user-holding-a-key-path  "m/44'/60'/0'/0/6" \
  --user-holding-b-key-path  "m/44'/60'/0'/0/7" \
  --user-holding-lp-key-path "m/44'/60'/0'/0/8" \
  --max-amount-a  1000 \
  --max-amount-b  1000 \
  --min-amount-lp 1
echo "Add liquidity complete via keycard"

sleep 15

echo "Keycard path 6 (LEZ holding) state (balance should have decreased):"
wallet account get --key-path "m/44'/60'/0'/0/6"
echo "Keycard path 7 (LEE holding) state (balance should have decreased):"
wallet account get --key-path "m/44'/60'/0'/0/7"
echo "Keycard path 8 (LP holding) state (should have received LP tokens):"
wallet account get --key-path "m/44'/60'/0'/0/8"

# =============================================================================
# (10) Remove liquidity — keycard accounts for holding A (path 6), B (path 7), LP (path 8)
# =============================================================================
echo ""
echo "=== (10) Remove liquidity (keycard path 6=LEZ, path 7=LEE, path 8=LP) ==="
wallet amm remove-liquidity \
  --user-holding-a-key-path  "m/44'/60'/0'/0/6" \
  --user-holding-b-key-path  "m/44'/60'/0'/0/7" \
  --user-holding-lp-key-path "m/44'/60'/0'/0/8" \
  --balance-lp   500 \
  --min-amount-a 1 \
  --min-amount-b 1
echo "Remove liquidity complete via keycard"

sleep 15

echo "Keycard path 6 (LEZ holding) state (balance should have increased):"
wallet account get --key-path "m/44'/60'/0'/0/6"
echo "Keycard path 7 (LEE holding) state (balance should have increased):"
wallet account get --key-path "m/44'/60'/0'/0/7"
echo "Keycard path 8 (LP holding) state (balance should have decreased):"
wallet account get --key-path "m/44'/60'/0'/0/8"
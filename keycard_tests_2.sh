source venv/bin/activate
export KEYCARD_PIN=111111

# =============================================================================
# (2) Initialize token definitions + initial supply holdings for LEZ and LEE.
#     All without keycard.
# =============================================================================
echo ""
echo "=== Test (2): Create LEZ and LEE token definitions (without keycard) ==="

wallet account new public --label lez-def    2>/dev/null || true
wallet account new public --label lez-supply 2>/dev/null || true
wallet account new public --label lee-def    2>/dev/null || true
wallet account new public --label lee-supply 2>/dev/null || true

LEZ_DEF_ID=$(wallet account id --account-label lez-def)
LEE_DEF_ID=$(wallet account id --account-label lee-def)

wallet token new \
  --definition-account-label lez-def \
  --supply-account-label     lez-supply \
  --total-supply 100000 \
  --name LEZ
echo "LEZ token created"

wallet token new \
  --definition-account-label lee-def \
  --supply-account-label     lee-supply \
  --total-supply 100000 \
  --name LEE
echo "LEE token created"

# =============================================================================
# (3) Initialize LEE token holding accounts:
#       - two public keycard holders (paths 2 and 3)
#       - one private holder (without keycard)
#
# token init is idempotent: skips if the holder already has token data.
# =============================================================================
echo ""
echo "=== Test (3): Initialize LEE token holding accounts ==="

wallet token init \
  --definition-account-id "Public/$LEE_DEF_ID" \
  --holder-key-path "m/44'/60'/0'/0/2"
echo "LEE holding initialized for keycard m/44'/60'/0'/0/2"

wallet token init \
  --definition-account-id "Public/$LEE_DEF_ID" \
  --holder-key-path "m/44'/60'/0'/0/3"
echo "LEE holding initialized for keycard m/44'/60'/0'/0/3"

wallet account new private --label lee-priv-holder 2>/dev/null || true
wallet token init \
  --definition-account-id "Public/$LEE_DEF_ID" \
  --holder-account-label   lee-priv-holder
echo "Private LEE holding initialized"

# Fund the two keycard LEE holdings from the supply.
# Only the sender (lee-supply, stored key) needs to sign for a token Transfer
# to an already-initialized holding.
wallet token send \
  --from-label  lee-supply \
  --to-key-path "m/44'/60'/0'/0/2" \
  --amount 5000
echo "Transferred 5000 LEE → keycard path 2"

wallet token send \
  --from-label  lee-supply \
  --to-key-path "m/44'/60'/0'/0/3" \
  --amount 5000
echo "Transferred 5000 LEE → keycard path 3"

echo "Keycard path 2 LEE state (balance should be 5000):"
wallet account get --key-path "m/44'/60'/0'/0/2"
echo "Keycard path 3 LEE state (balance should be 5000):"
wallet account get --key-path "m/44'/60'/0'/0/3"

# =============================================================================
# (4) Shielded (public → private) LEE transfer from keycard holding to the
#     private LEE holding account.
# =============================================================================
echo ""
echo "=== Test (4): Shielded transfer keycard LEE holding → private LEE holding ==="

wallet token send \
  --from-key-path "m/44'/60'/0'/0/2" \
  --to-label      lee-priv-holder \
  --amount 500
echo "Shielded transfer complete (500 LEE: path-2 keycard → private holder)"

wallet account sync-private
echo "Private LEE holder state (balance should be 500):"
wallet account get --account-label lee-priv-holder

# =============================================================================
# (5) Create AMM pool for LEZ/LEE (without keycard)
# =============================================================================
echo ""
echo "=== Test (5): Create AMM pool for LEZ/LEE (without keycard) ==="

wallet account new public --label amm-lp-lez-holding 2>/dev/null || true
wallet account new public --label amm-lp-lee-holding 2>/dev/null || true
wallet account new public --label amm-lp-lp-holding  2>/dev/null || true

wallet token init \
  --definition-account-id "Public/$LEZ_DEF_ID" \
  --holder-account-label  amm-lp-lez-holding
wallet token init \
  --definition-account-id "Public/$LEE_DEF_ID" \
  --holder-account-label  amm-lp-lee-holding

wallet token send --from-label lez-supply --to-label amm-lp-lez-holding --amount 40000
wallet token send --from-label lee-supply --to-label amm-lp-lee-holding --amount 40000

wallet amm new \
  --user-holding-a-label  amm-lp-lez-holding \
  --user-holding-b-label  amm-lp-lee-holding \
  --user-holding-lp-label amm-lp-lp-holding \
  --balance-a 40000 \
  --balance-b 40000
echo "AMM pool created for LEZ/LEE"

# =============================================================================
# (6) Swaps, add liquidity, remove liquidity using keycard holding accounts.
#
# Path layout:
#   path 2 → LEE holding (4500 LEE after step 4)
#   path 3 → LEE holding (5000 LEE)
#   path 4 → fresh; initialized below as LEZ holding (receives swapped LEZ)
# =============================================================================
echo ""
echo "=== Test (6a): Initialize LEZ holding for keycard path 4 (swap output) ==="
wallet token init \
  --definition-account-id "Public/$LEZ_DEF_ID" \
  --holder-key-path "m/44'/60'/0'/0/4"
echo "LEZ holding initialized for keycard m/44'/60'/0'/0/4"

# Resolve raw account IDs needed for the swap --user-holding-* args.
PATH2_ID=$(wallet account id --key-path "m/44'/60'/0'/0/2")
PATH3_ID=$(wallet account id --key-path "m/44'/60'/0'/0/3")
PATH4_ID=$(wallet account id --key-path "m/44'/60'/0'/0/4")

echo "Path 2: $PATH2_ID  Path 3: $PATH3_ID  Path 4: $PATH4_ID"
echo "LEE def ID: $LEE_DEF_ID"

echo ""
echo "=== Test (6b): Swap LEE → LEZ (path 2 sells LEE, path 4 receives LEZ) ==="
# user-holding-b (path 2) is the input (LEE); user-holding-a (path 4) receives LEZ.
# --key-path signs for the input account (path 2).
wallet amm swap-exact-input \
  --user-holding-a "Public/$PATH4_ID" \
  --user-holding-b "Public/$PATH2_ID" \
  --amount-in      500 \
  --min-amount-out 1 \
  --token-definition "$LEE_DEF_ID" \
  --key-path "m/44'/60'/0'/0/2"
echo "Swap LEE→LEZ complete via keycard"

echo "Path 4 (LEZ) state:"
wallet account get --key-path "m/44'/60'/0'/0/4"
echo "Path 2 (LEE) state:"
wallet account get --key-path "m/44'/60'/0'/0/2"

echo ""
echo "=== Test (6c): Add liquidity (path 4 LEZ + path 3 LEE) ==="
wallet amm add-liquidity \
  --user-holding-a-key-path "m/44'/60'/0'/0/4" \
  --user-holding-b-key-path "m/44'/60'/0'/0/3" \
  --user-holding-lp-label   amm-lp-lp-holding \
  --min-amount-lp 1 \
  --max-amount-a  200 \
  --max-amount-b  200
echo "Add liquidity complete via keycard"

echo ""
echo "=== Test (6d): Remove liquidity (LP from amm-lp-lp-holding) ==="
wallet amm remove-liquidity \
  --user-holding-a-label  amm-lp-lez-holding \
  --user-holding-b-label  amm-lp-lee-holding \
  --user-holding-lp-label amm-lp-lp-holding \
  --balance-lp  1000 \
  --min-amount-a 1 \
  --min-amount-b 1
echo "Remove liquidity complete"

echo ""
echo "=== All keycard tests finished ==="

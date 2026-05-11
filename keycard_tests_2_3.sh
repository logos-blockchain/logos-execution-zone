source venv/bin/activate
export KEYCARD_PIN=111111



# =============================================================================
# (11) ATA create — keycard path 9 as owner for LEZ
# =============================================================================
echo ""
echo "=== (11) ATA create: keycard path 9 as owner, LEZ token ==="
ATA_OWNER_ID=$(wallet account id --key-path "m/44'/60'/0'/0/9")
echo "ATA owner (keycard path 9): $ATA_OWNER_ID"

wallet ata create \
  --key-path         "m/44'/60'/0'/0/9" \
  --token-definition "$LEZ_DEF_ID"
echo "ATA created for keycard path 9 / LEZ"

sleep 15

LEZ_ATA_ID=$(wallet ata address --owner "$ATA_OWNER_ID" --token-definition "$LEZ_DEF_ID")
echo "Keycard path 9 LEZ ATA ID: $LEZ_ATA_ID"
echo "ATA state (should be initialized with zero balance):"
wallet account get --account-id "Public/$LEZ_ATA_ID"

# Fund the ATA from LEZ supply (path 3) — setup for tests 12 and 13
wallet token send \
  --from-key-path "m/44'/60'/0'/0/3" \
  --to            "Public/$LEZ_ATA_ID" \
  --amount 3000
echo "Funded keycard path 9 ATA with 3000 LEZ"

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
  --from-key-path    "m/44'/60'/0'/0/9" \
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
# (13) ATA burn — keycard path 7's ATA burns 200 LEZ
# =============================================================================
echo ""
echo "=== (13) ATA burn: keycard path 7's ATA burns 200 LEZ ==="
wallet ata burn \
  --key-path         "m/44'/60'/0'/0/9" \
  --token-definition "$LEZ_DEF_ID" \
  --amount           200
echo "Burned 200 LEZ from keycard path 9 ATA"

sleep 15

echo "Keycard path 9 ATA state (balance should be 2300):"
wallet account get --account-id "Public/$LEZ_ATA_ID"
echo "LEZ definition state (total supply should reflect burn):"
wallet account get --key-path "m/44'/60'/0'/0/2"

echo ""
echo "=== All keycard token + AMM + ATA tests finished ==="

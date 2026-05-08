#!/bin/bash
# =============================================================================
# LP-0016: Anonymous Forum — End-to-End Demonstration Script
# =============================================================================
#
# PREREQUISITES (must be running before executing this script):
#   Terminal 1: just run-bedrock          (Bedrock L1 node via Docker)
#   Terminal 2: just run-indexer          (LEZ indexer)
#   Terminal 3: just run-sequencer        (LEZ sequencer)
#
# SETUP STEPS:
#   1. Install the wallet:
#      cargo install --path wallet --force
#
#   2. Build reproducible artifacts (requires Docker):
#      just build-artifacts
#
#   3. Install and generate the IDL:
#      cargo install --path /path/to/spel --bin spel --force
#      spel generate-idl program_methods/guest/src/bin/membership_registry.rs \
#          > membership_registry-idl.json
#
#   4. Deploy the programs and note the returned program IDs:
#      just run-wallet deploy-program artifacts/program_methods/membership_registry.bin
#      just run-wallet deploy-program artifacts/program_methods/forum_membership_proof.bin
#
#   5. Set PROGRAM_PATH below to the deployed program binary path.
#      Set ADMIN to your wallet's public key (run: just run-wallet account list)
#
# NOTE: This script demonstrates the on-chain instruction lifecycle using the
#       SPEL CLI. The full cryptographic flow (ZK proofs, N-of-M moderation,
#       NSK reconstruction) is demonstrated via the integration test:
#
#       HOST_CC=gcc cargo test --release -p integration_tests \
#           -- test_forum_e2e_full_lifecycle --nocapture
#
# =============================================================================

set -e

echo "==========================================="
echo "   LP-0016: Anonymous Forum SPEL Demo"
echo "==========================================="

# --- CONFIGURATION (edit before running) ---

# Path to SPEL CLI (must be installed globally: cargo install --path /path/to/spel --bin spel --force)
SPEL_CLI="spel"

# Path to the deployed program binary
PROGRAM_PATH="artifacts/program_methods/membership_registry.bin"

# Path to the generated IDL file
IDL_PATH="membership_registry-idl.json"

# Your wallet admin public key (run: just run-wallet account list)
# Replace with the actual key from your wallet
ADMIN="11111111111111111111111111111111"

# Forum IDs — unique 32-byte identifiers per forum instance (hex, no 0x prefix)
# Forum A: lightweight moderation (K=2, N=2-of-3)
FORUM_A="0000000000000000000000000000000000000000000000000000000000000001"
# Forum B: stricter moderation (K=3, N=3-of-5)
FORUM_B="0000000000000000000000000000000000000000000000000000000000000002"

# --- VALIDATION ---
if [ ! -f "$IDL_PATH" ]; then
    echo "ERROR: IDL file not found at $IDL_PATH"
    echo "Run: cargo run --manifest-path ../AllProject/spel/Cargo.toml --bin spel -- generate-idl program_methods/guest/src/bin/membership_registry.rs > $IDL_PATH"
    exit 1
fi

if [ ! -f "$PROGRAM_PATH" ]; then
    echo "ERROR: Program binary not found at $PROGRAM_PATH"
    echo "Run: just build-artifacts"
    exit 1
fi

# =============================================================================
# FORUM INSTANCE A — K=2, N=2-of-3 (lightweight moderation)
# =============================================================================
echo ""
echo "=== Forum Instance A (K=2, N=2, M=3) ==="
echo ""

echo "[A-1/4] Initialize Forum A..."
$SPEL_CLI --idl $IDL_PATH -p $PROGRAM_PATH -- initialize-forum \
    --forum-id $FORUM_A \
    --k-strikes 2 \
    --n-moderators 2 \
    --m-moderators 3 \
    --admin $ADMIN

echo "[A-2/4] Register Member in Forum A (stake: 1500)..."
$SPEL_CLI --idl $IDL_PATH -p $PROGRAM_PATH -- register-member \
    --forum-id $FORUM_A \
    --commitment 0000000000000000000000000000000000000000000000000000000000000000 \
    --stake-amount 1500 \
    --member $ADMIN

echo "[A-3/4] Verify Post in Forum A..."
# registry-root and tracing-tag are derived from the ZK proof journal in production.
# These placeholder values demonstrate the instruction interface.
$SPEL_CLI --idl $IDL_PATH -p $PROGRAM_PATH -- verify-post \
    --forum-id $FORUM_A \
    --registry-root 0000000000000000000000000000000000000000000000000000000000000000 \
    --tracing-tag aabbccdd00000000000000000000000000000000000000000000000000000001

echo "[A-4/4] Slash Member in Forum A..."
# slashed-nsk is the NSK reconstructed by SlashAggregator after K strikes.
# In production this comes from: aggregator.reconstruct_nsk(&accumulated_strikes)
$SPEL_CLI --idl $IDL_PATH -p $PROGRAM_PATH -- slash-member \
    --forum-id $FORUM_A \
    --slashed-nsk 0000000000000000000000000000000000000000000000000000000000000000 \
    --authority $ADMIN

# =============================================================================
# FORUM INSTANCE B — K=3, N=3-of-5 (stricter moderation)
# =============================================================================
echo ""
echo "=== Forum Instance B (K=3, N=3, M=5) ==="
echo ""

echo "[B-1/4] Initialize Forum B..."
$SPEL_CLI --idl $IDL_PATH -p $PROGRAM_PATH -- initialize-forum \
    --forum-id $FORUM_B \
    --k-strikes 3 \
    --n-moderators 3 \
    --m-moderators 5 \
    --admin $ADMIN

echo "[B-2/4] Register Member in Forum B (stake: 2000)..."
$SPEL_CLI --idl $IDL_PATH -p $PROGRAM_PATH -- register-member \
    --forum-id $FORUM_B \
    --commitment 0000000000000000000000000000000000000000000000000000000000000000 \
    --stake-amount 2000 \
    --member $ADMIN

echo "[B-3/4] Verify Post in Forum B..."
$SPEL_CLI --idl $IDL_PATH -p $PROGRAM_PATH -- verify-post \
    --forum-id $FORUM_B \
    --registry-root 0000000000000000000000000000000000000000000000000000000000000000 \
    --tracing-tag bbccddee00000000000000000000000000000000000000000000000000000002

echo "[B-4/4] Slash Member in Forum B..."
$SPEL_CLI --idl $IDL_PATH -p $PROGRAM_PATH -- slash-member \
    --forum-id $FORUM_B \
    --slashed-nsk 0000000000000000000000000000000000000000000000000000000000000000 \
    --authority $ADMIN

echo ""
echo "==========================================="
echo "   Demo Complete!"
echo "   Forum A: K=2, N=2-of-3 moderators"
echo "   Forum B: K=3, N=3-of-5 moderators"
echo ""
echo "   Two independent forum instances demonstrated"
echo "   with different K and N-of-M parameters."
echo ""
echo "   For full cryptographic E2E test (real ZK proofs):"
echo "   HOST_CC=gcc cargo test --release -p integration_tests \\"
echo "       -- test_forum_e2e_full_lifecycle --nocapture"
echo "==========================================="

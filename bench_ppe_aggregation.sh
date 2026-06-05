#!/usr/bin/env bash
# Runs the PPE aggregation test across a range of fixture counts and prints a results table.
#
# Usage:
#   ./bench_ppe_aggregation.sh
#
# Environment:
#   PPE_FIXTURES  - path to the fixture file (default: ppe_fixtures.bin)
#   COUNTS        - space-separated list of counts to test (default: powers of 2, 1..256)
#
# Example:
#   PPE_FIXTURES=/path/to/ppe_fixtures.bin COUNTS="4 8 16" ./bench_ppe_aggregation.sh

set -euo pipefail

FIXTURES="$(realpath "${PPE_FIXTURES:-ppe_fixtures.bin}")"
COUNTS="${COUNTS:-1 2 4 6 8 10 12 14 16}"

if [ ! -f "$FIXTURES" ]; then
    echo "ERROR: fixture file '$FIXTURES' not found."
    echo "Generate it first:"
    echo "  RISC0_DEV_MODE=1 cargo run --release -p ppe_test_data_gen -- --output $FIXTURES"
    exit 1
fi

printf "\n%-6s  %14s  %20s\n" "n" "proving_ms" "proof_size_bytes"
printf "%-6s  %14s  %20s\n" "------" "--------------" "--------------------"

for count in $COUNTS; do
    line=$(
        PPE_FIXTURES="$FIXTURES" \
        PPE_FIXTURES_COUNT="$count" \
        cargo test -p lee aggregate_ppe_proofs_from_fixtures -- --nocapture 2>&1 \
        | grep -v "^test_programs:" \
        | grep "\[lee::analytics\] ppe_aggregation" || true
    )

    if [ -z "$line" ]; then
        printf "%-6s  %14s  %20s\n" "$count" "skipped" "-"
        continue
    fi

    n=$(echo "$line"          | grep -o 'n=[0-9]*'               | cut -d= -f2)
    proving_ms=$(echo "$line" | grep -o 'proving_ms=[0-9]*'      | cut -d= -f2)
    proof_size=$(echo "$line" | grep -o 'proof_size_bytes=[0-9]*'| cut -d= -f2)

    printf "%-6s  %14s  %20s\n" "$n" "$proving_ms" "$proof_size"
done

printf "\n"

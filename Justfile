set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

default:
    @just --list

# ---- Configuration ----
ARTIFACTS := "artifacts"

# On macOS the integration-test binary links pyo3 against the CommandLineTools
# Python framework with no embedded rpath, so it needs this to launch. Empty on
# Linux/CI, which is unaffected.
DEMO_ENV := if os() == "macos" { "DYLD_FALLBACK_FRAMEWORK_PATH=/Library/Developer/CommandLineTools/Library/Frameworks" } else { "" }

# Build risc0 program artifacts and test fixture.
build-artifacts:
    @echo "🔨 Building artifacts"
    @rm -rf {{ARTIFACTS}}
    @just build-artifact lee/privacy_preserving_circuit
    @just build-artifact lez/programs programs

    @if [ "${GITHUB_ACTIONS:-}" = "true" ]; then \
        echo "Skipping test fixture regeneration because CI doesn't need it"; \
    else \
        just regenerate-test-fixture; \
    fi

RISC0_DOCKER_CONTAINER_TAG := "r0.1.91.1"

build-artifact methods_path features="":
    @echo "Building artifacts for {{methods_path}}"
    @rm -rf target/{{methods_path}}/riscv32im-risc0-zkvm-elf/docker/*.bin
    @if [ "{{features}}" = "" ]; then \
        RISC0_DOCKER_CONTAINER_TAG={{RISC0_DOCKER_CONTAINER_TAG}} CARGO_TARGET_DIR=target/{{methods_path}} cargo risczero build --manifest-path {{methods_path}}/Cargo.toml; \
    else \
        RISC0_DOCKER_CONTAINER_TAG={{RISC0_DOCKER_CONTAINER_TAG}} CARGO_TARGET_DIR=target/{{methods_path}} cargo risczero build --no-default-features --features {{features}} --manifest-path {{methods_path}}/Cargo.toml; \
    fi
    @mkdir -p {{ARTIFACTS}}/{{methods_path}}
    @cp target/{{methods_path}}/riscv32im-risc0-zkvm-elf/docker/*.bin {{ARTIFACTS}}/{{methods_path}}

# Format codebase.
fmt:
    @echo "🎨 Formatting codebase"
    cargo +nightly fmt
    taplo fmt

# Run tests.
test:
    @echo "🧪 Running tests"
    RISC0_DEV_MODE=1 cargo nextest run --no-fail-fast

# Regenerate the prebuilt sequencer db dump for fast TestContext::new() (needs Docker; commit the dump).
regenerate-test-fixture:
    @echo "🧪 Regenerating test fixture"
    RISC0_DEV_MODE=1 RUST_LOG=info cargo run -p test_fixtures --bin regenerate_test_fixture

# Regenerate the committed Grafana dashboards from the Rust generator
# (tools/dashboard_gen) and commit the result. CI checks these are up to date.
regenerate-dashboards:
    @echo "📊 Regenerating Grafana dashboards"
    @cargo build -q -p dashboard_gen
    @cargo run -q -p dashboard_gen -- sequencer > monitoring/grafana/dashboards/sequencer.json

# Run criterion benches: fast crypto primitives, then the slow PPE verify (real proving setup).
bench:
    @echo "📊 Running criterion benches"
    cargo bench -p crypto_primitives_bench --bench primitives
    cargo bench -p cycle_bench --features ppe --bench verify

# Run Bedrock node in docker.
[working-directory: 'bedrock']
run-bedrock:
    @echo "⛓️ Running bedrock"
    docker compose up

# Run Prometheus + Grafana in docker. Grafana: http://localhost:3000 (anonymous
# admin), Prometheus: http://localhost:9090. Scrapes the sequencer's /metrics.
[working-directory: 'monitoring']
run-monitoring:
    @echo "📊 Running Prometheus (http://localhost:9090) + Grafana (http://localhost:3000)"
    docker compose up

# Run Sequencer. Extra args are forwarded to the binary. Run with RISC0_DEV_MODE=1 to disable proof verification for faster iteration.
[working-directory: 'lez/sequencer/service']
run-sequencer *args:
    @echo "🧠 Running sequencer"
    RUST_LOG=info cargo run --release -p sequencer_service -- configs/debug/sequencer_config.json {{args}}

# Run Sequencer with mocked Bedrock clients. Takes the same args as `run-sequencer`.
[working-directory: 'lez/sequencer/service']
run-sequencer-standalone *args:
    @echo "🧪 Running sequencer in standalone mode"
    RUST_LOG=info cargo run --features standalone --release -p sequencer_service -- configs/debug/sequencer_config.json {{args}}

# Run Indexer. Run with RISC0_DEV_MODE=1 to disable proof verification for faster iteration.
[working-directory: 'lez/indexer/service']
run-indexer mock="":
    @echo "🔍 Running indexer"
    @if [ "{{mock}}" = "mock" ]; then \
        echo "🧪 Using mock data"; \
        RUST_LOG=info cargo run --release --features mock-responses -p indexer_service configs/debug/indexer_config.json; \
    else \
        echo "🚀 Using real data"; \
        RUST_LOG=info cargo run --release -p indexer_service configs/debug/indexer_config.json; \
    fi

# Run Explorer.
[working-directory: 'lez/explorer_service']
run-explorer:
    @echo "🌐 Running explorer"
    RUST_LOG=info cargo leptos serve

# Run Wallet.
[working-directory: 'lez/wallet']
run-wallet +args:
    @echo "🔑 Running wallet"
    LEE_WALLET_HOME_DIR=$(pwd)/configs/debug cargo run --release -p wallet -- {{args}}

# Query sequencer metrics in raw format. Useful for quick debugging. For a more detailed view, use `just run-monitoring`.
get-sequencer-metrics:
    @echo "📊 Querying sequencer's metrics"
    curl http://localhost:9000/metrics

# Import test accounts supplied in sequencer configuration.
wallet-import-test-accounts:
    @echo "⚙️ Initializing accounts"
    just run-wallet account import public --private-key 7f273098f25b71e6c005a9519f2678da8d1c7f01f6a27778e2d9948abdf901fb
    just run-wallet vault claim --account-id Public/CbgR6tj5kWx5oziiFptM7jMvrQeYY3Mzaao6ciuhSr2r --amount 10000

    just run-wallet account import public --private-key f434f8741720014586ae43356d2aec6257da086222f604ddb75d69733b86fc4c
    just run-wallet vault claim --account-id Public/2RHZhw9h534Zr3eq2RGhQete2Hh667foECzXPmSkGni2 --amount 20000

    just run-wallet account list

# Demo: cross-zone ping. Boots two zones on one Bedrock and sends a message from
# zone A to zone B, where the indexer re-derives and verifies it (Option B)
# before ping_receiver records it. Dev mode, no proving.
demo-cross-zone-ping:
    @echo "📡 Cross-zone ping demo (message A → B, indexer-verified)"
    {{DEMO_ENV}} RISC0_DEV_MODE=1 cargo test -p integration_tests --release --test cross_zone_verified -- --nocapture

# Demo: cross-zone wrapped-token bridge. Locks a balance on zone A and mints the
# wrapped token to a recipient on zone B over the same verified spine.
demo-cross-zone-bridge:
    @echo "🌉 Cross-zone bridge demo (lock on A, mint on B)"
    {{DEMO_ENV}} RISC0_DEV_MODE=1 cargo test -p integration_tests --release --test cross_zone_bridge -- --nocapture

# Demo: interactive cross-zone chat. Boots two zones on one Bedrock and serves a
# local two-column web UI; type in one zone and watch the message cross into the
# other. Two people can chat across the zones. Dev mode, no proving.
cross-zone-chat:
    @echo "💬 Cross-zone chat demo — open the printed localhost URL"
    {{DEMO_ENV}} RISC0_DEV_MODE=1 cargo run -p cross_zone_chat --release

# Demo: two CACP participant zones plus a neutral LEZ bond execution zone.
# Bedrock appends one fee transfer after the two business inscriptions.
demo-cacp:
    @echo "🔐 CACP + protocol-enforced LEZ bond demo"
    {{DEMO_ENV}} RISC0_DEV_MODE=1 cargo run -p cacp_demo

# Clean runtime data
clean:
    @echo "🧹 Cleaning run artifacts"
    rm -rf lez/sequencer/service/bedrock_signing_key
    rm -rf lez/sequencer/service/rocksdb*
    rm -rf lez/indexer/service/rocksdb*
    rm -rf lez/wallet/configs/debug/storage.json
    rm -rf lez/wallet/configs/debug/statistics.json
    rm -rf rocksdb*
    cd bedrock && docker compose down -v && cd ..
    cd monitoring && docker compose down -v && cd ..

# Chef stage - uses pre-built cargo-chef image
FROM lukemathwalker/cargo-chef:latest-rust-1.94.0-slim-trixie AS chef

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libclang-dev \
    clang \
    cmake \
    ninja-build \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install r0vm
# Use quick install for x86-64 (risczero provides binaries only for this linux platform)
# Manual build for other platforms (including arm64 Linux)
RUN ARCH=$(uname -m); \
    if [ "$ARCH" = "x86_64" ]; then \
        echo "Using quick install for $ARCH"; \
        curl -L https://risczero.com/install | bash; \
        export PATH="/root/.cargo/bin:/root/.risc0/bin:${PATH}"; \
        rzup install; \
    else \
        echo "Using manual build for $ARCH"; \
        git clone --depth 1 --branch release-3.0 https://github.com/risc0/risc0.git; \
        git clone --depth 1 --branch r0.1.91.1 https://github.com/risc0/rust.git; \
        cd /risc0; \
        cargo install --path rzup; \
        rzup build --path /rust rust --verbose; \
        cargo install --path risc0/cargo-risczero; \
    fi
ENV PATH="/root/.cargo/bin:/root/.risc0/bin:${PATH}"
RUN cp "$(which r0vm)" /usr/local/bin/r0vm
RUN test -x /usr/local/bin/r0vm
RUN r0vm --version

# Install logos blockchain circuits
RUN curl -sSL https://raw.githubusercontent.com/logos-blockchain/logos-blockchain/main/scripts/setup-logos-blockchain-circuits.sh | bash

WORKDIR /indexer_service

# Planner stage - generates dependency recipe
FROM chef AS planner
COPY . .
RUN cargo chef prepare --bin indexer_service --recipe-path recipe.json

# Builder stage - builds dependencies and application
FROM chef AS builder
COPY --from=planner /indexer_service/recipe.json recipe.json
# Build dependencies only (this layer will be cached)
RUN cargo chef cook --bin indexer_service --release --recipe-path recipe.json

# Copy source code
COPY . .

# Build the actual application
RUN cargo build --release --bin indexer_service

# Strip debug symbols to reduce binary size
RUN strip /indexer_service/target/release/indexer_service

# Runtime stage - minimal image
FROM debian:trixie-slim

# Install runtime dependencies
RUN apt-get update \
 && apt-get install -y gosu jq \
 && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash indexer_service_user && \
    mkdir -p /indexer_service /etc/indexer_service && \
    chown -R indexer_service_user:indexer_service_user /indexer_service /etc/indexer_service

# Copy binary from builder
COPY --from=builder --chown=indexer_service_user:indexer_service_user /indexer_service/target/release/indexer_service /usr/local/bin/indexer_service

# Copy r0vm binary from builder
COPY --from=builder --chown=indexer_service_user:indexer_service_user /usr/local/bin/r0vm /usr/local/bin/r0vm

# Copy logos blockchain circuits from builder
COPY --from=builder --chown=indexer_service_user:indexer_service_user /root/.logos-blockchain-circuits /home/indexer_service_user/.logos-blockchain-circuits

# Copy entrypoint script
COPY indexer/service/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Expose default port
EXPOSE 8779

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl http://localhost:8779 \
    -H "Content-Type: application/json" \
    -d "{ \
        \"jsonrpc\": \"2.0\", \
        \"method\": \"get_schema\", \
        \"params\": {}, \
        \"id\": 1 \
    }" || exit 1

# Run the application
ENV RUST_LOG=info

USER root

ENTRYPOINT ["/docker-entrypoint.sh"]

WORKDIR /indexer_service
CMD ["indexer_service", "/etc/indexer_service/indexer_config.json"]

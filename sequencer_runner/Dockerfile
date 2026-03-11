# Chef stage - uses pre-built cargo-chef image
FROM lukemathwalker/cargo-chef:latest-rust-1.94.0-slim-trixie AS chef

# Install dependencies
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
        git clone --depth 1 --branch r0.1.94.0 https://github.com/risc0/rust.git; \
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

WORKDIR /sequencer_runner

# Build argument to enable standalone feature (defaults to false)
ARG STANDALONE=false

# Planner stage - generates dependency recipe
FROM chef AS planner
COPY . .
RUN cargo chef prepare --bin sequencer_runner --recipe-path recipe.json

# Builder stage - builds dependencies and application
FROM chef AS builder
ARG STANDALONE
COPY --from=planner /sequencer_runner/recipe.json recipe.json
# Build dependencies only (this layer will be cached)
RUN if [ "$STANDALONE" = "true" ]; then \
      cargo chef cook --bin sequencer_runner --features standalone --release --recipe-path recipe.json; \
    else \
      cargo chef cook --bin sequencer_runner --release --recipe-path recipe.json; \
    fi

# Copy source code
COPY . .

# Build the actual application
RUN if [ "$STANDALONE" = "true" ]; then \
      cargo build --release --features standalone --bin sequencer_runner; \
    else \
      cargo build --release --bin sequencer_runner; \
    fi

# Strip debug symbols to reduce binary size
RUN strip /sequencer_runner/target/release/sequencer_runner

# Runtime stage - minimal image
FROM debian:trixie-slim

# Install runtime dependencies
RUN apt-get update \
 && apt-get install -y gosu jq \
 && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash sequencer_user && \
    mkdir -p /sequencer_runner /etc/sequencer_runner && \
    chown -R sequencer_user:sequencer_user /sequencer_runner /etc/sequencer_runner

# Copy binary from builder
COPY --from=builder --chown=sequencer_user:sequencer_user /sequencer_runner/target/release/sequencer_runner /usr/local/bin/sequencer_runner

# Copy r0vm binary from builder
COPY --from=builder --chown=sequencer_user:sequencer_user /usr/local/bin/r0vm /usr/local/bin/r0vm

# Copy logos blockchain circuits from builder
COPY --from=builder --chown=sequencer_user:sequencer_user /root/.logos-blockchain-circuits /home/sequencer_user/.logos-blockchain-circuits

# Copy entrypoint script
COPY sequencer_runner/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Expose default port
EXPOSE 3040

# Health check (TODO #244: Replace when a real health endpoint is available)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl http://localhost:3040 \
    -H "Content-Type: application/json" \
    -d "{ \
        \"jsonrpc\": \"2.0\", \
        \"method\": \"hello\", \
        \"params\": {}, \
        \"id\": 1 \
    }" || exit 1

# Run the application
ENV RUST_LOG=info

# Set explicit location for r0vm binary
ENV RISC0_SERVER_PATH=/usr/local/bin/r0vm

USER root

ENTRYPOINT ["/docker-entrypoint.sh"]

WORKDIR /sequencer_runner
CMD ["sequencer_runner", "/etc/sequencer_runner"]

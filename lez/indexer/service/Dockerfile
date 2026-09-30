# Chef stage
FROM risc0_base AS chef

WORKDIR /indexer_service

# Comma-separated extra cargo features. Defaults to `prove`, which selects the
# in-process guest executor with a memoized memory image instead of spawning an
# r0vm subprocess per execution.
ARG FEATURES="prove"

# Planner stage - generates dependency recipe
FROM chef AS planner
COPY . .
RUN cargo chef prepare --bin indexer_service --recipe-path recipe.json

# Builder stage - builds dependencies and application
FROM chef AS builder
ARG FEATURES
COPY --from=planner /indexer_service/recipe.json recipe.json
# Build dependencies only (this layer will be cached)
RUN --mount=type=cache,target=/usr/local/cargo/registry/index \
    --mount=type=cache,target=/usr/local/cargo/registry/cache \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/indexer_service/target \
    cargo chef cook --bin indexer_service ${FEATURES:+--features "$FEATURES"} \
      --release --recipe-path recipe.json

# Copy source code
COPY . .

# Build the actual application and copy the binary out of the cache mount
RUN --mount=type=cache,target=/usr/local/cargo/registry/index \
    --mount=type=cache,target=/usr/local/cargo/registry/cache \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/indexer_service/target \
    cargo build --release ${FEATURES:+--features "$FEATURES"} --bin indexer_service \
    && strip /indexer_service/target/release/indexer_service \
    && cp /indexer_service/target/release/indexer_service /usr/local/bin/indexer_service

# Runtime stage - minimal image
FROM debian:trixie-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash indexer_service_user && \
    mkdir -p /indexer_service /etc/indexer_service /var/lib/indexer_service && \
    chown -R indexer_service_user:indexer_service_user /indexer_service /etc/indexer_service /var/lib/indexer_service

# Copy binary from builder
COPY --from=builder --chown=indexer_service_user:indexer_service_user /usr/local/bin/indexer_service /usr/local/bin/indexer_service

# Copy r0vm binary from builder
COPY --from=builder --chown=indexer_service_user:indexer_service_user /usr/local/bin/r0vm /usr/local/bin/r0vm

VOLUME /var/lib/indexer_service

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

USER indexer_service_user

WORKDIR /indexer_service
CMD ["indexer_service", "/etc/indexer_service/indexer_config.json", "--data-dir", "/var/lib/indexer_service"]

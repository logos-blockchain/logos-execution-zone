# Chef stage
FROM risc0_base AS chef

WORKDIR /sequencer_service

# Build argument to enable standalone feature (defaults to false)
ARG STANDALONE=false

# Planner stage - generates dependency recipe
FROM chef AS planner
COPY . .
RUN cargo chef prepare --bin sequencer_service --recipe-path recipe.json

# Builder stage - builds dependencies and application
FROM chef AS builder
ARG STANDALONE
COPY --from=planner /sequencer_service/recipe.json recipe.json
# Build dependencies only (this layer will be cached)
RUN --mount=type=cache,target=/usr/local/cargo/registry/index \
    --mount=type=cache,target=/usr/local/cargo/registry/cache \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/sequencer_service/target \
    if [ "$STANDALONE" = "true" ]; then \
      cargo chef cook --bin sequencer_service --features standalone --release --recipe-path recipe.json; \
    else \
      cargo chef cook --bin sequencer_service --release --recipe-path recipe.json; \
    fi

# Copy source code
COPY . .

# Build the actual application and copy the binary out of the cache mount
RUN --mount=type=cache,target=/usr/local/cargo/registry/index \
    --mount=type=cache,target=/usr/local/cargo/registry/cache \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/sequencer_service/target \
    if [ "$STANDALONE" = "true" ]; then \
      cargo build --release --features standalone --bin sequencer_service; \
    else \
      cargo build --release --bin sequencer_service; \
    fi \
    && strip /sequencer_service/target/release/sequencer_service \
    && cp /sequencer_service/target/release/sequencer_service /usr/local/bin/sequencer_service

# Runtime stage - minimal image
FROM debian:trixie-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash sequencer_service_user && \
    mkdir -p /sequencer_service /etc/sequencer_service /var/lib/sequencer_service && \
    chown -R sequencer_service_user:sequencer_service_user /sequencer_service /etc/sequencer_service /var/lib/sequencer_service

# Copy binary from builder
COPY --from=builder --chown=sequencer_service_user:sequencer_service_user /usr/local/bin/sequencer_service /usr/local/bin/sequencer_service

# Copy r0vm binary from builder
COPY --from=builder --chown=sequencer_service_user:sequencer_service_user /usr/local/bin/r0vm /usr/local/bin/r0vm

VOLUME /var/lib/sequencer_service

# Expose default ports
EXPOSE 3040
EXPOSE 9000

# Health check (TODO #244: Replace when a real health endpoint is available)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl http://localhost:3040 \
    -H "Content-Type: application/json" \
    -d "{ \
        \"jsonrpc\": \"2.0\", \
        \"method\": \"checkHealth\", \
        \"params\": {}, \
        \"id\": 1 \
    }" || exit 1

# Run the application
ENV RUST_LOG=info

# Set explicit location for r0vm binary
ENV RISC0_SERVER_PATH=/usr/local/bin/r0vm

USER sequencer_service_user

WORKDIR /sequencer_service
CMD ["sequencer_service", "/etc/sequencer_service/sequencer_config.json"]

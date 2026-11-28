# syntax=docker/dockerfile:1
#
# The sequencer run through Logos Core: logosctl with the lez_core module from the
# blockchain-modules-release catalog, rather than the `sequencer_service` binary built from source.
# It takes the same SEQUENCER_* variables, ports, volume and health check as
# lez/sequencer/service/Dockerfile.

ARG LOGOSCTL_VERSION=0.3.2
ARG LEZ_CORE_VERSION=0.7.0

# Empty unless overridden: `--build-context lez_core_lgx=<dir>` installs the .lgx in <dir> (e.g. a
# release run's build artifact) instead of downloading LEZ_CORE_VERSION from the catalog.
FROM scratch AS lez_core_lgx

# ===========================
# BUILD IMAGE
# ===========================

FROM debian:trixie-slim AS builder

ARG LOGOSCTL_VERSION
ARG LEZ_CORE_VERSION
ARG LOGOS_CATALOG=https://raw.githubusercontent.com/logos-blockchain/blockchain-modules-release/refs/heads/main/logos-repo.json

ENV LOGOSCTL_CONFIG_DIR=/build/session

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o logosctl.tar.gz \
  "https://github.com/logos-co/logos-logoscore-cli/releases/download/${LOGOSCTL_VERSION}/logosctl-$(uname -m)-linux.tar.gz" \
  && tar -xzf logosctl.tar.gz && rm logosctl.tar.gz && mv logosctl-*.AppImage logosctl \
  # Patch the AppImage magic bytes, so QEMU (cross-arch builds) matches it as a plain ELF.
  && dd if=/dev/zero of=logosctl bs=1 count=3 seek=8 conv=notrunc \
  && chmod +x logosctl && ./logosctl --appimage-extract >/dev/null && mv squashfs-root logosctl-app

RUN --mount=type=bind,from=lez_core_lgx,target=/local-lgx \
  set -e; ctl=./logosctl-app/AppRun; $ctl daemon start --detach; \
  lgx=$(find /local-lgx -maxdepth 1 -name '*.lgx' | head -1); \
  if [ -z "$lgx" ]; then \
    $ctl catalog add "$LOGOS_CATALOG"; $ctl catalog refresh; \
    $ctl package download lez_core --version "$LEZ_CORE_VERSION" --output ./; \
    lgx="./lez_core-${LEZ_CORE_VERSION}.lgx"; \
  fi; \
  $ctl install "$lgx" -y; $ctl daemon stop

# ===========================
# SEQUENCER IMAGE
# ===========================

FROM debian:trixie-slim

LABEL source="https://github.com/logos-blockchain/logos-execution-zone" \
  description="LEZ sequencer, run by logosctl with the lez_core module"

# curl: the health check. jq: the entrypoint turns SEQUENCER_* into start options.
RUN apt-get update && apt-get install -y --no-install-recommends curl jq ca-certificates \
  && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 -s /bin/bash sequencer_service_user \
  && mkdir -p /var/lib/sequencer_service /opt/logos-session \
  && chown sequencer_service_user:sequencer_service_user /var/lib/sequencer_service /opt/logos-session

COPY --from=builder /build/logosctl-app /opt/logosctl
COPY --from=builder /build/session/modules /opt/modules
COPY lez/sequencer/service/logosctl/entrypoint.sh /usr/local/bin/lez-sequencer
RUN ln -s /opt/logosctl/AppRun /usr/local/bin/logosctl && chmod +x /usr/local/bin/lez-sequencer

USER sequencer_service_user

# The daemon's session; `modules_dirs` points it at the read-only modules installed above.
ENV LOGOSCTL_CONFIG_DIR=/opt/logos-session
RUN printf 'version: 2\nmodules_dirs:\n  - /opt/modules\n' > /tmp/daemon.yaml \
  && logosctl daemon config set /tmp/daemon.yaml && rm /tmp/daemon.yaml

VOLUME /var/lib/sequencer_service

EXPOSE 3040
EXPOSE 9000

# Defaults for `start`, as env so a deployment can override each one the same way.
ENV SEQUENCER_HOME=/var/lib/sequencer_service
ENV SEQUENCER_RPC_LISTEN_ADDRESS=0.0.0.0:3040
ENV SEQUENCER_METRICS_LISTEN_ADDRESS=0.0.0.0:9000
ENV RUST_LOG=info,risc0_zkvm=warn,kameo=warn
# One JSON object per log line, for log collectors. `LOG_FORMAT=text` for plain lines.
ENV LOG_FORMAT=json

# Follows the ops server when SEQUENCER_METRICS_LISTEN_ADDRESS is overridden.
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
  CMD curl -fsS -o /dev/null "http://$SEQUENCER_METRICS_LISTEN_ADDRESS/health" || exit 1

ENTRYPOINT ["lez-sequencer"]

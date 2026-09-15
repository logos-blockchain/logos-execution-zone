# The resolved node is built or downloaded outside this image. Keeping this
# runtime image small makes Docker-backed fixtures and CI direct TF deployments
# use the same Cargo-authoritative node revision. Local native TF uses its
# host-platform counterpart from bedrock/.resolved-host/.
# Source builds run in the LEZ CI image, which is based on Debian Trixie. Use
# the same distribution family for the runtime so newer glibc symbols used by a
# future Cargo-resolved node cannot outpace this image.
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3t64 \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY .resolved/logos-blockchain-node /usr/bin/logos-blockchain-node
RUN chmod 0755 /usr/bin/logos-blockchain-node

ENTRYPOINT ["/usr/bin/logos-blockchain-node"]

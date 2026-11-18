# The upstream Logos Storage node, pinned to a release and checked against that release's digests.
FROM debian:trixie-slim AS fetch

ARG TARGETARCH
ARG LOGOS_STORAGE_VERSION=v0.5.3
# SHA-256 of each release asset, from the release page; the build fails on a mismatch.
ARG LOGOS_STORAGE_SHA256_AMD64=1086fae4f283cab882f133abe4d5a88cfae8d61edba9f0094c7f75b368ec9d56
ARG LOGOS_STORAGE_SHA256_ARM64=ecbc32536565096b75b2330dab4ff47a993714a1f3ce345099396968bc69796b

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip \
  && rm -rf /var/lib/apt/lists/*

RUN case "$TARGETARCH" in \
    amd64) sha256="$LOGOS_STORAGE_SHA256_AMD64" ;; \
    arm64) sha256="$LOGOS_STORAGE_SHA256_ARM64" ;; \
    *) echo "No Logos Storage release for $TARGETARCH" >&2; exit 1 ;; \
  esac \
  && asset="logos-storage-linux-${TARGETARCH}-${LOGOS_STORAGE_VERSION}" \
  && curl -fsSL -o /tmp/logos-storage.zip \
    "https://github.com/logos-storage/logos-storage-nim/releases/download/${LOGOS_STORAGE_VERSION}/${asset}.zip" \
  && echo "${sha256}  /tmp/logos-storage.zip" | sha256sum -c - \
  && unzip -q /tmp/logos-storage.zip -d /tmp/logos-storage \
  && install -m 0755 "/tmp/logos-storage/${asset}" /usr/local/bin/logos-storage

FROM debian:trixie-slim

# The node links libstdc++; the entrypoint and the healthcheck use curl.
RUN apt-get update && apt-get install -y --no-install-recommends curl libstdc++6 \
  && rm -rf /var/lib/apt/lists/*

# A user and data directory of its own: the node never sees a sequencer's keys.
RUN useradd -m -u 1001 -s /usr/sbin/nologin logos_storage_user \
  && mkdir -p /var/lib/logos_storage \
  && chown logos_storage_user:logos_storage_user /var/lib/logos_storage \
  && chmod 0700 /var/lib/logos_storage

COPY --from=fetch /usr/local/bin/logos-storage /usr/local/bin/logos-storage
COPY --chmod=0755 lez/docker/logos-storage-entrypoint.sh /usr/local/bin/logos-storage-entrypoint

VOLUME /var/lib/logos_storage

# REST API and peer connections.
EXPOSE 8080
EXPOSE 8070

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
  CMD curl -fsS -o /dev/null http://127.0.0.1:8080/api/storage/v1/space || exit 1

USER logos_storage_user

ENTRYPOINT ["logos-storage-entrypoint"]

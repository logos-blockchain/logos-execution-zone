#!/bin/sh
# Starts a Logos Storage node on a private network: it announces its own address rather than
# probing for one, and bootstraps from `LOGOS_STORAGE_BOOTSTRAP_API`'s node, never a public preset.
# Without it, the node is the network's first. Extra arguments go to the node.
set -eu

ip=$(hostname -i | awk '{ print $1 }')
set -- \
  --data-dir=/var/lib/logos_storage \
  --api-bindaddr=0.0.0.0 \
  --api-port=8080 \
  --listen-port=8070 \
  --nat="extip:${ip}" \
  "$@"

if [ -n "${LOGOS_STORAGE_BOOTSTRAP_API:-}" ]; then
  spr=$(curl -fsS --retry 30 --retry-delay 2 --retry-all-errors \
    -H 'Accept: text/plain' "${LOGOS_STORAGE_BOOTSTRAP_API}/api/storage/v1/spr")
  set -- "$@" --bootstrap-node="${spr}"
else
  set -- "$@" --no-bootstrap-node
fi

exec logos-storage "$@"

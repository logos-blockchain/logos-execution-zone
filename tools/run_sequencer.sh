#!/usr/bin/env bash
# Runs one sequencer out of its home directory, which holds its RocksDB, both
# signing keys, its ports and its logs.
#
#     tools/run_sequencer.sh ~/lez-nodes/seq-OG
#     tools/run_sequencer.sh ~/lez-nodes/seq-4 <funding-account>
#
# A home the channel does not exist for yet creates it, and stakes nothing. A
# new home on an existing channel stakes itself in, alongside the node so it
# follows the channel while accreditation settles. An existing home just runs;
# set LEZ_STAKE=1 to stake one anyway, e.g. after leaving the committee.
#
# Extra arguments go to join_sequencer.py (--amount, --timeout, ...).
#
# A home holds its own sequencer config when `setup_sequencer.py` made it, and
# the Bedrock node comes from there. LEZ_CONFIG, LEZ_NODE and LEZ_SEQUENCER
# override; LEZ_FEATURES adds cargo features; RUST_LOG sets verbosity.
set -euo pipefail

[ $# -ge 1 ] || { echo "usage: $(basename "$0") <home> [funding-account] [args...]" >&2; exit 2; }
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p "$1"
home="$(realpath -m "$1")"
shift
funding="${1:-}"
shift || true
# What `setup_sequencer.py` left behind, when it ran.
[ -z "$funding" ] && [ -f "$home/stake-funding-account" ] && funding="$(cat "$home/stake-funding-account")"

# A home set up by setup_sequencer.py carries its own config; otherwise fall
# back to LEZ_CONFIG or the debug one.
if [ -f "$home/sequencer_config.json" ]; then
    config="$home/sequencer_config.json"
else
    config="${LEZ_CONFIG:-$repo/lez/sequencer/service/configs/debug/sequencer_config.json}"
fi
node="${LEZ_NODE:-$(python3 -c "import json;print(json.load(open('$config'))['bedrock_config']['node_url'])")}"
sequencer="${LEZ_SEQUENCER:-http://127.0.0.1:3040}"
name="$(basename "$home")"

say() { echo "$name: $*" | tee -a "$log"; }

# Whether anything is listening on $1. Reuses the address like a server does,
# so sockets left in TIME_WAIT by a stopped node do not read as busy.
port_busy() {
    python3 -c "
import socket, sys
with socket.socket() as probe:
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind(('0.0.0.0', int(sys.argv[1])))
    except OSError:
        raise SystemExit(0)
raise SystemExit(1)
" "$1"
}

# The first free port at or after $1.
free_port() {
    local port="$1"
    while port_busy "$port"; do port=$((port + 1)); done
    echo "$port"
}

channel="$(python3 -c "import json;print(json.load(open('$config'))['bedrock_config']['channel_id'])")"

# A key already in the committee needs no stake; an absent channel means this
# node creates it and stakes nothing.
accredited() {
    local keys
    keys="$(curl -s -m 5 "$node/channel/$channel")" || return 1
    case "$keys" in *'"accredited_keys"'*) ;; *) return 2 ;; esac
    case "$keys" in *"$1"*) return 0 ;; *) return 1 ;; esac
}

log="$home/sequencer.log"

# Ports live in the home so a node keeps them across restarts. A seq-<n> name
# gets the matching offset; any other new name takes the first free pair.
ports="$home/ports"
offset="${name#seq-}"
case "$name" in
    seq-OG) offset=0 ;;
    *) case "$offset" in ''|*[!0-9]*) offset="" ;; esac ;;
esac
if [ -f "$ports" ]; then
    # shellcheck disable=SC1090
    . "$ports"
    port="$PORT"
    metrics="$METRICS"
elif [ -n "$offset" ]; then
    port=$((3040 + offset))
    metrics=$((9000 + offset))
else
    port="$(free_port 3040)"
    metrics="$(free_port 9000)"
fi
printf 'PORT=%s\nMETRICS=%s\n' "$port" "$metrics" >"$ports"

if port_busy "$port"; then
    echo "$name: port $port is in use; is this node already running?" >&2
    exit 2
fi

printf '\n=== %s  %s  rpc :%s  metrics :%s ===\n' "$(date -Is)" "$name" "$port" "$metrics" >>"$log"
say "home $home, log $log, rpc :$port, metrics :$metrics"

cd "$repo"
key="$(cargo run --release -q -p sequencer_service --bin bedrock_pubkey -- \
    "$config" --home "$home" | tail -n 1)"
say "key $key"

# join_sequencer.py writes this once staked, naming the account that holds the
# stake. Its presence stops a later run from staking again: the key may have
# been slashed, and a second stake would burn too.
staked="$home/stake-ownership-account"
stake=false
if accredited "$key"; then
    say "already in the committee"
elif [ $? = 2 ]; then
    say "channel does not exist yet; this node creates it"
elif [ -f "$staked" ] && [ "${LEZ_STAKE:-}" != 1 ]; then
    say "staked before to $(cat "$staked") and is not in the committee, not staking."
    say "    LEZ_STAKE=1 just run-sequencer $home <funding-account>   to stake again"
else
    stake=true
fi

if [ "$stake" = true ]; then
    stake_log="$home/stake.log"
    printf '\n=== %s  %s staking ===\n' "$(date -Is)" "$name" >>"$stake_log"
    say "staking in the background, log $stake_log"
    [ -n "$funding" ] && set -- --funding-account "$funding" "$@"
    [ -d "$home/wallet" ] && set -- --wallet "$home/wallet" "$@"
    (
        if "$repo/tools/join_sequencer.py" --home "$home" --config "$config" \
            --node "$node" --sequencer "$sequencer" --no-run "$@" >>"$stake_log" 2>&1
        then
            say "accredited"
        else
            say "staking failed, see $stake_log" >&2
        fi
    ) &
fi

# LEZ_FEATURES=mdns discovers peers on the LAN, so a devnet gossips its
# mempool without bootstrap addresses.
features=()
[ -n "${LEZ_FEATURES:-}" ] && features=(--features "$LEZ_FEATURES")

RUST_LOG="${RUST_LOG:-info,kameo=warn}" cargo run --release -p sequencer_service "${features[@]}" -- \
    "$config" --home "$home" --port "$port" --metrics-address "0.0.0.0:$metrics" 2>&1 |
    tee -a "$log"

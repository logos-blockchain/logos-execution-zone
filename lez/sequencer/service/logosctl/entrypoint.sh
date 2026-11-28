#!/bin/sh
# Runs the sequencer through Logos Core: a logosctl daemon with the lez_core module, which starts
# the sequencer out of $SEQUENCER_HOME. It takes the SEQUENCER_* variables `sequencer_service start`
# reads (see `sequencer_service start --help`), passed to lez_core's `start_sequencer` as JSON.
# SIGTERM stops the sequencer, then the daemon.
set -eu

: "${SEQUENCER_HOME:=/var/lib/sequencer_service}"

ctl() { logosctl "$@"; }
# A module call's `result`; fails when the call itself does.
call() { ctl call lez_core "$@" | jq -er '.result'; }

# The SEQUENCER_* variables as `start_sequencer` options. Unset or empty ones keep their default.
overrides() {
    jq -nc '
        def opt($key; $var): ($ENV[$var] // "") as $v | if $v == "" then {} else {($key): $v} end;
        # As `sequencer_service start` reads them (clap `BoolishValueParser`).
        def flag($key; $var):
            ($ENV[$var] // "" | ascii_downcase) as $v
            | if $v == "" then {}
              elif (["y", "yes", "t", "true", "on", "1"] | index($v)) then {($key): true}
              elif (["n", "no", "f", "false", "off", "0"] | index($v)) then {($key): false}
              else error("\($var): expected a boolean, got \($ENV[$var])") end;
        opt("config"; "SEQUENCER_CONFIG")
        + flag("create_channel"; "SEQUENCER_CREATE_CHANNEL")
        + flag("wait_for_channel"; "SEQUENCER_WAIT_FOR_CHANNEL")
        + opt("channel_signing_key_file"; "SEQUENCER_CHANNEL_SIGNING_KEY_FILE")
        + opt("funding_public_key"; "SEQUENCER_FUNDING_PUBLIC_KEY")
        + opt("bedrock_node_url"; "SEQUENCER_BEDROCK_NODE_URL")
        + opt("channel_id"; "SEQUENCER_CHANNEL_ID")
        + opt("rpc_listen_address"; "SEQUENCER_RPC_LISTEN_ADDRESS")
        + opt("metrics_listen_address"; "SEQUENCER_METRICS_LISTEN_ADDRESS")
        + opt("gossip_listen_addr"; "SEQUENCER_GOSSIP_LISTEN_ADDR")
        + (($ENV.SEQUENCER_GOSSIP_BOOTSTRAP_PEER // "") | split(",") | map(gsub("^\\s+|\\s+$"; ""))
           | map(select(. != "")) | if length == 0 then {} else {gossip_bootstrap_peers: .} end)
    '
}

daemon=
shutdown() {
    trap - TERM INT
    echo "Stopping the sequencer"
    ctl call lez_core stop_sequencer >/dev/null 2>&1 || true
    ctl daemon stop >/dev/null 2>&1 || true
    [ -n "$daemon" ] && wait "$daemon" 2>/dev/null || true
    exit "${1:-0}"
}
trap 'shutdown 0' TERM INT

options=$(overrides)

ctl daemon start &
daemon=$!
until ctl daemon status >/dev/null 2>&1; do
    kill -0 "$daemon" 2>/dev/null || { echo "The logosctl daemon exited" >&2; exit 1; }
    sleep 1
done

ctl module load lez_core >/dev/null
# Its level is the default for RUST_LOG, which takes precedence.
call init_logger "${SEQUENCER_LOG_LEVEL:-info}" >/dev/null

echo "Starting the sequencer out of $SEQUENCER_HOME with $options"
code=$(call start_sequencer "$SEQUENCER_HOME" "$options")
if [ "$code" != 0 ]; then
    echo "start_sequencer failed with FfiOperationError $code" >&2
    shutdown 1
fi

# The start finishes in the background (it waits for the Bedrock node, and with
# SEQUENCER_WAIT_FOR_CHANNEL for the channel): exit if it fails, or if the daemon does, so the
# container is restarted. `sleep` runs in the background so a SIGTERM is handled at once.
while kill -0 "$daemon" 2>/dev/null; do
    sleep 10 &
    wait $! || true
    status=$(call getStatus 2>/dev/null || true)
    case "$status" in
        *StartFailed*)
            echo "The sequencer failed to start: $status" >&2
            shutdown 1
            ;;
    esac
done
echo "The logosctl daemon exited" >&2
exit 1

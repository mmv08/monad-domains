#!/usr/bin/env bash
# Runs script/PageGasBench.s.sol against a fresh `anvil --network monad` and prints
# `label,gasUsed` for every transaction it sent, from the node's receipts.
#
#   script/page-gas-bench.sh [project dir] [port]
#
# Anvil's Monad mode refuses locally signed transactions ("Insufficient funds"), so every
# transaction is sent unlocked from the first dev account.
set -euo pipefail

PROJECT=$(cd "${1:-$(dirname "$0")/..}" && pwd)
PORT=${2:-8548}
RPC=http://127.0.0.1:$PORT
SENDER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

anvil --network monad --port "$PORT" --silent &
ANVIL=$!
trap 'kill $ANVIL 2>/dev/null' EXIT
for _ in $(seq 50); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.1; done

cd "$PROJECT"
forge build --quiet

# Registration reads the parent block, which a fresh chain lacks.
cast rpc --rpc-url "$RPC" anvil_mine 0x10 >/dev/null

run() {
  forge script script/PageGasBench.s.sol:PageGasBench --rpc-url "$RPC" --unlocked --sender "$SENDER" \
    --broadcast --slow --sig "$@"
}

# Pairs the `TX,<label>` lines of a run with its broadcast transactions, in order.
report() {
  local log=$1 json=$2
  paste -d, <(grep -o 'TX,.*' "$log" | cut -d, -f2) \
    <(jq -r '.receipts as $r | .transactions[].hash as $h | $r[] | select(.transactionHash == $h) | .gasUsed' "$json" \
      | while read -r gas; do printf '%d\n' "$gas"; done)
}

LOG=$(mktemp)
run "deploy()" >"$LOG"
HUB=$(awk '/HUB/ {print $2}' "$LOG")
RECEIVER=$(awk '/RECEIVER/ {print $2}' "$LOG")
report "$LOG" broadcast/PageGasBench.s.sol/31337/deploy-latest.json

# Past the registering block, so the rounds' heights are final.
cast rpc --rpc-url "$RPC" anvil_mine 0x40 >/dev/null
run "measure(address,address)" "$HUB" "$RECEIVER" >"$LOG"
report "$LOG" broadcast/PageGasBench.s.sol/31337/measure-latest.json

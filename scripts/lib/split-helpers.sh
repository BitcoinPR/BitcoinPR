#!/usr/bin/env bash
#
# Shared helpers for the BIP-110 split-cluster scenario scripts
# (scripts/interop-split-scenario-*.sh). Sourced, not executed.
#
# Drives the same 2-node cluster as scripts/interop-split-test.sh
# (docker-compose.split.yml): split-bitcoinpr enforces BIP-110 from height
# 110, split-core does not. This lib factors out the cluster-up / baseline /
# forge-invalid-block boilerplate so each scenario script can focus on its
# own mining pattern and assertions.
#
# interop-split-test.sh is intentionally left untouched (it's the pinned
# regression test) — this lib duplicates its early-stage helpers rather than
# refactoring that script to depend on it.

# Caller scripts are expected to `set -euo pipefail` themselves; do it here
# too so a script that sources this without doing so still fails loudly.
set -euo pipefail

# Resolve repo root from this file's location (scripts/lib/ -> repo root),
# regardless of the caller's cwd.
SPLIT_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SPLIT_LIB_DIR/../.."

COMPOSE=(docker compose -p bitcoinpr-split -f docker-compose.split.yml)
PR_RPC="http://127.0.0.1:19443"
CORE_RPC="http://127.0.0.1:39443"
WEB="http://127.0.0.1:13000"
ADMIN_TOKEN="splittest"
BIP110_HEIGHT=110
# Fixed regtest address used whenever a scenario mines on split-bitcoinpr
# directly (mirrors the address interop-split-test.sh uses for the same
# purpose).
PR_MINE_ADDR="bcrt1qhgq7kd64luescw6d639vf3zj777m7600mwlc5f"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERR ]${NC} $*"; }
step() { echo -e "\n${CYAN}${BOLD}━━━ $* ━━━${NC}"; }

fail() {
    err "$*"
    err "Cluster left running for inspection:"
    err "  docker logs split-bitcoinpr | tail -50"
    err "  docker compose -p bitcoinpr-split -f docker-compose.split.yml down -v"
    exit 1
}

# ─── RPC helpers (jsonrpc 2.0 envelope — required by bitcoinpr) ───────────────

rpcurl() {  # url method [params] [timeout]
    local url="$1" method="$2" params="${3:-[]}" timeout="${4:-15}"
    curl -sk --max-time "$timeout" -u test:test -X POST "$url" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"id\":1}" \
        2>/dev/null
}
pr()   { rpcurl "$PR_RPC" "$@"; }
core() { rpcurl "$CORE_RPC" "$@"; }

result_of() { python3 -c "import sys,json;
try:
    d=json.load(sys.stdin); print(d.get('result','') if d.get('result') is not None else '')
except Exception: print('')" 2>/dev/null; }

jget() { python3 -c "import sys,json;
try:
    d=json.load(sys.stdin); r=d.get('result')
    print(eval('r'+sys.argv[1]) if r is not None else '')
except Exception: print('')" "$1" 2>/dev/null; }

wait_height() {  # url target timeout_s
    local url="$1" target="$2" timeout="${3:-60}"
    local waited=0 h
    while (( waited < timeout )); do
        h=$(rpcurl "$url" getblockcount | result_of)
        if [[ -n "$h" && "$h" -ge "$target" ]]; then return 0; fi
        sleep 2; waited=$((waited + 2))
    done
    return 1
}

wait_rpc() {  # url timeout_s
    local url="$1" timeout="${2:-90}"
    local waited=0
    while (( waited < timeout )); do
        if [[ -n "$(rpcurl "$url" getblockcount | result_of)" ]]; then return 0; fi
        sleep 2; waited=$((waited + 2))
    done
    return 1
}

# Poll pr getchainsplitinfo until rival/ours heights match, or timeout.
# Sets SPLIT_JSON, RIVAL_H, OURS_H, FORK_H, DEFICIT, ARMED on success.
wait_split_match() {  # expected_rival expected_ours timeout_s
    local exp_rival="$1" exp_ours="$2" timeout="${3:-90}"
    local waited=0
    while (( waited < timeout )); do
        SPLIT_JSON=$(pr getchainsplitinfo)
        RIVAL_H=$(echo "$SPLIT_JSON" | jget "['split']['rival']['height']")
        OURS_H=$(echo "$SPLIT_JSON" | jget "['split']['ours']['height']")
        if [[ "$RIVAL_H" == "$exp_rival" && "$OURS_H" == "$exp_ours" ]]; then
            FORK_H=$(echo "$SPLIT_JSON" | jget "['split']['fork_height']")
            DEFICIT=$(echo "$SPLIT_JSON" | jget "['split']['block_deficit']")
            ARMED=$(echo "$SPLIT_JSON" | jget "['split']['capitulation_armed']")
            return 0
        fi
        sleep 3; waited=$((waited + 3))
    done
    return 1
}

# ─── Cluster lifecycle ────────────────────────────────────────────────────

start_cluster() {
    "${COMPOSE[@]}" up -d
    wait_rpc "$PR_RPC" 120 || fail "split-bitcoinpr RPC did not come up"
    wait_rpc "$CORE_RPC" 120 || fail "split-core RPC did not come up"
    info "Both RPCs up"
}

# Idempotent wallet setup + mine past BIP-110 height so blocks with standard
# outputs already validate on both sides. Sets BASELINE, CORE_ADDR.
baseline_sync() {  # extra_margin (blocks past BIP110_HEIGHT)
    local margin="${1:-5}"
    core createwallet '["split"]' >/dev/null 2>&1 || core loadwallet '["split"]' >/dev/null 2>&1 || true
    CORE_ADDR=$(core getnewaddress | result_of)
    [[ -n "$CORE_ADDR" ]] || fail "could not get a Core wallet address"

    BASELINE=$((BIP110_HEIGHT + margin))
    local cur
    cur=$(core getblockcount | result_of)
    if (( cur < BASELINE )); then
        core generatetoaddress "[$((BASELINE - cur)),\"$CORE_ADDR\"]" 60 >/dev/null
    fi
    wait_height "$PR_RPC" "$BASELINE" 90 || fail "split-bitcoinpr did not reach baseline $BASELINE"
    local pr_tip core_tip
    pr_tip=$(pr getbestblockhash | result_of)
    core_tip=$(core getbestblockhash | result_of)
    [[ "$pr_tip" == "$core_tip" ]] || fail "tips disagree at baseline ($pr_tip vs $core_tip)"
    info "Baseline $BASELINE reached, tips agree"
}

# Forges a >83-byte OP_RETURN block on Core (RDTS rule 1 violation), one
# height past Core's CURRENT tip (not necessarily BASELINE — a second call
# after an `invalidateblock` rollback forges an independent rival branch
# from wherever Core's tip has been rolled back to).
# Args: payload_byte (default "aa" — pass a different byte, e.g. "bb", to
# forge a second branch with a distinguishable block hash).
# Sets FORGED_HASH, FORGED_HEIGHT. Asserts split-bitcoinpr holds at its
# current own height (`hold_height`, default BASELINE) while Core advances.
forge_invalid_block() {  # payload_byte hold_height
    local payload_byte="${1:-aa}" hold_height="${2:-$BASELINE}"
    local data raw funded signed pre_h
    data=$(python3 -c "import sys; print(sys.argv[1] * 100)" "$payload_byte")
    raw=$(core createrawtransaction "[[],{\"data\":\"$data\"}]" | result_of)
    [[ -n "$raw" ]] || fail "createrawtransaction failed"
    funded=$(core fundrawtransaction "[\"$raw\"]" | jget "['hex']")
    [[ -n "$funded" ]] || fail "fundrawtransaction failed"
    signed=$(core signrawtransactionwithwallet "[\"$funded\"]" | jget "['hex']")
    [[ -n "$signed" ]] || fail "signrawtransactionwithwallet failed"
    pre_h=$(core getblockcount | result_of)
    FORGED_HASH=$(core generateblock "[\"$CORE_ADDR\",[\"$signed\"]]" | jget "['hash']")
    [[ -n "$FORGED_HASH" ]] || fail "generateblock failed (needs Core >= v0.21)"
    FORGED_HEIGHT=$((pre_h + 1))
    info "Forged block $FORGED_HEIGHT: $FORGED_HASH"

    sleep 10
    local pr_h core_h
    pr_h=$(pr getblockcount | result_of)
    [[ "$pr_h" == "$hold_height" ]] || fail "split-bitcoinpr height $pr_h — expected to hold at $hold_height"
    core_h=$(core getblockcount | result_of)
    [[ "$core_h" == "$FORGED_HEIGHT" ]] || fail "Core height $core_h — expected $FORGED_HEIGHT"
    info "split-bitcoinpr held at $hold_height, Core at $FORGED_HEIGHT — split established"
}

# Waits for the monitor to surface the split and validates the initial
# picture (mode=fixed, deficit=1, not yet armed). Requires
# forge_invalid_block to have run first.
establish_split_view() {
    wait_split_match "$FORGED_HEIGHT" "$BASELINE" 90 || fail "monitor did not surface the split"
    local mode inv_h
    mode=$(echo "$SPLIT_JSON" | jget "['bip110']['mode']")
    [[ "$mode" == "fixed" ]] || fail "bip110 mode '$mode' — expected 'fixed'"
    [[ "$FORK_H" == "$BASELINE" ]] || fail "fork height '$FORK_H' — expected $BASELINE"
    [[ "$ARMED" == "False" ]] || fail "armed '$ARMED' — expected False at deficit 1"
    inv_h=$(echo "$SPLIT_JSON" | jget "['split']['rival_first_invalid']['height']")
    [[ "$inv_h" == "$FORGED_HEIGHT" ]] || fail "first invalid height '$inv_h' — expected $FORGED_HEIGHT"
    info "getchainsplitinfo: rival=$RIVAL_H fork=$FORK_H armed=$ARMED first_invalid=$inv_h"
}

# Full setup used by every scenario: cluster up, baseline, forge, confirm
# the monitor sees it. Leaves BASELINE/FORGED_HEIGHT/CORE_ADDR set for the
# scenario's own mining loop.
setup_split() {
    step "Start split cluster + baseline sync past BIP-110 height $BIP110_HEIGHT"
    start_cluster
    baseline_sync
    step "Forge a >83-byte OP_RETURN block on Core (RDTS rule 1 violation)"
    forge_invalid_block
    step "Confirm the split monitor tracks the rival branch"
    establish_split_view
}

# ─── Mining (no wait — caller decides when/whether to sync up) ────────────

pr_mine() {  # n
    pr generatetoaddress "[$1,\"$PR_MINE_ADDR\"]" 60 >/dev/null
}
core_mine() {  # n
    core generatetoaddress "[$1,\"$CORE_ADDR\"]" 60 >/dev/null
}

# ─── Capitulation (abandon minority chain) ─────────────────────────────────

# POST /api/split/capitulate, wait for the restart, and assert convergence
# onto Core's current tip from header re-announcement alone (no new
# majority block mined). Mirrors interop-split-test.sh steps 6-7.
capitulate_and_converge() {
    step "POST /api/split/capitulate — abandon minority chain"
    local cap_resp shutting
    cap_resp=$(curl -s --max-time 15 -X POST "$WEB/api/split/capitulate" \
        -H "Origin: $WEB" -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"confirm":"ABANDON-BIP110"}')
    shutting=$(echo "$cap_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('shutting_down',''))" 2>/dev/null || true)
    [[ "$shutting" == "True" ]] || fail "capitulate response: $cap_resp"
    info "Capitulation accepted — node shutting down (docker restarts it)"

    step "Node restarts with BIP-110 abandoned and converges on Core's chain"
    sleep 5
    wait_rpc "$PR_RPC" 180 || fail "split-bitcoinpr RPC did not come back after capitulation"
    local core_h pr_tip core_tip
    core_h=$(core getblockcount | result_of)
    wait_height "$PR_RPC" "$core_h" 120 || fail "did not converge to Core height $core_h from re-announcement alone"
    pr_tip=$(pr getbestblockhash | result_of)
    core_tip=$(core getbestblockhash | result_of)
    [[ "$pr_tip" == "$core_tip" ]] || fail "tips disagree after capitulation ($pr_tip vs $core_tip)"

    SPLIT_JSON=$(pr getchainsplitinfo)
    local abandoned mode
    abandoned=$(echo "$SPLIT_JSON" | jget "['abandoned']")
    mode=$(echo "$SPLIT_JSON" | jget "['bip110']['mode']")
    [[ "$abandoned" == "True" ]] || fail "abandoned '$abandoned' — expected True"
    [[ "$mode" == "abandoned" ]] || fail "mode '$mode' — expected 'abandoned'"
    info "Converged at $core_h ($pr_tip), mode=abandoned"
}

# ─── Crash simulation ───────────────────────────────────────────────────

# SIGKILL split-bitcoinpr and bring it back up. Gotcha (confirmed
# empirically): `docker kill` marks the container as intentionally stopped
# for restart-policy purposes — `restart: unless-stopped` will NOT
# auto-restart it the way it does for a graceful capitulate-triggered exit
# or an OOM kill, even though nothing about the kill itself is "graceful".
# An explicit `docker start` is required afterward.
kill_and_restart_pr() {
    docker kill split-bitcoinpr >/dev/null 2>&1 || true
    docker start split-bitcoinpr >/dev/null 2>&1 || true
}

# ─── Teardown ───────────────────────────────────────────────────────────

teardown_split() {  # keep(0/1)
    if [[ "${1:-0}" == "1" ]]; then
        info "cluster left running (--keep)"
    else
        "${COMPOSE[@]}" down -v >/dev/null 2>&1
        info "cluster torn down"
    fi
}

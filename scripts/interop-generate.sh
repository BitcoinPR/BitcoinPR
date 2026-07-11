#!/usr/bin/env bash
# scripts/interop-generate.sh — Generate blocks on bitcoinpr1 and verify sync.
#
# All six nodes must converge to the same tip height.  JSON-RPC nodes
# (bitcoinpr1/2, bitcoin-core, bitcoin-knots, btcd) are also cross-checked for tip
# hash agreement.  Libbitcoin is queried for height via bx running inside its
# container; tip hash is derived from the block header returned by bx.
#
# Usage:
#   ./scripts/interop-generate.sh [BLOCKS] [OPTIONS]
#
#   BLOCKS              Number of blocks to generate (default: 50)
#
#   --address ADDR      Coinbase recipient (default: well-known regtest address)
#   --no-verify         Skip post-generation sync check
#   --timeout SECS      Sync timeout per node (default: 120)
#   --continuous N      Generate N blocks every INTERVAL seconds (use with --interval)
#   --interval SECS     Interval for --continuous mode (default: 10)

set -euo pipefail

# ─── Defaults ─────────────────────────────────────────────────────────────────

BLOCKS="${1:-50}"
COINBASE_ADDR="bcrt1q7h3sfzkjk0eu54cpxcc8p7dfm8ek82xfl4mdx6"
SYNC_TIMEOUT=120
VERIFY=1
CONTINUOUS=0
CONT_BLOCKS=1
CONT_INTERVAL=10

# Shift past the positional blocks arg if numeric
if [[ "${1:-}" =~ ^[0-9]+$ ]]; then shift; fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --address)   COINBASE_ADDR="$2"; shift 2 ;;
        --no-verify) VERIFY=0; shift ;;
        --timeout)   SYNC_TIMEOUT="$2"; shift 2 ;;
        --continuous)CONTINUOUS=1; CONT_BLOCKS="$2"; shift 2 ;;
        --interval)  CONT_INTERVAL="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ─── RPC endpoints ────────────────────────────────────────────────────────────

declare -A RPC_URLS=(
    [bitcoinpr1]="http://test:test@127.0.0.1:18443"
    [bitcoinpr2]="http://test:test@127.0.0.1:28443"
    [bitcoin-core]="http://test:test@127.0.0.1:38443"
    [bitcoin-knots]="http://test:test@127.0.0.1:48443"
    [btcd]="https://test:test@127.0.0.1:58443"
)
MINER_NODE="bitcoinpr1"
POLL_INTERVAL=3

LB_CONTAINER="interop-libbitcoin"
# bx.cfg is the bitcoin-explorer *client* config (points at our local ZMQ
# endpoint and sets regtest network identifier).  bs.cfg is the server config
# and has options that bx does not recognise, causing "unrecognised option" errors.
LB_BX_CFG="/etc/libbitcoin/bx.cfg"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[GENERATE]${NC} $*" >&2; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
fail()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }
step()  { echo -e "${CYAN}${BOLD}==> $*${NC}" >&2; }

# ─── Helpers ──────────────────────────────────────────────────────────────────

rpc() {
    local node="$1" method="$2"
    local params="${3:-[]}"
    local timeout="${4:-10}"
    curl -sk --max-time "$timeout" -X POST "${RPC_URLS[$node]}" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"id\":1}" \
        2>/dev/null
}

result_of() {
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('result',''))" 2>/dev/null || echo ""
}

error_of() {
    python3 -c "
import sys, json
d = json.load(sys.stdin)
e = d.get('error')
print(e['message'] if e else '')
" 2>/dev/null || echo ""
}

height_of() {
    local node="$1"
    rpc "$node" "getblockcount" | result_of
}

tip_of() {
    local node="$1"
    rpc "$node" "getbestblockhash" | result_of
}

# ─── Libbitcoin / bx helpers ──────────────────────────────────────────────────

bx_exec() {
    docker exec "$LB_CONTAINER" bx "$@" -c "$LB_BX_CFG" 2>/dev/null || true
}

lb_height_of() {
    bx_exec fetch-height | tr -d '[:space:]'
}

# Derive the tip hash by fetching the block header at height $1 and parsing
# the "hash" field from bx's structured output.
# bx 3.8.0 command: fetch-header --height N  (not "fetch-block-header N")
lb_tip_of() {
    local h="${1:-$(lb_height_of)}"
    [[ ! "$h" =~ ^[0-9]+$ ]] && echo "" && return
    bx_exec fetch-header --height "$h" 2>/dev/null \
        | awk '/^\s+hash /{print $2; exit}' || echo ""
}

lb_wait_for_sync() {
    local target="$1"
    local start=$SECONDS
    while true; do
        local h
        h=$(lb_height_of)
        if [[ "$h" == "$target" ]]; then
            return 0
        fi
        if (( SECONDS - start > SYNC_TIMEOUT )); then
            warn "libbitcoin stuck at height ${h:-?} (target: ${target}) after ${SYNC_TIMEOUT}s"
            return 1
        fi
        sleep "$POLL_INTERVAL"
    done
}

# ─── Block generation ──────────────────────────────────────────────────────────

generate_blocks() {
    local count="$1"
    step "Generating ${count} block(s) on ${MINER_NODE} → ${COINBASE_ADDR}"

    local before_height
    before_height=$(height_of "$MINER_NODE")
    info "Current height: ${before_height}"

    local resp err
    resp=$(rpc "$MINER_NODE" "generatetoaddress" "[${count}, \"${COINBASE_ADDR}\"]" 180)
    err=$(echo "$resp" | error_of)
    if [[ -n "$err" ]]; then
        fail "generatetoaddress failed: ${err}\nFull response: ${resp}"
    fi

    local hashes_count
    hashes_count=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('result',[])))" 2>/dev/null || echo 0)
    local new_height
    new_height=$(height_of "$MINER_NODE")
    info "Generated ${hashes_count} blocks — new height: ${new_height}"
    echo "$new_height"
}

# ─── Sync verification ─────────────────────────────────────────────────────────

wait_for_sync() {
    local node="$1" target="$2"
    local start=$SECONDS

    while true; do
        local h
        h=$(height_of "$node")
        if [[ "$h" == "$target" ]]; then
            return 0
        fi
        if (( SECONDS - start > SYNC_TIMEOUT )); then
            warn "${node} stuck at height ${h} (target: ${target}) after ${SYNC_TIMEOUT}s"
            return 1
        fi
        sleep "$POLL_INTERVAL"
    done
}

verify_sync() {
    local target="$1"
    step "Verifying all nodes synced to height ${target}"

    local all_ok=1
    local -A heights tips

    for node in "${!RPC_URLS[@]}"; do
        local h t
        h=$(height_of "$node")
        t=$(tip_of "$node")
        heights[$node]="$h"
        tips[$node]="$t"
    done

    # Libbitcoin via bx
    heights[libbitcoin]=$(lb_height_of)
    tips[libbitcoin]=$(lb_tip_of "${heights[libbitcoin]}")

    # Print table
    printf "%-18s  %-8s  %-7s  %s\n" "NODE" "HEIGHT" "SYNC" "TIP HASH"
    printf "%-18s  %-8s  %-7s  %s\n" "----" "------" "----" "--------"
    for node in bitcoinpr1 bitcoinpr2 bitcoin-core bitcoin-knots btcd libbitcoin; do
        local h="${heights[$node]:-?}"
        local t="${tips[$node]:-}"
        local ok_mark t_display
        if [[ "$h" == "$target" ]]; then
            ok_mark="${GREEN}✓${NC}"
        else
            ok_mark="${RED}✗ (${h})${NC}"
            all_ok=0
        fi
        if [[ -n "$t" ]]; then
            t_display="${t:0:32}..."
        elif [[ "$node" == "libbitcoin" ]]; then
            t_display="(bx tip unavailable)"
        else
            t_display="(unavailable)"
        fi
        printf "%-18s  %-8s  " "$node" "$h"
        echo -e "${ok_mark}    ${t_display}"
    done

    # Cross-check tips: all nodes that returned a hash must agree with bitcoinpr1
    local ref_tip="${tips[bitcoinpr1]:-}"
    local tip_mismatch=0
    for node in bitcoinpr2 bitcoin-core bitcoin-knots btcd libbitcoin; do
        local t="${tips[$node]:-}"
        if [[ -n "$t" ]] && [[ "$t" != "$ref_tip" ]]; then
            warn "${node} tip mismatch! Expected: ${ref_tip:0:16}... Got: ${t:0:16}..."
            tip_mismatch=1
            all_ok=0
        fi
    done

    echo ""
    if [[ "$all_ok" == 1 ]]; then
        echo -e "${GREEN}${BOLD}All 6 nodes agree on tip at height ${target}.${NC}"
    else
        echo -e "${RED}${BOLD}Sync or tip mismatch detected!${NC}"
        if [[ "$tip_mismatch" == 1 ]]; then
            echo -e "${RED}TIP MISMATCH — possible consensus failure. Check logs immediately.${NC}"
            echo "  Run: ./scripts/interop-logs.sh --tail 100 --level error"
        fi
        return 1
    fi
}

wait_all_sync() {
    local target="$1"
    step "Waiting for all 6 nodes to reach height ${target} (timeout: ${SYNC_TIMEOUT}s)"
    local pids=() failed=0

    for node in "${!RPC_URLS[@]}"; do
        [[ "$node" == "$MINER_NODE" ]] && continue
        ( wait_for_sync "$node" "$target" && info "${node} synced to ${target}" || warn "${node} timed out" ) &
        pids+=($!)
    done

    # Libbitcoin via bx
    ( lb_wait_for_sync "$target" && info "libbitcoin synced to ${target}" || warn "libbitcoin timed out" ) &
    pids+=($!)

    for pid in "${pids[@]}"; do
        wait "$pid" || failed=1
    done

    return $failed
}

# ─── Main loop ────────────────────────────────────────────────────────────────

if [[ "$CONTINUOUS" == 1 ]]; then
    step "Continuous mode: ${CONT_BLOCKS} block(s) every ${CONT_INTERVAL}s (Ctrl-C to stop)"
    trap 'echo ""; info "Continuous generation stopped."; exit 0' INT TERM
    while true; do
        new_height=$(generate_blocks "$CONT_BLOCKS")
        sleep "$CONT_INTERVAL"
    done
else
    new_height=$(generate_blocks "$BLOCKS")
    if [[ "$VERIFY" == 1 ]]; then
        wait_all_sync "$new_height"
        verify_sync "$new_height"
    fi
fi

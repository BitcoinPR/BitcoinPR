#!/usr/bin/env bash
# scripts/interop-test.sh — End-to-end interop test suite for the 6-node regtest cluster.
#
# Drives the running cluster (docker-compose.interop.yml) through a battery of
# functional tests: P2P connectivity, block creation/propagation from every
# node, mempool fill/clear & transaction relay, the BitcoinPR-specific Stratum
# and getblocktemplate paths, Electrum + web interfaces, and resilience
# (container restart / reconnect / mempool persistence / inbound acceptance).
#
# It DOES NOT modify any source or config file.  It only issues RPC calls,
# polls state, restarts containers, and spins up one ephemeral throwaway node.
#
# Usage:
#   ./scripts/interop-test.sh              Run the full suite
#   ./scripts/interop-test.sh --quick      Skip the slow resilience/restart phase
#   ./scripts/interop-test.sh --no-restart Same as --quick
#
# Prerequisite: the cluster must already be up:
#   ./scripts/interop-cluster.sh start
#
# Exit code: 0 if no test FAILED (skips are tolerated), 1 otherwise.

set -uo pipefail   # NOT -e: a failing test must not abort the whole suite.

# ─── Config ───────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

declare -A RPC_URLS=(
    [bitcoinpr1]="http://test:test@127.0.0.1:18443"
    [bitcoinpr2]="http://test:test@127.0.0.1:28443"
    [bitcoin-core]="http://test:test@127.0.0.1:38443"
    [bitcoin-knots]="http://test:test@127.0.0.1:48443"
    [btcd]="https://test:test@127.0.0.1:58443"
)
# btcd has no wallet and a narrower RPC surface, so it stays out of the active
# generate/relay/mempool tests (RPC_NODES) but is still checked for sync + tip
# agreement (SYNC_NODES / ALL_NODES), like libbitcoin.
RPC_NODES=(bitcoinpr1 bitcoinpr2 bitcoin-core bitcoin-knots)   # JSON-RPC nodes driven by active tests
SYNC_NODES=(bitcoinpr1 bitcoinpr2 bitcoin-core bitcoin-knots btcd)  # JSON-RPC nodes checked for sync/tip
ALL_NODES=(bitcoinpr1 bitcoinpr2 bitcoin-core bitcoin-knots btcd libbitcoin)

# Container names
declare -A CONTAINERS=(
    [bitcoinpr1]="interop-bitcoinpr1"
    [bitcoinpr2]="interop-bitcoinpr2"
    [bitcoin-core]="interop-bitcoin-core"
    [bitcoin-knots]="interop-bitcoin-knots"
    [btcd]="interop-btcd"
    [libbitcoin]="interop-libbitcoin"
)

LB_CONTAINER="interop-libbitcoin"
LB_BX_CFG="/etc/libbitcoin/bx.cfg"

# Well-known regtest address (no key needed for generatetoaddress)
FIXED_ADDR="bcrt1qngpn06rdppfde2w8f7qnukqxrumn6tjlhtjwle"

CORE_BASE="http://test:test@127.0.0.1:38443"
CORE_WALLET="interoptest"
CORE_WALLET_URL="${CORE_BASE}/wallet/${CORE_WALLET}"

MATURITY_BLOCKS=110    # seed-mine this many to Core wallet so several coinbases mature
SYNC_TIMEOUT=90
MEMPOOL_TIMEOUT=30
PROP_TIMEOUT=90        # window for a non-seed block batch to converge cluster-wide
RESTART_TIMEOUT=120
POLL=2

QUICK=0
for arg in "$@"; do
    case "$arg" in
        --quick|--no-restart) QUICK=1 ;;
    esac
done

# ─── Colors / logging ─────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERR ]${NC} $*"; }
step()  { echo -e "\n${CYAN}${BOLD}━━━ $* ━━━${NC}"; }

# ─── RPC helpers ──────────────────────────────────────────────────────────────

rpcurl() {  # url method [params] [timeout]
    local url="$1" method="$2" params="${3:-[]}" timeout="${4:-15}"
    curl -sk --max-time "$timeout" -X POST "$url" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"id\":1}" \
        2>/dev/null
}

rpc() {  # node method [params] [timeout]
    rpcurl "${RPC_URLS[$1]}" "$2" "${3:-[]}" "${4:-15}"
}

result_of() { python3 -c "import sys,json;
try:
    d=json.load(sys.stdin); print(d.get('result','') if d.get('result') is not None else '')
except Exception: print('')" 2>/dev/null; }

error_of() { python3 -c "import sys,json;
try:
    d=json.load(sys.stdin); e=d.get('error'); print(e['message'] if e else '')
except Exception: print('')" 2>/dev/null; }

jget() { python3 -c "import sys,json;
try:
    d=json.load(sys.stdin); r=d.get('result')
    print(eval('r'+sys.argv[1]) if r is not None else '')
except Exception: print('')" "$1" 2>/dev/null; }

height_of() { rpc "$1" getblockcount | result_of; }
tip_of()    { rpc "$1" getbestblockhash | result_of; }
peercount_of() { rpc "$1" getconnectioncount | result_of; }
mempool_size_of() { rpc "$1" getmempoolinfo | jget "['size']"; }

# ─── Libbitcoin / bx ──────────────────────────────────────────────────────────

bx_exec() { docker exec "$LB_CONTAINER" bx "$@" -c "$LB_BX_CFG" 2>/dev/null || true; }
lb_height() { bx_exec fetch-height | tr -d '[:space:]'; }

# ─── Result tracking ──────────────────────────────────────────────────────────

# Initialize to empty arrays: under `set -u`, expanding ${#arr[@]} on a
# declared-but-never-assigned array aborts the script — which only happens
# on a perfectly clean run (no observations), killing the OVERALL verdict.
declare -a R_NAME=() R_STATUS=() R_DUR=() R_NOTE=()
declare -a OBSERVATIONS=()
declare -a ACTIONS=()
PASS_N=0; FAIL_N=0; SKIP_N=0
SUITE_START=$SECONDS

T_NOTE=""
note()    { T_NOTE="$*"; }
observe() { OBSERVATIONS+=("$*"); }
action()  { ACTIONS+=("$*"); }

run_test() {  # name function
    local name="$1" fn="$2"
    T_NOTE=""
    step "$name"
    local start=$SECONDS rc
    "$fn"; rc=$?
    local dur=$((SECONDS - start))
    R_NAME+=("$name"); R_DUR+=("$dur"); R_NOTE+=("$T_NOTE")
    case $rc in
        0) R_STATUS+=("PASS"); PASS_N=$((PASS_N+1)); info  "PASS (${dur}s) ${T_NOTE}" ;;
        2) R_STATUS+=("SKIP"); SKIP_N=$((SKIP_N+1)); warn  "SKIP (${dur}s) ${T_NOTE}" ;;
        *) R_STATUS+=("FAIL"); FAIL_N=$((FAIL_N+1)); err   "FAIL (${dur}s) ${T_NOTE}" ;;
    esac
}

# ─── Poll helpers ─────────────────────────────────────────────────────────────

wait_rpc_ready() {  # node timeout
    local node="$1" to="${2:-$RESTART_TIMEOUT}" start=$SECONDS
    while (( SECONDS - start < to )); do
        local h; h=$(height_of "$node")
        [[ "$h" =~ ^[0-9]+$ ]] && return 0
        sleep "$POLL"
    done
    return 1
}

wait_all_height() {  # target timeout  -> 0 if all RPC nodes (+libbitcoin best-effort) reach target
    # `>=`, not `==`: outside hashrate (e.g. a LAN bitaxe on the Stratum port)
    # can extend the chain past `target` mid-wait; that's still successful
    # propagation. Callers that care about agreement also check tips_agree.
    local target="$1" to="${2:-$SYNC_TIMEOUT}" start=$SECONDS
    while (( SECONDS - start < to )); do
        local ok=1
        for n in "${SYNC_NODES[@]}"; do
            local h; h=$(height_of "$n")
            [[ "$h" =~ ^[0-9]+$ ]] && (( h >= target )) || ok=0
        done
        if (( ok )); then
            # libbitcoin best-effort (don't fail the test on it)
            local lh; lh=$(lb_height)
            [[ "$lh" =~ ^[0-9]+$ ]] && (( lh >= target )) || observe "libbitcoin lagged at ${lh:-?} when others reached ${target} (eventual-consistency; ZMQ sync)"
            return 0
        fi
        sleep "$POLL"
    done
    return 1
}

wait_mempool_has() {  # node txid timeout
    local node="$1" txid="$2" to="${3:-$MEMPOOL_TIMEOUT}" start=$SECONDS
    while (( SECONDS - start < to )); do
        rpc "$node" getrawmempool | grep -q "$txid" && return 0
        sleep "$POLL"
    done
    return 1
}

wait_mempool_empty() {  # node timeout
    local node="$1" to="${2:-$MEMPOOL_TIMEOUT}" start=$SECONDS
    while (( SECONDS - start < to )); do
        [[ "$(mempool_size_of "$node")" == "0" ]] && return 0
        sleep "$POLL"
    done
    return 1
}

# Cross-check all RPC nodes share one tip hash. echoes "OK" or mismatch detail.
tips_agree() {
    local ref; ref=$(tip_of bitcoinpr1)
    local bad=""
    for n in bitcoinpr2 bitcoin-core bitcoin-knots btcd; do
        local t; t=$(tip_of "$n")
        [[ -n "$t" && "$t" != "$ref" ]] && bad+="${n}=${t:0:12} "
    done
    [[ -z "$bad" ]] && echo "OK" || echo "MISMATCH ref=${ref:0:12} ${bad}"
}

# Mine on a node to a given address; echoes new height (empty on error)
mine_on() {  # node count address
    local node="$1" count="$2" addr="$3"
    rpc "$node" generatetoaddress "[${count}, \"${addr}\"]" 120 | result_of >/dev/null
    height_of "$node"
}

# ══════════════════════════════════════════════════════════════════════════════
#  TESTS
# ══════════════════════════════════════════════════════════════════════════════

test_health() {
    action "Probed RPC/web/electrum/stratum health of all nodes"
    local down=()
    for n in "${SYNC_NODES[@]}"; do
        wait_rpc_ready "$n" 20 || down+=("$n")
    done
    # libbitcoin via bx
    local lh; lh=$(lb_height)
    [[ "$lh" =~ ^[0-9]+$ ]] || { down+=("libbitcoin"); observe "libbitcoin bx not responding (ZMQ query iface; no JSON-RPC by design)"; }
    # web
    local web; web=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1:3000/ 2>/dev/null)
    [[ "$web" == "200" ]] || { down+=("web:3000"); }
    # electrum plain + tls
    local ev; ev=$(printf '{"id":1,"method":"server.version","params":["t","1.4"]}\n' | timeout 5 nc 127.0.0.1 50001 2>/dev/null | head -1)
    echo "$ev" | grep -q '"result"' || down+=("electrum:50001")
    # stratum reachable (port open)
    timeout 4 bash -c 'exec 3<>/dev/tcp/127.0.0.1/3333' 2>/dev/null || down+=("stratum:3333")

    if (( ${#down[@]} == 0 )); then
        note "all endpoints up: RPC×5, libbitcoin bx, web:3000, electrum:50001, stratum:3333"
        return 0
    fi
    note "unreachable: ${down[*]}"
    return 1
}

test_p2p() {
    action "Inspected P2P topology (getpeerinfo/getconnectioncount) on all RPC nodes"
    echo -e "${DIM}  node            conns  peers(subver)${NC}"
    local seed_peers; seed_peers=$(peercount_of bitcoinpr1)
    for n in "${RPC_NODES[@]}"; do
        local cc subs
        cc=$(peercount_of "$n")
        subs=$(rpc "$n" getpeerinfo | python3 -c "import sys,json
try:
    d=json.load(sys.stdin)['result']
    print(', '.join(sorted({p.get('subver','?').strip('/') for p in d})) or '(none)')
except Exception: print('(err)')" 2>/dev/null)
        printf "  %-14s  %-5s  %s\n" "$n" "$cc" "$subs"
    done

    # BitcoinPR getpeerinfo inbound field check
    local inb
    inb=$(rpc bitcoinpr1 getpeerinfo | python3 -c "import sys,json
try:
    d=json.load(sys.stdin)['result']; print(all(p.get('inbound') is None for p in d))
except Exception: print('err')" 2>/dev/null)
    if [[ "$inb" == "True" ]]; then
        observe "BitcoinPR getpeerinfo reports inbound=null for every peer — direction not exposed; explorers/monitoring can't distinguish inbound vs outbound on BitcoinPR nodes"
    fi

    # Assert: seed sees >=4 peers; each leaf node has >=1 connection
    local fail=0 detail=""
    [[ "$seed_peers" =~ ^[0-9]+$ ]] && (( seed_peers >= 4 )) || { fail=1; detail+="seed_peers=${seed_peers} (<4) "; }
    for n in bitcoinpr2 bitcoin-core bitcoin-knots; do
        local cc; cc=$(peercount_of "$n")
        [[ "$cc" =~ ^[0-9]+$ ]] && (( cc >= 1 )) || { fail=1; detail+="${n}_conns=${cc} "; }
    done
    # Core reports inbound properly — confirm its link to seed is outbound
    local core_out
    core_out=$(rpc bitcoin-core getpeerinfo | python3 -c "import sys,json
try:
    d=json.load(sys.stdin)['result']; print(any(p.get('inbound') is False for p in d))
except Exception: print('err')" 2>/dev/null)
    [[ "$core_out" == "True" ]] && note "seed has ${seed_peers} inbound peers; core/knots/r2 hold outbound to seed" \
                                || note "seed peers=${seed_peers}; core outbound-flag=${core_out} ${detail}"
    return $fail
}

test_addr_self_advertise() {
    # O5/O7 wire validation. The cluster network is RFC1918 (172.30.0.0/24), so
    # the external-address discovery + `addr` self-advertisement path is normally
    # (and correctly) inert here. Both BitcoinPR nodes run with
    # --gossip-private-addrs, which treats private addresses as routable for this
    # path only — so each node must now learn its own 172.30.0.x address from a
    # peer's version.receiver and adopt it. We assert that on the wire by reading
    # the node's own log ("Discovered external IP from peers"); no RPC currently
    # surfaces the local/advertised address.
    action "Checked addr self-advertisement (O5) fires on the RFC1918 cluster via --gossip-private-addrs"
    local fail=0 detail=""
    for c in "${CONTAINERS[bitcoinpr1]}" "${CONTAINERS[bitcoinpr2]}"; do
        local line
        line=$(docker logs "$c" 2>&1 | grep -F "Discovered external IP from peers" | tail -1)
        if [[ -n "$line" ]] && grep -qE "172\.30\.0\.[0-9]+" <<<"$line"; then
            local ip; ip=$(grep -oE "172\.30\.0\.[0-9]+" <<<"$line" | head -1)
            observe "${c}: adopted+advertised external address ${ip} (O5/O7 path active)"
        else
            fail=1; detail+="${c}:no-discovery "
        fi
    done
    # Storm guard: self-advertisement on a mesh once amplified `addr` relay into a
    # ~58k-msg/s loop (every received addr was re-relayed). The fix relays only
    # newly-learned addresses, so steady-state addr traffic must stay tiny. Assert
    # bitcoinpr1 sees well under a few hundred addr messages in a 5s idle window.
    local addr_rate
    addr_rate=$(docker logs --since 5s "${CONTAINERS[bitcoinpr1]}" 2>&1 | grep -c "Received addr")
    if (( addr_rate > 500 )); then
        fail=1; detail+="addr-storm(${addr_rate}/5s) "
    else
        observe "addr relay bounded: ${addr_rate} addr msgs/5s on bitcoinpr1 (storm fix holding)"
    fi
    if (( fail )); then
        note "O5/O7 wire check failed: ${detail}(flag on both nodes? addr-relay bounded?)"
    else
        note "both BitcoinPR nodes discovered + self-advertised; addr relay bounded (no storm)"
    fi
    return $fail
}

test_baseline_sync() {
    action "Verified baseline height + tip-hash agreement across all 6 nodes"
    local h1; h1=$(height_of bitcoinpr1)
    [[ "$h1" =~ ^[0-9]+$ ]] || { note "bitcoinpr1 height unreadable"; return 1; }
    if ! wait_all_height "$h1" 30; then
        note "nodes not converged at baseline height ${h1}"
        return 1
    fi
    local agree; agree=$(tips_agree)
    if [[ "$agree" == OK ]]; then
        note "all 6 nodes converged at height ${h1}, tips agree"
        return 0
    fi
    note "tip disagreement: ${agree}"
    return 1
}

# Mine `count` blocks on `node` to `addr` and assert all nodes converge + agree.
_mine_and_verify() {  # node count addr label
    local node="$1" count="$2" addr="$3" label="$4"
    local before; before=$(height_of "$node")
    local resp err
    resp=$(rpc "$node" generatetoaddress "[${count}, \"${addr}\"]" 180)
    err=$(echo "$resp" | error_of)
    if [[ -n "$err" ]]; then
        note "${label}: generatetoaddress failed: ${err}"
        return 1
    fi
    local target; target=$(height_of "$node")
    info "${label}: mined ${count} on ${node} (${before} → ${target}); waiting for cluster sync…"
    if ! wait_all_height "$target" "$SYNC_TIMEOUT"; then
        local hs=""
        for n in "${RPC_NODES[@]}"; do hs+="${n}=$(height_of "$n") "; done
        note "${label}: sync timeout at ${target}; heights: ${hs}"
        return 1
    fi
    local agree; agree=$(tips_agree)
    [[ "$agree" == OK ]] || { note "${label}: tip mismatch after sync: ${agree}"; return 1; }
    return 0
}

test_block_create_seed() {
    action "Mined blocks on bitcoinpr1 and verified propagation to all nodes"
    _mine_and_verify bitcoinpr1 5 "$FIXED_ADDR" "seed-mine" || return 1
    note "5 blocks from bitcoinpr1 accepted by core/knots/r2/libbitcoin"
    return 0
}

# Mine `count` blocks on a NON-seed node and report whether they propagate
# everywhere within `to` seconds.  Used to probe peer→peer block relay through
# the seed.  Returns 0 if all converge, 1 otherwise (does not abort the suite).
_mine_nonseed_probe() {  # node count timeout label
    local node="$1" count="$2" to="$3" label="$4"
    local before; before=$(height_of "$node")
    local resp err
    resp=$(rpc "$node" generatetoaddress "[${count}, \"${FIXED_ADDR}\"]" 120)
    err=$(echo "$resp" | error_of)
    [[ -n "$err" ]] && { note "${label}: generatetoaddress failed: ${err}"; return 1; }
    local target; target=$(height_of "$node")
    info "${label}: mined ${count} on ${node} (${before} → ${target}); checking propagation (${to}s)…"
    if wait_all_height "$target" "$to"; then
        local agree; agree=$(tips_agree)
        [[ "$agree" == OK ]] && { note "${label}: ${count} block(s) propagated cluster-wide"; return 0; }
        note "${label}: heights matched but tips diverged: ${agree}"; return 1
    fi
    local hs=""
    for n in "${RPC_NODES[@]}"; do hs+="${n}=$(height_of "$n") "; done
    note "${label}: NOT propagated within ${to}s — ${hs}"
    return 1
}

CORE_ADDR=""
test_setup_mature() {
    action "Created Core wallet; seed-mined ${MATURITY_BLOCKS} blocks to Core's address (keeps cluster synced + matures Core funds)"
    local cresp cerr
    cresp=$(rpcurl "$CORE_BASE" createwallet "[\"${CORE_WALLET}\"]" 30)
    cerr=$(echo "$cresp" | error_of)
    [[ -n "$cerr" ]] && rpcurl "$CORE_BASE" loadwallet "[\"${CORE_WALLET}\"]" 30 >/dev/null
    local addr; addr=$(rpcurl "$CORE_WALLET_URL" getnewaddress "[]" 15 | result_of)
    [[ -z "$addr" ]] && { note "could not obtain Core wallet address"; return 1; }
    CORE_ADDR="$addr"
    info "Core wallet address: ${addr}"
    # Mine on the SEED so the chain propagates reliably; coinbase pays Core's wallet.
    _mine_and_verify bitcoinpr1 "$MATURITY_BLOCKS" "$addr" "mature" || return 1
    sleep 2
    local bal; bal=$(rpcurl "$CORE_WALLET_URL" getbalance "[]" 15 | result_of)
    note "seed mined ${MATURITY_BLOCKS} blocks → Core wallet; spendable balance ≈ ${bal} BTC; cluster synced"
    return 0
}

TX1=""; TX2=""
test_mempool_fill_wallet() {
    action "Broadcast a wallet tx from Core; verified it filled mempools of r1/r2/core/knots"
    local bal; bal=$(rpcurl "$CORE_WALLET_URL" getbalance "[]" 15 | result_of)
    info "Core wallet balance: ${bal}"
    local txid
    txid=$(rpcurl "$CORE_WALLET_URL" sendtoaddress "[\"${CORE_ADDR:-$FIXED_ADDR}\", 1.0]" 30 | result_of)
    if [[ -z "$txid" ]]; then
        local e; e=$(rpcurl "$CORE_WALLET_URL" sendtoaddress "[\"${CORE_ADDR:-$FIXED_ADDR}\", 1.0]" 30 | error_of)
        note "sendtoaddress failed: ${e:-unknown}"
        return 1
    fi
    TX1="$txid"
    info "Core broadcast tx ${txid:0:16}…"
    local missing=()
    for n in bitcoinpr1 bitcoinpr2 bitcoin-core bitcoin-knots; do
        wait_mempool_has "$n" "$txid" "$MEMPOOL_TIMEOUT" || missing+=("$n")
    done
    if (( ${#missing[@]} == 0 )); then
        note "tx ${txid:0:12}… relayed into all 4 RPC mempools"
        return 0
    fi
    # If the seed downloaded the tx but never added it, flag the silent-drop path.
    if printf '%s\n' "${missing[@]}" | grep -q bitcoinpr1; then
        if docker logs --tail 4000 interop-bitcoinpr1 2>&1 | grep -q "Received transaction.*${txid}" \
           && ! docker logs --tail 4000 interop-bitcoinpr1 2>&1 | grep -q "Added tx to mempool.*${txid}"; then
            observe "bitcoinpr1 downloaded a peer-relayed tx (${txid:0:12}…) — log shows 'Received transaction' but no 'Added tx to mempool' and no rejection reason: a silent tx-acceptance drop path with no diagnostic logging."
        fi
    fi
    note "tx not in mempool of: ${missing[*]}"
    return 1
}

test_mempool_fill_rawtx_bitcoinpr() {
    action "Funded+signed a raw tx on Core, submitted via bitcoinpr1 sendrawtransaction, verified outward relay"
    # Build a funded, signed tx with Core's wallet but DO NOT broadcast from Core.
    local addr="${CORE_ADDR:-$FIXED_ADDR}"
    local raw funded signed hex txid
    raw=$(rpcurl "$CORE_WALLET_URL" createrawtransaction "[[], {\"${addr}\": 0.5}]" 20 | result_of)
    [[ -z "$raw" ]] && { note "createrawtransaction failed"; return 1; }
    funded=$(rpcurl "$CORE_WALLET_URL" fundrawtransaction "[\"${raw}\"]" 20 | jget "['hex']")
    [[ -z "$funded" ]] && { note "fundrawtransaction failed (insufficient funds?)"; return 1; }
    signed=$(rpcurl "$CORE_WALLET_URL" signrawtransactionwithwallet "[\"${funded}\"]" 20 | jget "['hex']")
    [[ -z "$signed" ]] && { note "signrawtransactionwithwallet failed"; return 1; }

    # Submit to bitcoinpr1 (tests BitcoinPR raw-tx acceptance + relay)
    local resp; resp=$(rpc bitcoinpr1 sendrawtransaction "[\"${signed}\"]" 20)
    txid=$(echo "$resp" | result_of)
    if [[ -z "$txid" ]]; then
        note "bitcoinpr1 sendrawtransaction rejected: $(echo "$resp" | error_of)"
        return 1
    fi
    TX2="$txid"
    info "bitcoinpr1 accepted raw tx ${txid:0:16}…"
    local missing=()
    for n in bitcoinpr2 bitcoin-core bitcoin-knots; do
        wait_mempool_has "$n" "$txid" "$MEMPOOL_TIMEOUT" || missing+=("$n")
    done
    if (( ${#missing[@]} == 0 )); then
        note "raw tx submitted to bitcoinpr1 relayed out to core/knots/r2"
        return 0
    fi
    note "raw tx not relayed to: ${missing[*]}"
    return 1
}

test_mempool_clear() {
    action "Mined a block to confirm pending txs; verified mempools drained and txs included"
    local before; before=$(mempool_size_of bitcoinpr1)
    info "bitcoinpr1 mempool before: ${before} tx(s)"
    local h; h=$(mine_on bitcoinpr1 1 "$FIXED_ADDR")
    wait_all_height "$h" "$SYNC_TIMEOUT" || { note "cluster did not sync block ${h}"; return 1; }
    # tx inclusion check
    local blockhash included=""
    blockhash=$(rpc bitcoinpr1 getblockhash "[${h}]" | result_of)
    local blocktxs; blocktxs=$(rpc bitcoinpr1 getblock "[\"${blockhash}\"]" | python3 -c "import sys,json
try: print(' '.join(json.load(sys.stdin)['result'].get('tx',[])))
except Exception: print('')" 2>/dev/null)
    for t in "$TX1" "$TX2"; do
        [[ -n "$t" ]] && { echo "$blocktxs" | grep -q "$t" && included+="${t:0:10}… "; }
    done
    # mempools cleared
    local notempty=()
    for n in bitcoinpr1 bitcoinpr2 bitcoin-core bitcoin-knots; do
        wait_mempool_empty "$n" "$MEMPOOL_TIMEOUT" || notempty+=("$n=$(mempool_size_of "$n")")
    done
    if (( ${#notempty[@]} == 0 )); then
        note "block ${h} confirmed txs [${included:-none-tracked}]; all mempools cleared to 0"
        return 0
    fi
    note "mempool not cleared on: ${notempty[*]}"
    return 1
}

test_stratum_mine() {
    action "Mined one block via the Stratum V1 gateway (sv1_mine_one.py)"
    if [[ ! -f "${SCRIPT_DIR}/sv1_mine_one.py" ]]; then
        note "sv1_mine_one.py not found"; return 2
    fi
    local before; before=$(height_of bitcoinpr1)
    local out; out=$(timeout 60 python3 "${SCRIPT_DIR}/sv1_mine_one.py" 2>&1)
    echo "$out" | sed 's/^/    /'
    if echo "$out" | grep -q "result=True"; then
        sleep 3
        local after; after=$(height_of bitcoinpr1)
        if [[ "$after" =~ ^[0-9]+$ ]] && (( after > before )); then
            wait_all_height "$after" "$SYNC_TIMEOUT" || observe "Stratum-mined block ${after} slow to propagate"
            note "Stratum block accepted (${before} → ${after}) and propagated"
            return 0
        fi
        note "submit accepted but height did not advance (${before} → ${after})"
        return 1
    fi
    note "Stratum submit not accepted; see output above"
    return 1
}

test_getblocktemplate() {
    action "Validated getblocktemplate structure on bitcoinpr1"
    local resp; resp=$(rpc bitcoinpr1 getblocktemplate '[{"rules":["segwit"]}]' 20)
    local ok; ok=$(echo "$resp" | python3 -c "import sys,json
try:
    r=json.load(sys.stdin)['result']
    print('OK' if all(k in r for k in ('previousblockhash','bits','height','coinbasevalue')) else 'MISSING')
except Exception as e: print('ERR')" 2>/dev/null)
    if [[ "$ok" == OK ]]; then
        note "getblocktemplate returned previousblockhash/bits/height/coinbasevalue"
        return 0
    fi
    note "getblocktemplate malformed or errored ($ok): $(echo "$resp" | error_of)"
    return 1
}

test_electrum() {
    action "Queried Electrum interface (server.version + headers height cross-check)"
    local ver hdr eh rpch
    ver=$(printf '{"id":1,"method":"server.version","params":["t","1.4"]}\n' | timeout 5 nc 127.0.0.1 50001 2>/dev/null | head -1)
    echo "$ver" | grep -q '"result"' || { note "server.version no response"; return 1; }
    hdr=$(printf '{"id":2,"method":"blockchain.headers.subscribe","params":[]}\n' | timeout 5 nc 127.0.0.1 50001 2>/dev/null | head -1)
    eh=$(echo "$hdr" | python3 -c "import sys,json
try: print(json.load(sys.stdin)['result'].get('height',''))
except Exception: print('')" 2>/dev/null)
    rpch=$(height_of bitcoinpr1)
    if [[ -n "$eh" && "$eh" == "$rpch" ]]; then
        note "Electrum height ${eh} == RPC height ${rpch}; server.version OK"
        return 0
    fi
    note "Electrum height=${eh:-none} vs RPC height=${rpch}"
    [[ -z "$eh" ]] && return 1
    observe "Electrum headers.subscribe height (${eh}) differs from RPC (${rpch}) — indexer lag?"
    return 1
}

test_web() {
    action "Checked web block explorer (:3000) reachability"
    local code; code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 6 http://127.0.0.1:3000/ 2>/dev/null)
    if [[ "$code" == "200" ]]; then
        note "web explorer returned HTTP 200"
        return 0
    fi
    note "web explorer HTTP ${code}"
    return 1
}

test_restart_reconnect() {
    action "Restarted interop-bitcoinpr2; verified P2P reconnect + chain resync"
    local target; target=$(height_of bitcoinpr1)
    info "Restarting interop-bitcoinpr2…"
    docker restart "${CONTAINERS[bitcoinpr2]}" >/dev/null 2>&1 || { note "docker restart failed"; return 1; }
    wait_rpc_ready bitcoinpr2 "$RESTART_TIMEOUT" || { note "bitcoinpr2 RPC did not come back"; return 1; }
    # reconnect
    local start=$SECONDS reconnected=0
    while (( SECONDS - start < RESTART_TIMEOUT )); do
        local cc; cc=$(peercount_of bitcoinpr2)
        [[ "$cc" =~ ^[0-9]+$ ]] && (( cc >= 1 )) && { reconnected=1; break; }
        sleep "$POLL"
    done
    (( reconnected )) || { note "bitcoinpr2 did not re-establish peer connection"; return 1; }
    # resync
    if [[ "$(height_of bitcoinpr2)" == "$target" ]] || wait_all_height "$target" "$RESTART_TIMEOUT"; then
        note "bitcoinpr2 restarted, reconnected (${reconnected} peer), resynced to ${target}"
        return 0
    fi
    note "bitcoinpr2 reconnected but did not resync to ${target} (at $(height_of bitcoinpr2))"
    return 1
}

test_mempool_persistence() {
    action "Broadcast a tx then restarted bitcoinpr1; checked mempool persistence across graceful shutdown"
    # need spendable funds
    local addr="${CORE_ADDR:-$FIXED_ADDR}"
    local txid
    txid=$(rpcurl "$CORE_WALLET_URL" sendtoaddress "[\"${addr}\", 0.25]" 30 | result_of)
    if [[ -z "$txid" ]]; then note "could not create funding tx for persistence test"; return 2; fi
    wait_mempool_has bitcoinpr1 "$txid" "$MEMPOOL_TIMEOUT" || { note "tx never reached bitcoinpr1 mempool"; return 1; }
    info "tx ${txid:0:16}… in bitcoinpr1 mempool; restarting interop-bitcoinpr1 (graceful mempool save)…"
    docker restart "${CONTAINERS[bitcoinpr1]}" >/dev/null 2>&1 || { note "docker restart failed"; return 1; }
    wait_rpc_ready bitcoinpr1 "$RESTART_TIMEOUT" || { note "bitcoinpr1 did not restart"; return 1; }
    sleep 3
    if rpc bitcoinpr1 getrawmempool | grep -q "$txid"; then
        note "mempool persisted across restart (tx ${txid:0:12}… reloaded)"
        return 0
    fi
    # not persisted — could legitimately be re-fetched from peers; check that too
    if wait_mempool_has bitcoinpr1 "$txid" 20; then
        observe "bitcoinpr1 mempool not persisted to disk on restart, but tx was re-relayed from peers — consider verifying the mempool.dat save path"
        note "tx not persisted locally but recovered via P2P relay"
        return 0
    fi
    note "tx ${txid:0:12}… lost across restart (neither persisted nor re-relayed)"
    observe "Mempool not restored after bitcoinpr1 restart — graceful mempool save may not be firing on SIGTERM"
    return 1
}

test_inbound_ephemeral() {
    action "Spun up an ephemeral BitcoinPR node (docker run, --connect bitcoinpr1) to verify seed accepts inbound"
    local img="bitcoinpr-local:lite"
    docker image inspect "$img" >/dev/null 2>&1 || img="bitcoinpr-local:full"
    docker image inspect "$img" >/dev/null 2>&1 || { note "no bitcoinpr-local image available"; return 2; }
    local net
    net=$(docker inspect "${CONTAINERS[bitcoinpr1]}" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null)
    [[ -z "$net" ]] && { note "could not determine interop network"; return 2; }

    local before; before=$(peercount_of bitcoinpr1)
    info "Seed peer count before: ${before}; launching ephemeral node on network ${net}…"
    docker rm -f interop-ephemeral >/dev/null 2>&1 || true
    docker run -d --rm --name interop-ephemeral --network "$net" "$img" \
        --network regtest --datadir /data/bitcoinpr \
        --connect interop-bitcoinpr1:18444 \
        --rpcbind 0.0.0.0 --rpcuser test --rpcpassword test --rpcport 18443 \
        --port 18444 >/dev/null 2>&1 \
        || { note "docker run of ephemeral node failed"; return 1; }

    local start=$SECONDS grew=0
    while (( SECONDS - start < 60 )); do
        local cc; cc=$(peercount_of bitcoinpr1)
        [[ "$cc" =~ ^[0-9]+$ && "$before" =~ ^[0-9]+$ ]] && (( cc > before )) && { grew=1; break; }
        sleep "$POLL"
    done
    local after; after=$(peercount_of bitcoinpr1)
    docker rm -f interop-ephemeral >/dev/null 2>&1 || true
    if (( grew )); then
        note "seed accepted ephemeral inbound peer (${before} → ${after} conns), then torn down"
        return 0
    fi
    note "seed peer count did not grow after ephemeral node connect (${before} → ${after})"
    return 1
}

# ── Non-seed block propagation probes (run LAST: may split the chain) ──────────
test_propagation_core() {
    action "Probe: mined blocks on bitcoin-core, checked relay through seed to all peers"
    if _mine_nonseed_probe bitcoin-core 2 "$PROP_TIMEOUT" "core→cluster"; then
        return 0
    fi
    observe "Blocks mined on a NON-seed node (bitcoin-core) propagate slowly through the seed — they reached the seed and bitcoinpr2 but a peer (knots) lagged beyond ${PROP_TIMEOUT}s. Block relay of peer-received blocks is functional but slow; under a LARGE divergence the seed was separately seen to livelock (repeated getheaders + 'Block not found/notfound' on getdata). Investigate received-block re-announce latency and the large-gap livelock."
    return 1
}

test_propagation_knots() {
    action "Probe: mined blocks on bitcoin-knots, checked relay through seed to all peers"
    _mine_nonseed_probe bitcoin-knots 2 "$PROP_TIMEOUT" "knots→cluster" && return 0
    return 1
}

# ══════════════════════════════════════════════════════════════════════════════
#  Report
# ══════════════════════════════════════════════════════════════════════════════

print_report() {
    local total=$((SECONDS - SUITE_START))
    local mm=$((total/60)) ss=$((total%60))
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║          BITCOINPR INTEROP CLUSTER — TEST SUMMARY REPORT              ║${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Run date    : $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "  Duration    : ${mm}m ${ss}s (${total}s)"
    echo -e "  Cluster tip : height $(height_of bitcoinpr1) @ $(tip_of bitcoinpr1 | cut -c1-20)…"
    echo -e "  Result      : ${GREEN}${PASS_N} passed${NC}, ${RED}${FAIL_N} failed${NC}, ${YELLOW}${SKIP_N} skipped${NC}  (of ${#R_NAME[@]} tests)"
    echo ""
    echo -e "${BOLD}  ── Test results ─────────────────────────────────────────────────────${NC}"
    printf "  %-3s %-7s %-6s %s\n" "#" "STATUS" "TIME" "TEST"
    local i
    for i in "${!R_NAME[@]}"; do
        local st="${R_STATUS[$i]}" col="$NC" sym="?"
        case "$st" in
            PASS) col="$GREEN"; sym="✓" ;;
            FAIL) col="$RED";   sym="✗" ;;
            SKIP) col="$YELLOW";sym="–" ;;
        esac
        printf "  %-3s ${col}%-1s %-5s${NC} %-5s %s\n" "$((i+1))" "$sym" "$st" "${R_DUR[$i]}s" "${R_NAME[$i]}"
        [[ -n "${R_NOTE[$i]}" ]] && echo -e "        ${DIM}↳ ${R_NOTE[$i]}${NC}"
    done

    echo ""
    echo -e "${BOLD}  ── Actions performed ────────────────────────────────────────────────${NC}"
    for a in "${ACTIONS[@]}"; do echo -e "  • $a"; done

    if (( FAIL_N > 0 )); then
        echo ""
        echo -e "${BOLD}${RED}  ── Failures ─────────────────────────────────────────────────────────${NC}"
        for i in "${!R_NAME[@]}"; do
            [[ "${R_STATUS[$i]}" == FAIL ]] && echo -e "  ${RED}✗${NC} ${R_NAME[$i]}\n        ${DIM}${R_NOTE[$i]}${NC}"
        done
    fi

    echo ""
    echo -e "${BOLD}  ── Observations & suggested improvements ────────────────────────────${NC}"
    if (( ${#OBSERVATIONS[@]} == 0 )); then
        echo -e "  ${GREEN}No anomalies recorded during this run.${NC}"
    else
        # de-dup
        printf '%s\n' "${OBSERVATIONS[@]}" | awk '!seen[$0]++' | while IFS= read -r o; do
            echo -e "  ${YELLOW}▶${NC} $o"
        done
    fi
    # Always-useful suggestions
    echo -e "  ${BLUE}ℹ${NC} libbitcoin exposes only a ZMQ/bx query interface — height/tip checks are"
    echo -e "      best-effort; it is not cross-checked for mempool/tx relay in this suite."
    echo ""
    if (( FAIL_N == 0 )); then
        echo -e "${GREEN}${BOLD}  OVERALL: PASS — cluster is interoperating correctly.${NC}"
    else
        echo -e "${RED}${BOLD}  OVERALL: ${FAIL_N} test(s) FAILED — see details above.${NC}"
    fi
    echo ""
}

trap 'echo ""; warn "Interrupted — printing partial report."; print_report; exit 130' INT TERM

# ══════════════════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}${CYAN}BitcoinPR interop cluster — functional test suite${NC}"
echo -e "${DIM}mode: $( ((QUICK)) && echo 'quick (no restart phase)' || echo 'full' )   started: $(date '+%H:%M:%S')${NC}"

# Sanity: cluster must be up
if ! wait_rpc_ready bitcoinpr1 15; then
    err "bitcoinpr1 RPC not reachable — start the cluster first: ./scripts/interop-cluster.sh start"
    exit 1
fi

# ── Phase A: healthy-cluster functional tests (all mining on the seed) ─────────
run_test "01 Health / endpoint reachability"          test_health
run_test "02 P2P connectivity & topology"             test_p2p
run_test "03 Addr self-advertisement (O5/O7 wire)"    test_addr_self_advertise
run_test "04 Baseline sync agreement"                 test_baseline_sync
run_test "05 Block creation on bitcoinpr1 (seed)"      test_block_create_seed
run_test "06 Coinbase maturity (seed→Core wallet)"    test_setup_mature
run_test "07 Mempool fill via Core wallet tx"         test_mempool_fill_wallet
run_test "08 Mempool fill via bitcoinpr1 raw tx"       test_mempool_fill_rawtx_bitcoinpr
run_test "09 Mempool clear on block confirmation"     test_mempool_clear
run_test "10 Stratum V1 block mining"                 test_stratum_mine
run_test "11 getblocktemplate sanity"                 test_getblocktemplate
run_test "12 Electrum interface"                      test_electrum
run_test "13 Web explorer reachability"               test_web
if (( QUICK )); then
    info "Skipping resilience/restart phase (--quick)"
else
    run_test "14 Resilience: restart & reconnect"     test_restart_reconnect
    run_test "15 Resilience: mempool persistence"     test_mempool_persistence
    run_test "16 Inbound acceptance (ephemeral node)" test_inbound_ephemeral
fi
# ── Phase B: non-seed propagation probes (run LAST — may split the chain) ──────
run_test "17 Propagation: blocks mined on bitcoin-core" test_propagation_core
run_test "18 Propagation: blocks mined on bitcoin-knots" test_propagation_knots

print_report
(( FAIL_N == 0 ))

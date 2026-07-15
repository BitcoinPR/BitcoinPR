#!/usr/bin/env bash
#
# BIP-110 chain-split scenario test.
#
# Drives the dedicated 2-node split cluster (docker-compose.split.yml — NOT
# the long-lived interop cluster): split-bitcoinpr enforces BIP-110 from
# height 110 (--bip110height fixed mode), split-core does not. Core forges an
# RDTS-violating block (>83-byte OP_RETURN via `generateblock`, which skips
# standardness), the chains split, and the test asserts:
#
#   1. cluster up + baseline sync past the activation height
#   2. the forged block is rejected + durably marked invalid (node NOT wedged)
#   3. the split monitor tracks the rival branch (getchainsplitinfo + /api/split)
#   4. the deficit arms the "abandon minority chain" action at +6 blocks
#   5. mining on our minority chain keeps working while the rival grows
#   5b. a mid-split restart resumes the split from persisted rival tips
#   6..8. capitulation: POST /api/split/capitulate → flag + restart →
#         convergence onto Core's chain from the header re-announcement
#         alone, no new majority block needed (skipped with --monitor-only)
#
# Run order convention:
#   scripts/gate.sh  →  interop-cluster.sh start --build  →
#   interop-test.sh (18/18)  →  interop-split-test.sh
#
# On failure the cluster is LEFT RUNNING for inspection; on success it is
# torn down (down -v). Usage:
#   ./scripts/interop-split-test.sh [--monitor-only] [--keep]

set -euo pipefail
cd "$(dirname "$0")/.."

MONITOR_ONLY=0
KEEP=0
for arg in "$@"; do
    case "$arg" in
        --monitor-only) MONITOR_ONLY=1 ;;
        --keep) KEEP=1 ;;
        *) echo "unknown arg: $arg"; exit 2 ;;
    esac
done

COMPOSE=(docker compose -p bitcoinpr-split -f docker-compose.split.yml)
PR_RPC="http://127.0.0.1:19443"
CORE_RPC="http://127.0.0.1:39443"
WEB="http://127.0.0.1:13000"
ADMIN_TOKEN="splittest"
BIP110_HEIGHT=110

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

wait_height() {  # url target timeout_s label
    local url="$1" target="$2" timeout="${3:-60}" label="${4:-node}"
    local waited=0 h
    while (( waited < timeout )); do
        h=$(rpcurl "$url" getblockcount | result_of)
        if [[ -n "$h" && "$h" -ge "$target" ]]; then return 0; fi
        sleep 2; waited=$((waited + 2))
    done
    return 1
}

wait_rpc() {  # url timeout_s label
    local url="$1" timeout="${2:-90}" label="${3:-node}"
    local waited=0
    while (( waited < timeout )); do
        if [[ -n "$(rpcurl "$url" getblockcount | result_of)" ]]; then return 0; fi
        sleep 2; waited=$((waited + 2))
    done
    return 1
}

# ─── 1. Cluster up + baseline ────────────────────────────────────────────────

step "1. Start split cluster + baseline sync past BIP-110 height ${BIP110_HEIGHT}"

"${COMPOSE[@]}" up -d
wait_rpc "$PR_RPC" 120 || fail "split-bitcoinpr RPC did not come up"
wait_rpc "$CORE_RPC" 120 || fail "split-core RPC did not come up"
info "Both RPCs up"

# Wallet (idempotent across reruns on a kept cluster).
core createwallet '["split"]' >/dev/null 2>&1 || core loadwallet '["split"]' >/dev/null 2>&1 || true
CORE_ADDR=$(core getnewaddress | result_of)
[[ -n "$CORE_ADDR" ]] || fail "could not get a Core wallet address"

BASELINE=$((BIP110_HEIGHT + 5))
CUR=$(core getblockcount | result_of)
if (( CUR < BASELINE )); then
    core generatetoaddress "[$((BASELINE - CUR)),\"$CORE_ADDR\"]" 60 >/dev/null
fi
wait_height "$PR_RPC" "$BASELINE" 90 || fail "split-bitcoinpr did not reach baseline $BASELINE"
PR_TIP=$(pr getbestblockhash | result_of)
CORE_TIP=$(core getbestblockhash | result_of)
[[ "$PR_TIP" == "$CORE_TIP" ]] || fail "tips disagree at baseline ($PR_TIP vs $CORE_TIP)"
info "Baseline $BASELINE reached, tips agree — blocks past $BIP110_HEIGHT validate (standard outputs)"

# ─── 2. Forge the RDTS-violating block on Core ───────────────────────────────

step "2. Forge a >83-byte OP_RETURN block on Core (RDTS rule 1 violation)"

DATA=$(python3 -c "print('aa'*100)")   # 100-byte OP_RETURN payload
RAW=$(core createrawtransaction "[[],{\"data\":\"$DATA\"}]" | result_of)
[[ -n "$RAW" ]] || fail "createrawtransaction failed"
FUNDED=$(core fundrawtransaction "[\"$RAW\"]" | jget "['hex']")
[[ -n "$FUNDED" ]] || fail "fundrawtransaction failed"
SIGNED=$(core signrawtransactionwithwallet "[\"$FUNDED\"]" | jget "['hex']")
[[ -n "$SIGNED" ]] || fail "signrawtransactionwithwallet failed"
FORGED_HASH=$(core generateblock "[\"$CORE_ADDR\",[\"$SIGNED\"]]" | jget "['hash']")
[[ -n "$FORGED_HASH" ]] || fail "generateblock failed (needs Core >= v0.21)"
FORGED_HEIGHT=$((BASELINE + 1))
info "Forged block $FORGED_HEIGHT: $FORGED_HASH"

# split-bitcoinpr must reject it and stay at baseline (and must not wedge).
sleep 10
PR_H=$(pr getblockcount | result_of)
[[ "$PR_H" == "$BASELINE" ]] || fail "split-bitcoinpr height $PR_H — expected to hold at $BASELINE"
CORE_H=$(core getblockcount | result_of)
[[ "$CORE_H" == "$FORGED_HEIGHT" ]] || fail "Core height $CORE_H — expected $FORGED_HEIGHT"
info "split-bitcoinpr held at $BASELINE, Core at $FORGED_HEIGHT — split established"

# ─── 3. Monitor sees the split ───────────────────────────────────────────────

step "3. Split monitor tracks the rival branch"

# The rejection→mark→track sequence can take a couple of block-download
# retries; poll until the monitor reports a split (and the live our-tip has
# been pushed by the 5s node tick).
waited=0
while (( waited < 90 )); do
    SPLIT_JSON=$(pr getchainsplitinfo)
    RIVAL_H=$(echo "$SPLIT_JSON" | jget "['split']['rival']['height']")
    OURS_H=$(echo "$SPLIT_JSON" | jget "['split']['ours']['height']")
    [[ "$RIVAL_H" == "$FORGED_HEIGHT" && "$OURS_H" == "$BASELINE" ]] && break
    sleep 3; waited=$((waited + 3))
done
MODE=$(echo "$SPLIT_JSON" | jget "['bip110']['mode']")
[[ "$MODE" == "fixed" ]] || fail "bip110 mode '$MODE' — expected 'fixed'"
[[ "$OURS_H" == "$BASELINE" ]] || fail "our height '$OURS_H' — expected $BASELINE"
FORK_H=$(echo "$SPLIT_JSON" | jget "['split']['fork_height']")
ARMED=$(echo "$SPLIT_JSON" | jget "['split']['capitulation_armed']")
INV_H=$(echo "$SPLIT_JSON" | jget "['split']['rival_first_invalid']['height']")
[[ "$RIVAL_H" == "$FORGED_HEIGHT" ]] || fail "rival height '$RIVAL_H' — expected $FORGED_HEIGHT"
[[ "$FORK_H" == "$BASELINE" ]] || fail "fork height '$FORK_H' — expected $BASELINE"
[[ "$ARMED" == "False" ]] || fail "armed '$ARMED' — expected False at deficit 1"
[[ "$INV_H" == "$FORGED_HEIGHT" ]] || fail "first invalid height '$INV_H' — expected $FORGED_HEIGHT"
info "getchainsplitinfo: rival=$RIVAL_H fork=$FORK_H armed=$ARMED first_invalid=$INV_H"

# ─── 4. Rival grows to +6+ → armed ───────────────────────────────────────────

step "4. Core extends the rival chain 6 blocks — capitulation arms"

core generatetoaddress "[6,\"$CORE_ADDR\"]" 60 >/dev/null
RIVAL_TARGET=$((FORGED_HEIGHT + 6))
waited=0
while (( waited < 60 )); do
    RIVAL_H=$(pr getchainsplitinfo | jget "['split']['rival']['height']")
    [[ "$RIVAL_H" == "$RIVAL_TARGET" ]] && break
    sleep 3; waited=$((waited + 3))
done
[[ "$RIVAL_H" == "$RIVAL_TARGET" ]] || fail "monitor rival height '$RIVAL_H' — expected $RIVAL_TARGET"

SPLIT_JSON=$(pr getchainsplitinfo)
DEFICIT=$(echo "$SPLIT_JSON" | jget "['split']['block_deficit']")
ARMED=$(echo "$SPLIT_JSON" | jget "['split']['capitulation_armed']")
(( DEFICIT >= 6 )) || fail "deficit $DEFICIT — expected >= 6"
[[ "$ARMED" == "True" ]] || fail "expected capitulation_armed after +6 rival blocks"
PR_H=$(pr getblockcount | result_of)
[[ "$PR_H" == "$BASELINE" ]] || fail "split-bitcoinpr wedged? height $PR_H, expected $BASELINE"
info "deficit=$DEFICIT armed=$ARMED — node holding its chain, RPC live"

# Web API agrees.
WEB_ARMED=$(curl -sf --max-time 10 "$WEB/api/split" | python3 -c "import sys,json; print(json.load(sys.stdin)['split']['capitulation_armed'])")
[[ "$WEB_ARMED" == "True" ]] || fail "GET /api/split armed '$WEB_ARMED' — expected True"
# The Split tab is stats-gated: split_active must be true while tracking.
SPLIT_ACTIVE=$(curl -sf --max-time 10 "$WEB/api/stats" | python3 -c "import sys,json; print(json.load(sys.stdin).get('split_active'))")
[[ "$SPLIT_ACTIVE" == "True" ]] || fail "/api/stats split_active '$SPLIT_ACTIVE' — expected True"
info "GET /api/split agrees (armed); /api/stats split_active=true (tab visible)"

# ─── 5. Both chains keep growing ─────────────────────────────────────────────

step "5. Mine on our minority chain — both tips grow, still armed"

pr generatetoaddress "[1,\"bcrt1qhgq7kd64luescw6d639vf3zj777m7600mwlc5f\"]" 60 >/dev/null
OURS_TARGET=$((BASELINE + 1))
wait_height "$PR_RPC" "$OURS_TARGET" 30 || fail "minority-chain mining failed"
# The monitor's our-tip is pushed by the node's 5s tick — poll until it
# reflects the new block.
waited=0
while (( waited < 30 )); do
    SPLIT_JSON=$(pr getchainsplitinfo)
    OURS_H=$(echo "$SPLIT_JSON" | jget "['split']['ours']['height']")
    [[ "$OURS_H" == "$OURS_TARGET" ]] && break
    sleep 3; waited=$((waited + 3))
done
DEFICIT=$(echo "$SPLIT_JSON" | jget "['split']['block_deficit']")
ARMED=$(echo "$SPLIT_JSON" | jget "['split']['capitulation_armed']")
[[ "$OURS_H" == "$OURS_TARGET" ]] || fail "our height '$OURS_H' — expected $OURS_TARGET"
(( DEFICIT >= 6 )) || fail "deficit $DEFICIT after mining — expected >= 6"
[[ "$ARMED" == "True" ]] || fail "expected still armed at deficit $DEFICIT"
info "ours=$OURS_H rival=$RIVAL_TARGET deficit=$DEFICIT armed=$ARMED"

# ─── 5b. Mid-split restart: persisted rival tips ─────────────────────────────

step "5b. Restart mid-split — the tracked rival survives (persistence)"

docker restart split-bitcoinpr >/dev/null
wait_rpc "$PR_RPC" 120 || fail "node did not come back after mid-split restart"
# No new rival blocks are mined: the split must resurface from the
# persisted rival tips alone (plus the 5s our-tip tick).
waited=0
while (( waited < 45 )); do
    RIVAL_H=$(pr getchainsplitinfo | jget "['split']['rival']['height']")
    ARMED=$(pr getchainsplitinfo | jget "['split']['capitulation_armed']")
    [[ "$RIVAL_H" == "$RIVAL_TARGET" && "$ARMED" == "True" ]] && break
    sleep 3; waited=$((waited + 3))
done
[[ "$RIVAL_H" == "$RIVAL_TARGET" ]] || fail "split not restored after restart (rival '$RIVAL_H')"
[[ "$ARMED" == "True" ]] || fail "capitulation not re-armed after restart"
info "split restored from persisted rival tips (rival=$RIVAL_H, armed)"

if (( MONITOR_ONLY )); then
    step "MONITOR-ONLY PASS (capitulation steps skipped)"
    if (( ! KEEP )); then "${COMPOSE[@]}" down -v >/dev/null 2>&1; info "cluster torn down"; fi
    exit 0
fi

# ─── 6. Capitulate: abandon minority chain ───────────────────────────────────

step "6. POST /api/split/capitulate — abandon minority chain"

CAP_RESP=$(curl -s --max-time 15 -X POST "$WEB/api/split/capitulate" \
    -H "Origin: $WEB" -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"confirm":"ABANDON-BIP110"}')
SHUTTING=$(echo "$CAP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('shutting_down',''))" 2>/dev/null || true)
[[ "$SHUTTING" == "True" ]] || fail "capitulate response: $CAP_RESP"
info "Capitulation accepted — node shutting down (docker restarts it)"

# ─── 7. Restart + convergence ────────────────────────────────────────────────

step "7. Node restarts with BIP-110 abandoned and converges on Core's chain"

sleep 5
wait_rpc "$PR_RPC" 180 || fail "split-bitcoinpr RPC did not come back after capitulation"
# NO new majority block is mined: with the markers cleared at startup, fork
# choice re-evaluates the re-announced stored rival branch and adopts it
# from the announcement alone (headers repair-path fork-choice re-eval).
CORE_H=$(core getblockcount | result_of)
wait_height "$PR_RPC" "$CORE_H" 120 || fail "did not converge to Core height $CORE_H from re-announcement alone"
PR_TIP=$(pr getbestblockhash | result_of)
CORE_TIP=$(core getbestblockhash | result_of)
[[ "$PR_TIP" == "$CORE_TIP" ]] || fail "tips disagree after capitulation ($PR_TIP vs $CORE_TIP)"

SPLIT_JSON=$(pr getchainsplitinfo)
ABANDONED=$(echo "$SPLIT_JSON" | jget "['abandoned']")
MODE=$(echo "$SPLIT_JSON" | jget "['bip110']['mode']")
[[ "$ABANDONED" == "True" ]] || fail "abandoned '$ABANDONED' — expected True"
[[ "$MODE" == "abandoned" ]] || fail "mode '$MODE' — expected 'abandoned'"
BC_STATUS=$(pr getblockchaininfo | jget "['softforks']['bip110']['bip9']['status']" || true)
info "Converged at $CORE_H ($PR_TIP), mode=abandoned, softfork status=${BC_STATUS:-n/a}"

# ─── 8. Teardown ─────────────────────────────────────────────────────────────

step "8. FULL PASS"
if (( ! KEEP )); then "${COMPOSE[@]}" down -v >/dev/null 2>&1; info "cluster torn down"; fi
exit 0

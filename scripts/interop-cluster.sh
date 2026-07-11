#!/usr/bin/env bash
# scripts/interop-cluster.sh — Manage the 6-node regtest interoperability cluster.
#
# Usage:
#   ./scripts/interop-cluster.sh start    [--build]   Start all nodes (optionally rebuild images)
#   ./scripts/interop-cluster.sh stop                 Stop and remove containers (keep data)
#   ./scripts/interop-cluster.sh restart              Stop then start
#   ./scripts/interop-cluster.sh reset                Stop, wipe all data volumes, and start fresh
#   ./scripts/interop-cluster.sh status               Print per-node height, hash, peers
#   ./scripts/interop-cluster.sh wait                 Block until all nodes are responsive
#
# Environment:
#   DATA_DIR   — base dir for node data  (default: ./data/interop)
#   COMPOSE    — path to docker compose  (default: docker-compose.interop.yml)
#
# Libbitcoin is queried via `bx` (bitcoin-explorer) running inside its container
# over ZMQ.  No host-side bx installation is required.

set -euo pipefail

# ─── Config ───────────────────────────────────────────────────────────────────

COMPOSE_FILE="${COMPOSE:-docker-compose.interop.yml}"
DATA_DIR="${DATA_DIR:-./data/interop}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# RPC endpoints for JSON-RPC nodes (host-mapped)
declare -A RPC_URLS=(
    [bitcoinpr1]="http://test:test@127.0.0.1:18443"
    [bitcoinpr2]="http://test:test@127.0.0.1:28443"
    [bitcoin-core]="http://test:test@127.0.0.1:38443"
    [bitcoin-knots]="http://test:test@127.0.0.1:48443"
    [btcd]="https://test:test@127.0.0.1:58443"
)

# Libbitcoin — queried via bx inside the container (ZMQ to localhost:9091)
LB_CONTAINER="interop-libbitcoin"
LB_BX_CFG="/etc/libbitcoin/bs.cfg"

RPC_TIMEOUT=120   # seconds to wait for each node to become responsive
POLL_INTERVAL=3

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[CLUSTER]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
step()  { echo -e "${CYAN}${BOLD}==> $*${NC}"; }

# ─── Helpers ──────────────────────────────────────────────────────────────────

dc() {
    docker compose -f "${REPO_ROOT}/${COMPOSE_FILE}" "$@"
}

rpc() {
    local node="$1" method="$2"
    local params="${3:-[]}"
    local url="${RPC_URLS[$node]}"
    curl -sk --max-time 10 -X POST "$url" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"id\":1}" \
        2>/dev/null || true
}

get_result() {
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('result',''))" 2>/dev/null || echo ""
}

get_error() {
    python3 -c "import sys,json; d=json.load(sys.stdin); e=d.get('error'); print(e['message'] if e else '')" 2>/dev/null || echo ""
}

# ─── Libbitcoin / bx helpers ──────────────────────────────────────────────────

# Run a bx command inside the libbitcoin container.
bx_exec() {
    docker exec "$LB_CONTAINER" bx "$@" -c "$LB_BX_CFG" 2>/dev/null || true
}

# Current chain height reported by libbitcoin (empty string if not ready).
lb_height() {
    bx_exec fetch-height | tr -d '[:space:]'
}

# Tip block hash at the current best height.
# bx fetch-block-header <height> outputs structured text including a "hash" line.
lb_tip() {
    local h
    h=$(lb_height)
    [[ ! "$h" =~ ^[0-9]+$ ]] && echo "" && return
    bx_exec fetch-block-header "$h" 2>/dev/null \
        | awk '/^\s+hash /{print $2; exit}' || echo ""
}

is_lb_ready() {
    [[ "$(lb_height)" =~ ^[0-9]+$ ]]
}

wait_for_lb() {
    local start=$SECONDS
    info "Waiting for libbitcoin bx to respond..."
    while true; do
        if is_lb_ready; then
            info "libbitcoin bx ready (height: $(lb_height))"
            return 0
        fi
        if (( SECONDS - start > RPC_TIMEOUT )); then
            warn "libbitcoin bx not responding after ${RPC_TIMEOUT}s — it may still be initialising"
            return 0  # non-fatal; P2P sync can still proceed
        fi
        sleep "$POLL_INTERVAL"
    done
}

# ─── JSON-RPC helpers ─────────────────────────────────────────────────────────

is_rpc_ready() {
    local node="$1"
    local resp
    resp=$(rpc "$node" "getblockcount" 2>/dev/null || true)
    [[ -n "$resp" ]] && echo "$resp" | grep -q '"result"'
}

wait_for_node() {
    local node="$1"
    local start=$SECONDS
    while true; do
        if is_rpc_ready "$node"; then
            info "${node} RPC ready"
            return 0
        fi
        if (( SECONDS - start > RPC_TIMEOUT )); then
            error "${node} RPC not ready after ${RPC_TIMEOUT}s"
            return 1
        fi
        sleep "$POLL_INTERVAL"
    done
}

prepare_data_dirs() {
    step "Preparing data directories under ${DATA_DIR}"
    local dirs=(bitcoinpr1 bitcoinpr2 bitcoin-core bitcoin-knots btcd libbitcoin)
    for d in "${dirs[@]}"; do
        mkdir -p "${DATA_DIR}/${d}"
    done
    # Bitcoin Core / Knots / btcd images run as uid 1000; ensure the volumes are writable.
    chmod 777 "${DATA_DIR}/bitcoin-core" "${DATA_DIR}/bitcoin-knots" "${DATA_DIR}/btcd" 2>/dev/null || true
    info "Data dirs ready"
}

wipe_data_dirs() {
    step "Wiping data directories"
    # Use an Alpine container to remove root-owned files safely.
    docker run --rm \
        -v "$(realpath "${DATA_DIR}"):/data" \
        alpine:latest \
        sh -c 'rm -rf /data/bitcoinpr1 /data/bitcoinpr2 /data/bitcoin-core /data/bitcoin-knots /data/btcd /data/libbitcoin' \
        2>/dev/null || true
    info "Data dirs wiped"
}

# ─── Sub-commands ─────────────────────────────────────────────────────────────

cmd_build() {
    step "Building images"
    dc build
}

cmd_start() {
    local do_build=0
    for arg in "$@"; do
        [[ "$arg" == "--build" ]] && do_build=1
    done

    cd "${REPO_ROOT}"
    prepare_data_dirs
    [[ "$do_build" == 1 ]] && cmd_build

    step "Starting interop cluster"
    DATA_DIR="${DATA_DIR}" dc up -d
    info "Containers started — waiting for RPC endpoints..."
    cmd_wait
    echo ""
    cmd_status
}

cmd_stop() {
    step "Stopping interop cluster"
    cd "${REPO_ROOT}"
    DATA_DIR="${DATA_DIR}" dc down
    info "Cluster stopped (data preserved)"
}

cmd_restart() {
    cmd_stop
    cmd_start "$@"
}

cmd_reset() {
    step "Resetting cluster (stop + wipe data + start fresh)"
    cd "${REPO_ROOT}"
    DATA_DIR="${DATA_DIR}" dc down -v 2>/dev/null || true
    wipe_data_dirs
    cmd_start "$@"
}

cmd_wait() {
    step "Waiting for all nodes to become responsive"
    local failed=0
    for node in "${!RPC_URLS[@]}"; do
        wait_for_node "$node" || failed=1
    done
    wait_for_lb  # non-fatal if bx is slow to initialise
    return $failed
}

cmd_status() {
    step "Cluster status"
    printf "%-18s  %-8s  %-10s  %-6s  %s\n" "NODE" "HEIGHT" "PEERS" "STATUS" "TIP HASH"
    printf "%-18s  %-8s  %-10s  %-6s  %s\n" "----" "------" "-----" "------" "--------"

    for node in bitcoinpr1 bitcoinpr2 bitcoin-core bitcoin-knots btcd; do
        local resp height peers tip status
        resp=$(rpc "$node" "getblockcount" 2>/dev/null || true)
        if echo "$resp" | grep -q '"result"'; then
            height=$(echo "$resp" | get_result)
            peers_resp=$(rpc "$node" "getpeerinfo" 2>/dev/null || true)
            peers=$(echo "$peers_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('result',[])))" 2>/dev/null || echo "?")
            tip_resp=$(rpc "$node" "getbestblockhash" 2>/dev/null || true)
            tip=$(echo "$tip_resp" | get_result)
            tip="${tip:0:16}..."
            status="${GREEN}UP${NC}"
        else
            height="—" peers="—" tip="—"
            status="${RED}DOWN${NC}"
        fi
        printf "%-18s  %-8s  %-10s  " "$node" "$height" "$peers"
        echo -e "${status}    ${tip}"
    done

    # Libbitcoin — query height and tip via bx
    local lb_state lb_h lb_t
    lb_state=$(docker inspect --format='{{.State.Status}}' "$LB_CONTAINER" 2>/dev/null || echo "not found")
    if [[ "$lb_state" == "running" ]]; then
        lb_h=$(lb_height)
        lb_t=$(lb_tip)
        if [[ "$lb_h" =~ ^[0-9]+$ ]]; then
            local lb_tip_display="${lb_t:0:16}..."
            [[ -z "$lb_t" ]] && lb_tip_display="(bx tip unavailable)"
            printf "%-18s  %-8s  %-10s  " "libbitcoin" "$lb_h" "(ZMQ)"
            echo -e "${GREEN}UP${NC}    ${lb_tip_display}"
        else
            printf "%-18s  %-8s  %-10s  " "libbitcoin" "init…" "(ZMQ)"
            echo -e "${GREEN}UP${NC}    (bx not ready yet)"
        fi
    else
        printf "%-18s  %-8s  %-10s  " "libbitcoin" "—" "—"
        echo -e "${RED}${lb_state}${NC}"
    fi
}

# ─── Main ─────────────────────────────────────────────────────────────────────

usage() {
    grep '^# Usage' -A 7 "${BASH_SOURCE[0]}" | sed 's/^# \?//'
}

case "${1:-}" in
    start)    shift; cmd_start   "$@" ;;
    stop)     cmd_stop ;;
    restart)  shift; cmd_restart "$@" ;;
    reset)    shift; cmd_reset   "$@" ;;
    status)   cmd_status ;;
    wait)     cmd_wait ;;
    build)    cmd_build ;;
    *)        usage; exit 1 ;;
esac

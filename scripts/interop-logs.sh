#!/usr/bin/env bash
# scripts/interop-logs.sh — Collect and analyse interop cluster logs.
#
# Modes:
#   follow   Stream all node logs interleaved with a per-node colour prefix (default)
#   dump     Collect recent logs from each node into a timestamped directory
#   summary  Print a structured event digest (blocks, peers, errors) from recent logs
#   diff     Compare block-received timestamps across nodes to measure propagation lag
#
# Usage:
#   ./scripts/interop-logs.sh [MODE] [OPTIONS]
#
#   MODE         follow | dump | summary | diff  (default: follow)
#
#   --lines N    Lines of history to fetch in dump/summary/diff mode (default: 500)
#   --level LVL  Filter to log level: error | warn | info | debug    (default: all)
#   --node NODE  Restrict output to one node (can repeat)
#   --out DIR    Output directory for dump mode (default: ./logs/interop-<timestamp>)
#   --since T    Docker --since flag (e.g. "5m", "1h", "2024-01-01T00:00:00")

set -euo pipefail

# ─── Constants ────────────────────────────────────────────────────────────────

ALL_NODES=(bitcoinpr1 bitcoinpr2 bitcoin-core bitcoin-knots btcd libbitcoin)

LB_CONTAINER="interop-libbitcoin"
LB_BX_CFG="/etc/libbitcoin/bs.cfg"

# Docker container names
declare -A CONTAINERS=(
    [bitcoinpr1]="interop-bitcoinpr1"
    [bitcoinpr2]="interop-bitcoinpr2"
    [bitcoin-core]="interop-bitcoin-core"
    [bitcoin-knots]="interop-bitcoin-knots"
    [btcd]="interop-btcd"
    [libbitcoin]="interop-libbitcoin"
)

# ANSI colour per node (foreground)
declare -A NODE_COLORS=(
    [bitcoinpr1]="\033[0;32m"      # green
    [bitcoinpr2]="\033[0;36m"      # cyan
    [bitcoin-core]="\033[0;33m"   # yellow
    [bitcoin-knots]="\033[0;35m"  # magenta
    [btcd]="\033[0;37m"           # white
    [libbitcoin]="\033[0;34m"     # blue
)
NC="\033[0m"
BOLD="\033[1m"
RED="\033[0;31m"
GREEN="\033[0;32m"

# ─── Argument parsing ─────────────────────────────────────────────────────────

MODE="${1:-follow}"
if [[ "$MODE" == follow || "$MODE" == dump || "$MODE" == summary || "$MODE" == diff ]]; then
    shift || true
fi

LINES=500
LEVEL=""
SINCE=""
OUT_DIR=""
SELECTED_NODES=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --lines)  LINES="$2"; shift 2 ;;
        --level)  LEVEL="$2"; shift 2 ;;
        --node)   SELECTED_NODES+=("$2"); shift 2 ;;
        --out)    OUT_DIR="$2"; shift 2 ;;
        --since)  SINCE="$2"; shift 2 ;;
        *)        echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

[[ ${#SELECTED_NODES[@]} -eq 0 ]] && SELECTED_NODES=("${ALL_NODES[@]}")

[[ -z "$OUT_DIR" ]] && OUT_DIR="./logs/interop-$(date +%Y%m%d-%H%M%S)"

# ─── Helpers ──────────────────────────────────────────────────────────────────

container_for() { echo "${CONTAINERS[$1]}"; }

bx_exec() {
    docker exec "$LB_CONTAINER" bx "$@" -c "$LB_BX_CFG" 2>/dev/null || true
}

lb_height() {
    bx_exec fetch-height | tr -d '[:space:]'
}

lb_tip() {
    local h="${1:-$(lb_height)}"
    [[ ! "$h" =~ ^[0-9]+$ ]] && echo "" && return
    bx_exec fetch-block-header "$h" 2>/dev/null \
        | awk '/^\s+hash /{print $2; exit}' || echo ""
}

docker_logs_args() {
    local args=()
    [[ -n "$SINCE" ]] && args+=(--since "$SINCE")
    args+=(--tail "$LINES")
    echo "${args[@]}"
}

is_running() {
    local cname
    cname=$(container_for "$1")
    docker inspect --format='{{.State.Running}}' "$cname" 2>/dev/null | grep -q true
}

level_grep_pattern() {
    case "${LEVEL,,}" in
        error) echo -iE "(error|ERR|FATAL|panic)" ;;
        warn)  echo -iE "(warn|WARNING|error|ERR)" ;;
        info)  echo -iE "(info|INFO|warn|WARNING|error|ERR)" ;;
        debug) echo "" ;;
        *)     echo "" ;;
    esac
}

# ─── Mode: follow ─────────────────────────────────────────────────────────────

cmd_follow() {
    echo -e "${BOLD}Streaming logs from ${#SELECTED_NODES[@]} node(s)... (Ctrl-C to stop)${NC}"
    echo ""
    local pids=()

    for node in "${SELECTED_NODES[@]}"; do
        if ! is_running "$node"; then
            echo -e "${RED}[${node}]${NC} container not running — skipping"
            continue
        fi

        local cname color
        cname=$(container_for "$node")
        color="${NODE_COLORS[$node]:-}"

        local args
        args=$(docker_logs_args)

        # Pipe docker logs through a prefix-stamper subshell
        (
            # shellcheck disable=SC2086
            docker logs -f $args "$cname" 2>&1 | \
            while IFS= read -r line; do
                # Optional level filter
                if [[ -n "$LEVEL" ]]; then
                    local pattern
                    pattern=$(level_grep_pattern)
                    [[ -n "$pattern" ]] && ! echo "$line" | grep -qP "${pattern#-iE }" && continue
                fi
                echo -e "${color}[${node}]${NC} ${line}"
            done
        ) &
        pids+=($!)
    done

    trap 'kill "${pids[@]}" 2>/dev/null; echo ""; echo "Log stream stopped."; exit 0' INT TERM
    wait "${pids[@]}" 2>/dev/null || true
}

# ─── Mode: dump ───────────────────────────────────────────────────────────────

cmd_dump() {
    mkdir -p "$OUT_DIR"
    echo -e "${BOLD}Dumping logs to: ${OUT_DIR}${NC}"

    for node in "${SELECTED_NODES[@]}"; do
        local cname outfile
        cname=$(container_for "$node")
        outfile="${OUT_DIR}/${node}.log"

        if ! is_running "$node"; then
            echo "  ${node}: container not running — skipping"
            echo "[container not running at $(date -Iseconds)]" > "$outfile"
            continue
        fi

        local args
        args=$(docker_logs_args)
        # shellcheck disable=SC2086
        docker logs $args "$cname" > "$outfile" 2>&1
        local lines
        lines=$(wc -l < "$outfile")
        printf "  %-18s  → %s  (%d lines)\n" "$node" "$outfile" "$lines"
    done

    # Write a manifest
    {
        echo "# Interop log dump — $(date -Iseconds)"
        echo "# Nodes: ${SELECTED_NODES[*]}"
        echo "# Lines: ${LINES}"
        [[ -n "$SINCE" ]] && echo "# Since: ${SINCE}"
    } > "${OUT_DIR}/MANIFEST"

    echo ""
    echo -e "${BOLD}Done. Logs saved to: ${OUT_DIR}${NC}"
}

# ─── Mode: summary ────────────────────────────────────────────────────────────

cmd_summary() {
    echo -e "${BOLD}Log event summary (last ${LINES} lines per node)${NC}"
    echo ""

    for node in "${SELECTED_NODES[@]}"; do
        local cname
        cname=$(container_for "$node")

        echo -e "${NODE_COLORS[$node]:-}${BOLD}── ${node} ──────────────────────────────────────${NC}"

        if ! is_running "$node"; then
            echo "  (not running)"
            echo ""
            continue
        fi

        local args raw
        args=$(docker_logs_args)
        # shellcheck disable=SC2086
        raw=$(docker logs $args "$cname" 2>&1 || true)

        if [[ -z "$raw" ]]; then
            echo "  (no log output)"
            echo ""
            continue
        fi

        # ── Block events
        local blocks
        blocks=$(echo "$raw" | grep -iE "(new block|block received|accepted block|connected block|validated block|height|block height)" | tail -5 || true)
        if [[ -n "$blocks" ]]; then
            echo "  BLOCKS (last 5):"
            echo "$blocks" | sed 's/^/    /'
        fi

        # ── Peer events
        local peers
        peers=$(echo "$raw" | grep -iE "(peer connected|peer disconnected|new peer|connection from|handshake|version msg)" | tail -5 || true)
        if [[ -n "$peers" ]]; then
            echo "  PEERS (last 5):"
            echo "$peers" | sed 's/^/    /'
        fi

        # ── Warnings
        local warns
        warns=$(echo "$raw" | grep -iE "warn" | grep -viE "error" | tail -5 || true)
        if [[ -n "$warns" ]]; then
            echo "  WARNINGS (last 5):"
            echo "$warns" | sed 's/^/    /'
        fi

        # ── Errors
        local errors
        errors=$(echo "$raw" | grep -iE "(error|ERR|fatal|panic)" | tail -10 || true)
        if [[ -n "$errors" ]]; then
            echo -e "  ${RED}ERRORS (last 10):${NC}"
            echo "$errors" | sed "s/^/    /" | GREP_COLOR='01;31' grep --color=always -iE "(error|ERR|fatal|panic)" || echo "$errors" | sed 's/^/    /'
        fi

        echo ""
    done
}

# ─── Mode: diff ───────────────────────────────────────────────────────────────
# Two-part output:
#   1. Live chain-state snapshot — queries current height + tip hash from every
#      node right now (bx for libbitcoin, JSON-RPC for the others).
#   2. Log-based block event lines — last N lines containing a block hash,
#      useful for spotting the first timestamp each node saw a given block.

declare -A DIFF_RPC_URLS=(
    [bitcoinpr1]="http://test:test@127.0.0.1:18443"
    [bitcoinpr2]="http://test:test@127.0.0.1:28443"
    [bitcoin-core]="http://test:test@127.0.0.1:38443"
    [bitcoin-knots]="http://test:test@127.0.0.1:48443"
    [btcd]="https://test:test@127.0.0.1:58443"
)

_rpc_field() {
    local url="$1" method="$2"
    curl -sk --max-time 8 -X POST "$url" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":[],\"id\":1}" \
        2>/dev/null | \
        python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('result',''))" \
        2>/dev/null || echo ""
}

cmd_diff() {
    echo -e "${BOLD}Chain-state snapshot + block propagation log (last ${LINES} lines)${NC}"
    echo ""

    # ── Part 1: live chain-state from all nodes ─────────────────────────────
    echo -e "${BOLD}── Live chain state ─────────────────────────────────────────────${NC}"
    printf "%-18s  %-8s  %s\n" "NODE" "HEIGHT" "TIP HASH"
    printf "%-18s  %-8s  %s\n" "----" "------" "--------"

    local ref_tip=""
    local mismatch=0

    for node in bitcoinpr1 bitcoinpr2 bitcoin-core bitcoin-knots btcd; do
        local color="${NODE_COLORS[$node]:-}" url="${DIFF_RPC_URLS[$node]}"
        local h t marker
        h=$(_rpc_field "$url" "getblockcount")
        t=$(_rpc_field "$url" "getbestblockhash")
        [[ -z "$ref_tip" && -n "$t" ]] && ref_tip="$t"
        if [[ -n "$t" && -n "$ref_tip" && "$t" != "$ref_tip" ]]; then
            marker=" ${RED}← MISMATCH${NC}"; mismatch=1
        else
            marker=""
        fi
        printf "%-18s  %-8s  " "$node" "${h:-?}"
        echo -e "${color}${t:-unavailable}${NC}${marker}"
    done

    # Libbitcoin via bx
    if is_running "libbitcoin"; then
        local lb_h lb_t lb_marker=""
        lb_h=$(lb_height)
        lb_t=$(lb_tip "$lb_h")
        if [[ -n "$lb_t" && -n "$ref_tip" && "$lb_t" != "$ref_tip" ]]; then
            lb_marker=" ${RED}← MISMATCH${NC}"; mismatch=1
        fi
        printf "%-18s  %-8s  " "libbitcoin" "${lb_h:-?}"
        echo -e "${NODE_COLORS[libbitcoin]}${lb_t:-unavailable}${NC}${lb_marker}"
    else
        printf "%-18s  %-8s  %s\n" "libbitcoin" "—" "(not running)"
    fi

    echo ""
    if [[ "$mismatch" == 1 ]]; then
        echo -e "${RED}${BOLD}TIP MISMATCH detected — possible consensus failure.${NC}"
        echo "  Run: ./scripts/interop-logs.sh summary --level error"
    else
        echo -e "${GREEN}All queried nodes agree on tip.${NC}"
    fi
    echo ""

    # ── Part 2: log-based block event lines ────────────────────────────────
    echo -e "${BOLD}── Block events in logs (last ${LINES} lines, lines containing a block hash) ──${NC}"
    echo ""

    local tmpdir
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    for node in "${SELECTED_NODES[@]}"; do
        local cname outfile
        cname=$(container_for "$node")
        outfile="${tmpdir}/${node}.txt"

        if ! is_running "$node"; then
            touch "$outfile"
            continue
        fi

        local args
        args=$(docker_logs_args)
        # Broad pattern: lines that mention a block and contain a 64-char hex hash
        # shellcheck disable=SC2086
        docker logs $args "$cname" 2>&1 | \
            grep -iE "(block|height)" | \
            grep -iE "[0-9a-f]{64}" \
            > "$outfile" 2>/dev/null || touch "$outfile"
    done

    for node in "${SELECTED_NODES[@]}"; do
        local color="${NODE_COLORS[$node]:-}"
        echo -e "${color}${BOLD}${node}${NC}"
        local count=0
        while IFS= read -r line; do
            printf "  %.200s\n" "$line"
            (( count++ ))
            [[ $count -ge 10 ]] && break
        done < "${tmpdir}/${node}.txt" || true
        [[ $count -eq 0 ]] && echo "  (no block hash lines found in last ${LINES} lines)"
        echo ""
    done

    echo "Tip: for precise propagation timing use '--since 1m' then generate one block."
    echo "     Compare the first timestamp each node logged the new hash."
}

# ─── Dispatch ─────────────────────────────────────────────────────────────────

case "$MODE" in
    follow)  cmd_follow  ;;
    dump)    cmd_dump    ;;
    summary) cmd_summary ;;
    diff)    cmd_diff    ;;
    *)
        echo "Unknown mode: ${MODE}" >&2
        echo "Usage: $0 [follow|dump|summary|diff] [options]" >&2
        exit 1
        ;;
esac

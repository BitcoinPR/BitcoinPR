#!/usr/bin/env bash
# dashboard.sh — BitcoinPR progress dashboard
#
# Renders a single-screen status board summarising the BitcoinPR port:
# workspace LOC, module weights, BIP coverage, git history, and (when a
# local bitcoinprd is reachable) live sync / peer / mempool stats.
#
# Usage:
#   ./scripts/dashboard.sh                  # one-shot render
#   ./scripts/dashboard.sh --watch          # refresh every 5s
#   ./scripts/dashboard.sh --watch 2        # refresh every 2s
#   ./scripts/dashboard.sh --no-rpc         # skip live RPC probe
#   ./scripts/dashboard.sh --rpc URL        # custom RPC endpoint
#   ./scripts/dashboard.sh --plain          # no ANSI colour
#
# RPC defaults to http://bitcoinpr:bitcoinpr@127.0.0.1:8332 (mainnet).

set -u

# ---------- arg parsing ----------
WATCH=0
WATCH_INTERVAL=5
USE_RPC=1
RPC_URL="http://bitcoinpr:bitcoinpr@127.0.0.1:8332"
COLOR=1

while [ $# -gt 0 ]; do
  case "$1" in
    --watch)
      WATCH=1
      if [ "${2-}" ] && echo "$2" | grep -qE '^[0-9]+$'; then
        WATCH_INTERVAL="$2"; shift
      fi
      ;;
    --no-rpc)   USE_RPC=0 ;;
    --rpc)      RPC_URL="${2:-$RPC_URL}"; shift ;;
    --plain)    COLOR=0 ;;
    -h|--help)
      sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done

# ---------- locate repo root ----------
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

# ---------- colour ----------
if [ "$COLOR" = 1 ] && [ -t 1 ]; then
  C_RESET=$'\033[0m'
  C_DIM=$'\033[2m'
  C_BOLD=$'\033[1m'
  C_ACCENT=$'\033[38;5;214m'   # bitcoin orange
  C_GREEN=$'\033[38;5;46m'
  C_RED=$'\033[38;5;203m'
  C_BLUE=$'\033[38;5;75m'
  C_FG=$'\033[38;5;255m'
else
  C_RESET=''; C_DIM=''; C_BOLD=''; C_ACCENT=''
  C_GREEN=''; C_RED=''; C_BLUE=''; C_FG=''
fi

# ---------- helpers ----------
hr() { printf '%s\n' "$C_DIM ₿· · · · · · · · · · · · · · · · · · · · · · · · ₿ · · · · · · · · · · · · · · · · · · · · · · · ·₿$C_RESET"; }

# Repeat a character N times.
rep() { local c="$1" n="$2" out=""; while [ "$n" -gt 0 ]; do out="$out$c"; n=$((n-1)); done; printf '%s' "$out"; }

# Render a horizontal bar of width W where N/D is filled.
bar() {
  local n="$1" d="$2" w="$3"
  [ "$d" -le 0 ] && d=1
  local fill=$(( (n * w) / d ))
  [ "$fill" -gt "$w" ] && fill=$w
  local empty=$(( w - fill ))
  printf '%s%s%s%s%s' "$C_ACCENT" "$(rep '█' "$fill")" "$C_DIM" "$(rep '░' "$empty")" "$C_RESET"
}

# ---------- workspace metrics (from filesystem) ----------
crate_loc() {
  local crate="$1"
  find "$crate/src" -name '*.rs' -type f -exec cat {} + 2>/dev/null | wc -l | tr -d ' '
}
crate_files() {
  local crate="$1"
  find "$crate/src" -name '*.rs' -type f 2>/dev/null | wc -l | tr -d ' '
}

CRATES="bitcoinpr bitcoinpr-core bitcoinpr-p2p bitcoinpr-storage bitcoinpr-rpc bitcoinpr-mining bitcoinpr-index bitcoinpr-web"

declare -A LOC_BY_CRATE
declare -A FILES_BY_CRATE
TOTAL_LOC=0
TOTAL_FILES=0
MAX_LOC=0
for c in $CRATES; do
  l=$(crate_loc "$c"); f=$(crate_files "$c")
  LOC_BY_CRATE[$c]=$l
  FILES_BY_CRATE[$c]=$f
  TOTAL_LOC=$((TOTAL_LOC + l))
  TOTAL_FILES=$((TOTAL_FILES + f))
  [ "$l" -gt "$MAX_LOC" ] && MAX_LOC=$l
done

# Tests, pub fns, comments, RPC methods, BIP coverage
TEST_COUNT=$(grep -rhE '^\s*#\[(tokio::)?test\]' --include='*.rs' . 2>/dev/null | wc -l | tr -d ' ')
PUBFN_COUNT=$(grep -rhE '^\s*pub (fn|async fn)' --include='*.rs' . 2>/dev/null | wc -l | tr -d ' ')
COMMENT_LINES=$(grep -rhE '^\s*(//|///)' --include='*.rs' . 2>/dev/null | wc -l | tr -d ' ')
RPC_METHODS=$(grep -hE 'name = "' bitcoinpr-rpc/src/methods.rs 2>/dev/null | grep -c 'name = "')

# BIPs that grep would find anywhere in code/docs (referenced, may include TODOs).
BIP_REFERENCED=$(grep -rhoE 'BIP[- ]?[0-9]+' --include='*.rs' --include='*.md' \
  --exclude='dashboard.sh' . 2>/dev/null \
  | grep -oE '[0-9]+' | sort -un)
BIP_REF_COUNT=$(printf '%s\n' "$BIP_REFERENCED" | grep -c .)
# BIP_COUNT (the headline number) is computed from BIP_GROUP further down,
# which represents BIPs we actively implement — not just mention.

if [ "$TOTAL_LOC" -gt 0 ]; then
  COMMENT_DENSITY=$(awk -v c="$COMMENT_LINES" -v t="$TOTAL_LOC" 'BEGIN{ printf "%.2f", (c*100)/t }')
else
  COMMENT_DENSITY="0.00"
fi

# ---------- git stats ----------
COMMITS=$(git rev-list --count HEAD 2>/dev/null || echo 0)
FIRST_COMMIT=$(git log --reverse --format='%ad' --date=short 2>/dev/null | head -n1)
LAST_COMMIT=$(git log -1 --format='%ad' --date=short 2>/dev/null)
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
HEAD_SHA=$(git rev-parse --short HEAD 2>/dev/null)
DIRTY=""
if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
  DIRTY=" ${C_RED}*dirty${C_RESET}"
fi

# Aggregate ins/del across history.
GIT_STATS=$(git log --shortstat --format='' 2>/dev/null \
  | awk '/files? changed/ {
      for (i=1;i<=NF;i++){
        if ($i ~ /insertion/) ins+=$(i-1);
        if ($i ~ /deletion/)  del+=$(i-1);
        if ($i ~ /file/)       files+=$(i-1);
      }
    } END { printf "%d %d %d", files+0, ins+0, del+0 }')
GIT_FILES=$(echo "$GIT_STATS" | awk '{print $1}')
GIT_INS=$(echo "$GIT_STATS" | awk '{print $2}')
GIT_DEL=$(echo "$GIT_STATS" | awk '{print $3}')
GIT_NET=$(( GIT_INS - GIT_DEL ))

# Span in days.
if [ -n "$FIRST_COMMIT" ] && [ -n "$LAST_COMMIT" ]; then
  if date -d "$FIRST_COMMIT" +%s >/dev/null 2>&1; then
    START_S=$(date -d "$FIRST_COMMIT" +%s)
    END_S=$(date -d "$LAST_COMMIT" +%s)
  else
    # BSD/macOS date
    START_S=$(date -j -f '%Y-%m-%d' "$FIRST_COMMIT" +%s 2>/dev/null || echo 0)
    END_S=$(date -j -f '%Y-%m-%d' "$LAST_COMMIT" +%s 2>/dev/null || echo 0)
  fi
  SPAN_DAYS=$(( (END_S - START_S) / 86400 ))
  [ "$SPAN_DAYS" -lt 1 ] && SPAN_DAYS=1
else
  SPAN_DAYS=1
fi
AVG_PER_DAY=$(( COMMITS / SPAN_DAYS ))
PEAK_DAY=$(git log --format='%ad' --date=short 2>/dev/null | sort | uniq -c | sort -rn | head -n1)
PEAK_COUNT=$(echo "$PEAK_DAY" | awk '{print $1}')
PEAK_DATE=$(echo "$PEAK_DAY" | awk '{print $2}')

# ---------- live RPC probe (best-effort) ----------
RPC_OK=0
SYNC_HEIGHT="-"; SYNC_HEADERS="-"; PEERS="-"; MEMPOOL="-"; DIFFICULTY="-"
NET_NAME="-"; IBD="-"; CHAIN_SIZE="-"; UPTIME_S="-"; PROGRESS_PCT="0"
if [ "$USE_RPC" = 1 ] && command -v curl >/dev/null 2>&1; then
  rpc_call() {
    local method="$1" params="${2:-[]}"
    curl -fsS --max-time 2 -H 'Content-Type: application/json' \
      -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
      "$RPC_URL" 2>/dev/null
  }
  CHAIN_INFO=$(rpc_call getblockchaininfo)
  if [ -n "$CHAIN_INFO" ]; then
    RPC_OK=1
    extract() { echo "$CHAIN_INFO" | grep -oE "\"$1\"[[:space:]]*:[[:space:]]*[^,}]*" | head -n1 | sed -E "s/.*: *\"?([^\"]*)\"?$/\1/"; }
    SYNC_HEIGHT=$(extract blocks)
    SYNC_HEADERS=$(extract headers)
    NET_NAME=$(extract chain)
    IBD=$(extract initialblockdownload)
    [ -z "$IBD" ] && IBD="false"
    DIFFICULTY=$(extract difficulty)
    PROG=$(extract verificationprogress)
    [ -n "$PROG" ] && PROGRESS_PCT=$(awk -v p="$PROG" 'BEGIN{ printf "%.2f", p*100 }')
    PEERS_RAW=$(rpc_call getconnectioncount); PEERS=$(echo "$PEERS_RAW" | grep -oE '"result":[^,}]*' | sed -E 's/.*: *([0-9]+).*/\1/')
    MP_RAW=$(rpc_call getmempoolinfo)
    if [ -n "$MP_RAW" ]; then
      MEMPOOL=$(echo "$MP_RAW" | grep -oE '"size"[[:space:]]*:[[:space:]]*[0-9]+' | head -n1 | grep -oE '[0-9]+')
    fi
    UP_RAW=$(rpc_call uptime)
    UPTIME_S=$(echo "$UP_RAW" | grep -oE '"result":[^,}]*' | sed -E 's/.*: *([0-9]+).*/\1/')
  fi
fi

# Rough on-disk size of the data dir + separate blocksdir (if any).
CHAIN_SIZE="-"
DATADIR_SIZE="-"
BLOCKSDIR_SIZE="-"
_datadir=""
for _dd in /data/BitcoinPR "$HOME/.bitcoinpr"; do
  if [ -d "$_dd" ]; then
    _datadir="$_dd"
    break
  fi
done
if [ -n "$_datadir" ]; then
  DATADIR_SIZE=$(du -sh "$_datadir" 2>/dev/null | awk '{print $1}')
  _total_bytes=$(du -sb "$_datadir" 2>/dev/null | awk '{print $1}')

  # Detect a separate blocksdir: first check the running process for --blocksdir,
  # then fall back to the node's persisted blocksdir.conf pointer (written inside
  # <net_dir>/ whenever --blocksdir or --migrateblocks relocated block storage, so
  # the location survives a restart without the flag — a single absolute path).
  _ext_blocksdir=""
  _proc_args=$(pgrep -a bitcoinprd 2>/dev/null | head -1)
  if echo "$_proc_args" | grep -qoE '\-\-blocksdir[= ][^ ]+'; then
    _ext_blocksdir=$(echo "$_proc_args" | grep -oE '\-\-blocksdir[= ][^ ]+' | sed -E 's/--blocksdir[= ]//')
  else
    _pointer=$(find "$_datadir" -maxdepth 2 -name blocksdir.conf -type f 2>/dev/null | head -1)
    if [ -n "$_pointer" ]; then
      _saved=$(tr -d '[:space:]' < "$_pointer" 2>/dev/null)
      [ -n "$_saved" ] && [ -d "$_saved" ] && _ext_blocksdir="$_saved"
    fi
  fi

  if [ -n "$_ext_blocksdir" ] && [ -d "$_ext_blocksdir" ]; then
    BLOCKSDIR_SIZE=$(du -sh "$_ext_blocksdir" 2>/dev/null | awk '{print $1}')
    _blk_bytes=$(du -sb "$_ext_blocksdir" 2>/dev/null | awk '{print $1}')
    _sum=$(( _total_bytes + _blk_bytes ))
    # Human-readable combined size.
    if [ "$_sum" -ge 1073741824 ]; then
      CHAIN_SIZE=$(awk -v b="$_sum" 'BEGIN{ printf "%.1fG", b/1073741824 }')
    else
      CHAIN_SIZE=$(awk -v b="$_sum" 'BEGIN{ printf "%.0fM", b/1048576 }')
    fi
  else
    CHAIN_SIZE="$DATADIR_SIZE"
  fi
fi

human_uptime() {
  local s="$1"
  if ! echo "$s" | grep -qE '^[0-9]+$'; then echo "-"; return; fi
  local d=$((s/86400)) h=$(( (s%86400)/3600 )) m=$(( (s%3600)/60 ))
  printf '%dd %02dh %02dm' "$d" "$h" "$m"
}
UPTIME_HUMAN=$(human_uptime "$UPTIME_S")

# ---------- readiness scoring (heuristic) ----------
# L1 = consensus + storage parity; L2 = networking + indexing; L3 = mining decentralisation.
# Pull the rough %s from TODO.md headers + crate weights.
L1_PCT=88   # consensus + storage parity; BIP-110 RDTS + assume-valid + reorgs done
L2_PCT=70   # P2P + indexing done; Tor/I2P pending
L3_PCT=45   # Datum client + runtime mining config done; SV2 Noise handshake pending

# ---------- BIP coverage map ----------
# Group BIPs into rough categories for the grid.
declare -A BIP_GROUP
BIP_GROUP[meta]="8 9 14 90"
BIP_GROUP[pre-segwit]="16 30 34 62 65 66 68"
BIP_GROUP[segwit]="112 113 125 141 143 144 147"
BIP_GROUP[p2p-msg]="35 37 111 130 133 152 157 158 159 339"
BIP_GROUP[transport]="155 324 325"
BIP_GROUP[taproot]="340 341 342 350"
BIP_GROUP[softfork]="110"
BIP_GROUP[mining]="22 23 310"
BIP_ORDER="meta pre-segwit segwit p2p-msg transport taproot softfork mining"

# Headline count = unique BIPs across all implemented groups.
BIP_COUNT=$(for grp in $BIP_ORDER; do echo "${BIP_GROUP[$grp]}"; done \
  | tr ' ' '\n' | grep -c .)

# ---------- module weights (sorted by LOC desc) ----------
SORTED_CRATES=$(for c in $CRATES; do echo "${LOC_BY_CRATE[$c]} $c"; done | sort -rn)

# ---------- render ----------
clear_screen() { [ "$WATCH" = 1 ] && printf '\033[H\033[2J'; }

ROLE_bitcoinpr="daemon (CLI, event loop, signal handling)"
ROLE_bitcoinpr_core="consensus, validation, script, mempool"
ROLE_bitcoinpr_p2p="TCP wire protocol, peer mgmt, sync"
ROLE_bitcoinpr_storage="RocksDB indexes, blocks, UTXO set"
ROLE_bitcoinpr_rpc="JSON-RPC HTTP server (jsonrpsee)"
ROLE_bitcoinpr_mining="Stratum V1 + SV2 mining gateway"
ROLE_bitcoinpr_index="scripthash + Electrum TCP server"
ROLE_bitcoinpr_web="embedded explorer (Axum HTTP/WS)"

role_for() {
  case "$1" in
    bitcoinpr)         echo "$ROLE_bitcoinpr" ;;
    bitcoinpr-core)    echo "$ROLE_bitcoinpr_core" ;;
    bitcoinpr-p2p)     echo "$ROLE_bitcoinpr_p2p" ;;
    bitcoinpr-storage) echo "$ROLE_bitcoinpr_storage" ;;
    bitcoinpr-rpc)     echo "$ROLE_bitcoinpr_rpc" ;;
    bitcoinpr-mining)  echo "$ROLE_bitcoinpr_mining" ;;
    bitcoinpr-index)   echo "$ROLE_bitcoinpr_index" ;;
    bitcoinpr-web)     echo "$ROLE_bitcoinpr_web" ;;
  esac
}

render() {
  clear_screen

  hr
  printf "            ${C_BOLD}${C_ACCENT}BITCOINPR${C_RESET}  ${C_DIM}■${C_RESET}  ${C_FG}Pure Rust Bitcoin full node 0.1.110${C_RESET}  ${C_DIM}■${C_RESET}  ${C_FG}RocksDB + tokio${C_RESET}\n"
  hr

  # ----- HARNESS / ABOUT -----
  printf "\n"
  printf "  ${C_BOLD}HARNESS${C_RESET}  ${C_DIM}■${C_RESET}  cargo workspace  ${C_DIM}■${C_RESET}  rust-bitcoin 0.32  ${C_DIM}■${C_RESET}  rocksdb 0.24  ${C_DIM}■${C_RESET}  jsonrpsee 0.24\n"
  printf "    Full-validating node (legacy + SegWit + Tapscript), headers-first IBD, RocksDB,\n"
  printf "    Core-compatible JSON-RPC, Stratum V1/SV2 mining, full Electrum server (TCP),\n"
  printf "    and an embedded block explorer. No local wallet support, so it can't delete yours.\n"
  printf "\n"

  hr

  # ----- BIG ASCII TITLE -----
  printf "\n"
  printf "${C_BOLD}${C_ACCENT}"
  cat <<'TITLE'
              █████      ███   █████                       ███             ███████████
             ▒▒███      ▒▒▒   ▒▒███                       ▒▒▒             ▒▒███▒▒▒▒▒███
              ▒███████  ████  ███████    ██████   ██████  ████  ████████   ▒███    ▒███
              ▒███▒▒███▒▒███ ▒▒▒███▒    ███▒▒███ ███▒▒███▒▒███ ▒▒███▒▒███  ▒██████████
              ▒███ ▒███ ▒███   ▒███    ▒███ ▒▒▒ ▒███ ▒███ ▒███  ▒███ ▒███  ▒███▒▒▒▒▒███
              ▒███ ▒███ ▒███   ▒███ ███▒███  ███▒███ ▒███ ▒███  ▒███ ▒███  ▒███    ▒███
              ████████  █████  ▒▒█████ ▒▒██████ ▒▒██████  █████ ████ █████ █████   █████
             ▒▒▒▒▒▒▒▒  ▒▒▒▒▒    ▒▒▒▒▒   ▒▒▒▒▒▒   ▒▒▒▒▒▒  ▒▒▒▒▒ ▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒   ▒▒▒▒▒
TITLE
  printf "${C_RESET}"
  printf "\n"
  hr

  # ----- MODULE TABLE -----
  printf "\n"
  printf "  ${C_BOLD}%-18s %8s %6s   %-20s   %s${C_RESET}\n" "MODULE" "LOC" "FILES" "WEIGHT" "ROLE"
  while read -r loc crate; do
    [ -z "$crate" ] && continue
    files=${FILES_BY_CRATE[$crate]}
    role=$(role_for "$crate")
    pretty_loc=$(printf "%'d" "$loc" 2>/dev/null || echo "$loc")
    printf "  %-18s %8s %6s   %s   %s\n" \
      "$crate" "$pretty_loc" "$files" "$(bar "$loc" "$MAX_LOC" 20)" "$role"
  done <<< "$SORTED_CRATES"
  printf "  ${C_DIM}%-18s %8s %6s${C_RESET}\n" "TOTAL" "$(printf "%'d" "$TOTAL_LOC" 2>/dev/null || echo "$TOTAL_LOC")" "$TOTAL_FILES"
  printf "\n"

  hr

  # ----- BIP COVERAGE -----
  printf "\n"
  printf "  ${C_BOLD}BIP COVERAGE${C_RESET}   ${C_DIM}■${C_RESET}   $BIP_COUNT BIPs implemented   ${C_DIM}($BIP_REF_COUNT referenced incl. roadmap)${C_RESET}\n"
  for grp in $BIP_ORDER; do
    label=$(printf "%-12s" "$grp")
    printf "    ${C_DIM}%s${C_RESET}  " "$label"
    for n in ${BIP_GROUP[$grp]}; do
      printf "${C_ACCENT}%4s${C_RESET}" "$n"
    done
    printf "\n"
  done
  printf "\n"

  hr

  # ----- LIVE STATUS -----
  printf "\n"
  if [ "$RPC_OK" = 1 ]; then
    printf "  ${C_BOLD}STATUS${C_RESET}     ${C_GREEN}live binary${C_RESET}  $NET_NAME  ${C_DIM}■${C_RESET}  uptime $UPTIME_HUMAN  ${C_DIM}■${C_RESET}  rpc $RPC_URL\n"
    printf "             tip          h=%s / headers=%s   IBD=%s   diff=%s\n" \
      "$SYNC_HEIGHT" "$SYNC_HEADERS" "$IBD" "$DIFFICULTY"
    if [ "$BLOCKSDIR_SIZE" != "-" ]; then
      printf "             peers        %-6s   mempool %s tx   disk %s ${C_DIM}(datadir %s + blocks %s)${C_RESET}\n" \
        "$PEERS" "$MEMPOOL" "$CHAIN_SIZE" "$DATADIR_SIZE" "$BLOCKSDIR_SIZE"
    else
      printf "             peers        %-6s   mempool %s tx   chain on disk %s\n" \
        "$PEERS" "$MEMPOOL" "$CHAIN_SIZE"
    fi
    # Sync progress bar.
    pct_int=$(printf "%.0f" "$PROGRESS_PCT" 2>/dev/null || echo 0)
    printf "             sync         %s  %s%%\n" "$(bar "$pct_int" 100 40)" "$PROGRESS_PCT"
  else
    printf "  ${C_BOLD}STATUS${C_RESET}     ${C_DIM}no live node detected at${C_RESET} $RPC_URL\n"
    printf "             start one with:  ${C_BLUE}cargo run --release -- --network signet${C_RESET}\n"
    printf "             or pass:         ${C_BLUE}--rpc http://user:pass@host:port${C_RESET}\n"
  fi
  printf "\n"
  printf "             ${C_BOLD}L1 readiness${C_RESET}  consensus + storage    %s  %s%%\n" "$(bar "$L1_PCT" 100 30)" "$L1_PCT"
  printf "             ${C_BOLD}L2 readiness${C_RESET}  networking + indexing  %s  %s%%\n" "$(bar "$L2_PCT" 100 30)" "$L2_PCT"
  printf "             ${C_BOLD}L3 readiness${C_RESET}  mining decentralise    %s  %s%%\n" "$(bar "$L3_PCT" 100 30)" "$L3_PCT"
  printf "\n"

  hr

  # ----- GIT -----
  printf "\n"
  printf "  ${C_BOLD}GIT${C_RESET}  %s@%s%s  ${C_DIM}■${C_RESET}  %s commits / %s days (%s/day, peak %s)\n" \
    "$BRANCH" "$HEAD_SHA" "$DIRTY" "$COMMITS" "$SPAN_DAYS" "$AVG_PER_DAY" "$PEAK_COUNT"
  printf "       +%s/-%s (+%s net)  ${C_DIM}■${C_RESET}  %s LOC  ${C_DIM}■${C_RESET}  %s files  ${C_DIM}■${C_RESET}  %s tests  ${C_DIM}■${C_RESET}  %s pub fns\n" \
    "$GIT_INS" "$GIT_DEL" "$GIT_NET" \
    "$(printf "%'d" "$TOTAL_LOC" 2>/dev/null || echo "$TOTAL_LOC")" \
    "$TOTAL_FILES" "$TEST_COUNT" "$PUBFN_COUNT"
  printf "\n"
  hr
  printf "\n"
}

if [ "$WATCH" = 1 ]; then
  trap 'tput cnorm 2>/dev/null; exit 0' INT TERM
  tput civis 2>/dev/null
  while :; do
    render
    sleep "$WATCH_INTERVAL"
  done
else
  render
fi

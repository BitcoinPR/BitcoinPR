#!/usr/bin/env bash
# scripts/interop-dash.sh — Live TUI for the 6-node regtest interop cluster.
#
# Usage:
#   ./scripts/interop-dash.sh                  # one-shot render
#   ./scripts/interop-dash.sh --watch          # refresh every 5s
#   ./scripts/interop-dash.sh --watch 2        # refresh every 2s
#   ./scripts/interop-dash.sh --plain          # no ANSI colour
#
# Nodes monitored:
#   bitcoinpr1     RPC 127.0.0.1:18443  (miner · web :3000 · stratum :3333)
#   bitcoinpr2     RPC 127.0.0.1:28443  (validator)
#   bitcoin-core  RPC 127.0.0.1:38443
#   bitcoin-knots RPC 127.0.0.1:48443
#   btcd          RPC 127.0.0.1:58443  (Go sync node)
#   libbitcoin    ZMQ via bx inside interop-libbitcoin container

set -u

# ---------- arg parsing ----------
WATCH=0
WATCH_INTERVAL=5
COLOR=1

while [ $# -gt 0 ]; do
  case "$1" in
    --watch)
      WATCH=1
      if [ "${2-}" ] && printf '%s' "${2-}" | grep -qE '^[0-9]+$'; then
        WATCH_INTERVAL="$2"; shift
      fi
      ;;
    --plain)  COLOR=0 ;;
    -h|--help)
      sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) printf 'unknown flag: %s\n' "$1" >&2; exit 2 ;;
  esac
  shift
done

# ---------- colour ----------
if [ "$COLOR" = 1 ] && [ -t 1 ]; then
  C_RESET=$'\033[0m'
  C_DIM=$'\033[2m'
  C_BOLD=$'\033[1m'
  C_ACCENT=$'\033[38;5;214m'    # bitcoin orange
  C_GREEN=$'\033[38;5;46m'
  C_RED=$'\033[38;5;203m'
  C_YELLOW=$'\033[38;5;227m'
  C_BLUE=$'\033[38;5;75m'
  C_CYAN=$'\033[38;5;87m'
  C_FG=$'\033[38;5;255m'
else
  C_RESET=''; C_DIM=''; C_BOLD=''; C_ACCENT=''
  C_GREEN=''; C_RED=''; C_YELLOW=''; C_BLUE=''; C_CYAN=''; C_FG=''
fi

# ---------- cluster config ----------
RPC_r1="http://test:test@127.0.0.1:18443"
RPC_r2="http://test:test@127.0.0.1:28443"
RPC_bc="http://test:test@127.0.0.1:38443"
RPC_bk="http://test:test@127.0.0.1:48443"
RPC_bd="https://test:test@127.0.0.1:58443"
LB_CONTAINER="interop-libbitcoin"
LB_BX_CFG="/etc/libbitcoin/bx.cfg"

# ---------- helpers ----------
hr() {
  printf '%s\n' "${C_DIM} ₿· · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · · ·₿${C_RESET}"
}

section() {
  printf '\n  %s%s%s  %s%s%s\n' \
    "$C_BOLD" "$1" "$C_RESET" \
    "$C_DIM" "─────────────────────────────────────────────────────" "$C_RESET"
}

# Print a value with color, padded to $width visible chars.
col() {
  local color="$1" val="$2" width="$3"
  local vlen=${#val}
  local pad=$(( width - vlen ))
  [ "$pad" -lt 0 ] && pad=0
  printf '%s%s%s%*s' "$color" "$val" "$C_RESET" "$pad" ''
}

rpc_call() {
  local url="$1" method="$2" params="${3:-[]}"
  curl -fsSk --max-time 3 -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
    "$url" 2>/dev/null
}

# Parse a field from getblockchaininfo result dict; booleans are lowercased.
chain_field() {
  local json="$1" field="$2"
  printf '%s' "$json" | python3 -c \
    "import sys,json; d=json.load(sys.stdin).get('result',{}); v=d.get('$field',''); print(str(v).lower() if isinstance(v,bool) else v)" \
    2>/dev/null || printf ''
}

# Parse scalar result (getblockcount, getconnectioncount, uptime, etc.)
scalar_result() {
  printf '%s' "$1" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); r=d.get('result'); print('' if r is None else r)" \
    2>/dev/null || printf ''
}

# Probe one JSON-RPC node; writes one line: "height headers peers ibd diff mempool uptime tip"
probe_rpc() {
  local url="$1"
  local ci height headers peers ibd diff mempool uptime tip

  ci=$(rpc_call "$url" "getblockchaininfo")
  if [ -z "$ci" ] || ! printf '%s' "$ci" | grep -q '"result"'; then
    printf 'DOWN - - - - - - -\n'
    return
  fi

  height=$(chain_field "$ci" "blocks")
  headers=$(chain_field "$ci" "headers")
  ibd=$(chain_field "$ci" "initialblockdownload")
  tip=$(chain_field "$ci" "bestblockhash")
  diff=$(printf '%s' "$ci" | python3 -c \
    "import sys,json; d=json.load(sys.stdin).get('result',{}); v=d.get('difficulty',0); print(f'{float(v):.4e}')" \
    2>/dev/null || printf '-')

  local pr mr ur
  pr=$(rpc_call "$url" "getconnectioncount")
  peers=$(scalar_result "$pr")
  mr=$(rpc_call "$url" "getmempoolinfo")
  mempool=$(printf '%s' "$mr" | python3 -c \
    "import sys,json; d=json.load(sys.stdin).get('result',{}); print(d.get('size',''))" \
    2>/dev/null || printf '-')
  ur=$(rpc_call "$url" "uptime")
  uptime=$(scalar_result "$ur")

  [ -z "$height" ]  && height="-"
  [ -z "$headers" ] && headers="-"
  [ -z "$peers" ]   && peers="-"
  [ -z "$ibd" ]     && ibd="-"
  [ -z "$diff" ]    && diff="-"
  [ -z "$mempool" ] && mempool="-"
  [ -z "$uptime" ]  && uptime="-"
  [ -z "$tip" ]     && tip="-"

  printf 'UP %s %s %s %s %s %s %s %s\n' \
    "$height" "$headers" "$peers" "$ibd" "$diff" "$mempool" "$uptime" "$tip"
}

# Probe libbitcoin via bx; writes one line: "status height tip"
probe_lb() {
  local state
  state=$(docker inspect --format='{{.State.Status}}' "$LB_CONTAINER" 2>/dev/null || printf 'notfound')
  if [ "$state" != "running" ]; then
    printf 'DOWN - -\n'
    return
  fi

  local h
  h=$(docker exec "$LB_CONTAINER" bx fetch-height -c "$LB_BX_CFG" 2>/dev/null | tr -d '[:space:]' || printf '')
  if ! printf '%s' "$h" | grep -qE '^[0-9]+$'; then
    printf 'UP - -\n'
    return
  fi

  local tip
  tip=$(docker exec "$LB_CONTAINER" bx fetch-header --height "$h" -c "$LB_BX_CFG" 2>/dev/null \
    | awk '/^\s+hash /{print $2; exit}' || printf '')
  [ -z "$tip" ] && tip="-"
  printf 'UP %s %s\n' "$h" "$tip"
}

# Docker container state string.
container_state() {
  local name="$1"
  docker inspect --format='{{.State.Status}}{{if .State.Health}} ({{.State.Health.Status}}){{end}}' \
    "$name" 2>/dev/null || printf 'not found'
}

# Human-readable uptime from seconds.
human_uptime() {
  local s="$1"
  printf '%s' "$s" | grep -qE '^[0-9]+$' || { printf '-'; return; }
  local d=$((s/86400)) h=$(( (s%86400)/3600 )) m=$(( (s%3600)/60 ))
  printf '%dd %02dh %02dm' "$d" "$h" "$m"
}

# ---------- render ----------
render() {
  [ "$WATCH" = 1 ] && printf '\033[H\033[2J'

  local TS
  TS=$(date '+%Y-%m-%d %H:%M:%S')

  hr
  printf '  %sBITCOINPR INTEROP CLUSTER%s  %s■%s  %sregtest · 6 nodes%s  %s■%s  %s%s%s\n' \
    "${C_BOLD}${C_ACCENT}" "$C_RESET" \
    "$C_DIM" "$C_RESET" \
    "${C_FG}" "$C_RESET" \
    "$C_DIM" "$C_RESET" \
    "$C_DIM" "$TS" "$C_RESET"
  hr

  # ── parallel probes ──────────────────────────────────────────────────────
  local TMPD
  TMPD=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -rf '$TMPD'" EXIT INT TERM

  probe_rpc "$RPC_r1" > "$TMPD/r1" &
  probe_rpc "$RPC_r2" > "$TMPD/r2" &
  probe_rpc "$RPC_bc" > "$TMPD/bc" &
  probe_rpc "$RPC_bk" > "$TMPD/bk" &
  probe_rpc "$RPC_bd" > "$TMPD/bd" &
  probe_lb             > "$TMPD/lb" &
  wait

  # Parse results ─────────────────────────────────────────────────────────
  read -r r1_status r1_h r1_hdr r1_peers r1_ibd r1_diff r1_mp r1_up r1_tip \
    < "$TMPD/r1"
  read -r r2_status r2_h r2_hdr r2_peers r2_ibd r2_diff r2_mp r2_up r2_tip \
    < "$TMPD/r2"
  read -r bc_status bc_h bc_hdr bc_peers bc_ibd bc_diff bc_mp bc_up bc_tip \
    < "$TMPD/bc"
  read -r bk_status bk_h bk_hdr bk_peers bk_ibd bk_diff bk_mp bk_up bk_tip \
    < "$TMPD/bk"
  read -r bd_status bd_h bd_hdr bd_peers bd_ibd bd_diff bd_mp bd_up bd_tip \
    < "$TMPD/bd"
  read -r lb_status lb_h lb_tip \
    < "$TMPD/lb"

  rm -rf "$TMPD"
  # Re-arm trap for next render call in watch mode.
  trap 'tput cnorm 2>/dev/null; exit 0' INT TERM

  # ── node table ───────────────────────────────────────────────────────────
  section "NODES"
  printf '\n'
  printf '  %s%-18s  %-8s  %-8s  %-8s  %-6s  %-8s  %s%s\n' \
    "$C_BOLD" "NODE" "STATUS" "HEIGHT" "HEADERS" "PEERS" "IBD" "TIP HASH" "$C_RESET"
  printf '  %s%-18s  %-8s  %-8s  %-8s  %-6s  %-8s  %s%s\n' \
    "$C_DIM" \
    "──────────────────" "────────" "────────" "────────" "──────" "────────" \
    "────────────────────────" "$C_RESET"

  node_row() {
    local label="$1" status="$2" height="$3" headers="$4" peers="$5" ibd="$6" tip="$7"
    # Colored columns: embed trailing spaces to hit fixed visible width.
    # STATUS visible width = 8 chars ("UP"=2, "DOWN"=4).
    local sc ic td="—"
    if [ "$status" = "UP" ]; then
      sc="${C_GREEN}UP${C_RESET}      "
    else
      sc="${C_RED}DOWN${C_RESET}    "
    fi
    # IBD visible width = 8 chars.
    if   [ "$ibd" = "true" ];  then ic="${C_YELLOW}IBD${C_RESET}     "
    elif [ "$ibd" = "false" ]; then ic="${C_GREEN}synced${C_RESET}  "
    else                            ic="${C_DIM}—${C_RESET}       "
    fi
    if [ -n "$tip" ] && [ "$tip" != "-" ]; then td="${tip:0:24}…"; fi
    # %s for colored cols (width baked in); %-Ns for plain cols.
    printf '  %-18s  %s  %-8s  %-8s  %-6s  %s  %s\n' \
      "$label" "$sc" "$height" "$headers" "$peers" "$ic" "$td"
  }

  node_row "bitcoinpr1"    "$r1_status" "$r1_h" "$r1_hdr" "$r1_peers" "$r1_ibd" "$r1_tip"
  node_row "bitcoinpr2"    "$r2_status" "$r2_h" "$r2_hdr" "$r2_peers" "$r2_ibd" "$r2_tip"
  node_row "bitcoin-core" "$bc_status" "$bc_h" "$bc_hdr" "$bc_peers" "$bc_ibd" "$bc_tip"
  node_row "bitcoin-knots" "$bk_status" "$bk_h" "$bk_hdr" "$bk_peers" "$bk_ibd" "$bk_tip"
  node_row "btcd"         "$bd_status" "$bd_h" "$bd_hdr" "$bd_peers" "$bd_ibd" "$bd_tip"
  # libbitcoin: no headers/peers/ibd columns from bx
  node_row "libbitcoin"   "$lb_status" "$lb_h" "—"       "ZMQ"       "-"       "$lb_tip"

  printf '\n'

  # ── consensus indicator ──────────────────────────────────────────────────
  section "CONSENSUS"
  printf '\n'

  local up_heights="" up_tips="" down_count=0 up_count=0

  for _row in \
    "bitcoinpr1:$r1_status:$r1_h:$r1_tip" \
    "bitcoinpr2:$r2_status:$r2_h:$r2_tip" \
    "bitcoin-core:$bc_status:$bc_h:$bc_tip" \
    "bitcoin-knots:$bk_status:$bk_h:$bk_tip" \
    "btcd:$bd_status:$bd_h:$bd_tip" \
    "libbitcoin:$lb_status:$lb_h:$lb_tip"
  do
    local _node _st _height _tip
    IFS=':' read -r _node _st _height _tip <<< "$_row"
    if [ "$_st" = "UP" ] && [ "$_height" != "-" ] && [ "$_height" != "" ]; then
      up_count=$(( up_count + 1 ))
      up_heights="$up_heights $( printf '%s' "$_height" )"
      [ "$_tip" != "-" ] && up_tips="$up_tips $( printf '%s' "$_tip" )"
    else
      down_count=$(( down_count + 1 ))
    fi
  done

  local uniq_h uniq_t
  uniq_h=$(printf '%s\n' $up_heights | sort -u | grep -c .)
  uniq_t=$(printf '%s\n' $up_tips   | sort -u | grep -c .)

  if [ "$down_count" -gt 0 ] && [ "$up_count" -eq 0 ]; then
    printf '  %s✗  No nodes responding%s\n' "$C_RED$C_BOLD" "$C_RESET"
  elif [ "$uniq_h" -eq 1 ] && [ "$uniq_t" -le 1 ]; then
    local agree_h agree_t
    agree_h=$(printf '%s\n' $up_heights | sort -u)
    agree_t=$(printf '%s\n' $up_tips   | sort -u)
    printf '  %s✓  %d/%d nodes agree%s  height=%s%s%s  tip=%s%s…%s\n' \
      "${C_GREEN}${C_BOLD}" "$up_count" "$(( up_count + down_count ))" "$C_RESET" \
      "$C_ACCENT" "$agree_h" "$C_RESET" \
      "$C_DIM" "${agree_t:0:40}" "$C_RESET"
    [ "$down_count" -gt 0 ] && printf '  %s⚠  %d node(s) not responding%s\n' \
      "$C_YELLOW" "$down_count" "$C_RESET"
  else
    printf '  %s✗  CONSENSUS FAILURE — %d unique heights, %d unique tips%s\n' \
      "${C_RED}${C_BOLD}" "$uniq_h" "$uniq_t" "$C_RESET"
    for _row in \
      "bitcoinpr1:$r1_status:$r1_h:$r1_tip" \
      "bitcoinpr2:$r2_status:$r2_h:$r2_tip" \
      "bitcoin-core:$bc_status:$bc_h:$bc_tip" \
      "bitcoin-knots:$bk_status:$bk_h:$bk_tip" \
      "libbitcoin:$lb_status:$lb_h:$lb_tip"
    do
      IFS=':' read -r _node _st _height _tip <<< "$_row"
      printf '     %-18s  h=%-8s  %s…\n' "$_node" "$_height" "${_tip:0:24}"
    done
  fi
  printf '\n'

  # ── bitcoinpr1 extras ─────────────────────────────────────────────────────
  if [ "$r1_status" = "UP" ]; then
    section "BITCOINPR1  (miner · explorer · stratum · electrum)"
    printf '\n'

    local uptime_human
    uptime_human=$(human_uptime "$r1_up")

    # Check Stratum port (non-blocking).
    local stratum_ok="-"
    if nc -z -w1 127.0.0.1 3333 2>/dev/null; then
      stratum_ok="${C_GREEN}open${C_RESET}"
    else
      stratum_ok="${C_RED}closed${C_RESET}"
    fi

    # Check web explorer.
    local web_ok="-"
    if curl -fsS --max-time 2 http://127.0.0.1:3000/ -o /dev/null 2>/dev/null; then
      web_ok="${C_GREEN}up${C_RESET}"
    else
      web_ok="${C_RED}down${C_RESET}"
    fi

    # Check Electrum TCP.
    local elec_ok="-"
    if nc -z -w1 127.0.0.1 50001 2>/dev/null; then
      elec_ok="${C_GREEN}open${C_RESET}"
    else
      elec_ok="${C_RED}closed${C_RESET}"
    fi

    printf '  %-16s  %bhttp://127.0.0.1:3000%b\n' \
      "web explorer" "$C_BLUE" "$C_RESET"
    printf '  %-16s  ' "web status"
    printf '%b\n' "$web_ok"
    printf '  %-16s  %b127.0.0.1:3333%b  diff=%s%s%s\n' \
      "stratum" "$C_CYAN" "$C_RESET" "$C_ACCENT" "70000" "$C_RESET"
    printf '  %-16s  ' "stratum status"
    printf '%b\n' "$stratum_ok"
    printf '  %-16s  %b127.0.0.1:50001%b  (plain TCP)\n' \
      "electrum" "$C_CYAN" "$C_RESET"
    printf '  %-16s  ' "electrum status"
    printf '%b\n' "$elec_ok"
    printf '  %-16s  %s tx\n'   "mempool"    "$r1_mp"
    printf '  %-16s  %s\n'      "difficulty" "$r1_diff"
    printf '  %-16s  %s\n'      "uptime"     "$uptime_human"
    printf '\n'
  fi

  # ── docker status ────────────────────────────────────────────────────────
  section "CONTAINERS"
  printf '\n'
  for _cname in \
    interop-bitcoinpr1 \
    interop-bitcoinpr2 \
    interop-bitcoin-core \
    interop-bitcoin-knots \
    interop-btcd \
    interop-libbitcoin
  do
    local _state
    _state=$(container_state "$_cname")
    local _sc
    case "$_state" in
      running*) _sc="${C_GREEN}" ;;
      exited*|dead*|not\ found) _sc="${C_RED}" ;;
      *) _sc="${C_YELLOW}" ;;
    esac
    printf '  %-28s  %s%s%s\n' "$_cname" "$_sc" "$_state" "$C_RESET"
  done
  printf '\n'

  hr
  printf '\n'
}

# ---------- main ----------
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

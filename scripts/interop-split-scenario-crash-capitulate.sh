#!/usr/bin/env bash
#
# BIP-110 split scenario: crash (SIGKILL) around the capitulate call.
#
# `POST /api/split/capitulate` (bitcoinpr-web/src/api/split.rs) persists the
# abandon flag SYNCHRONOUSLY, before it ever sends the HTTP response —
# `header_index.set_bip110_abandoned()` is a single put_cf + explicit
# flush_wal (bitcoinpr-storage/src/header_index.rs), so by construction
# there is no "half-written" state at the storage layer: the flag is either
# durably there or it isn't. This scenario verifies that guarantee holds up
# against a hard `docker kill` (SIGKILL — no graceful-shutdown hooks run,
# unlike every other restart test in this suite which uses `docker restart`)
# fired at the two points that bracket the actual write:
#
#   Phase 1 — kill as close as possible to the capitulate call, without
#   waiting for its response. This is a genuine race: depending on exactly
#   when the kill lands relative to the internal flag write, the node comes
#   back EITHER not-abandoned-at-all (as if capitulate was never called) OR
#   fully-abandoned-and-converging. Both are safe; a corrupted in-between
#   state (e.g. flag set but markers not cleared) is not. The test branches
#   on the observed outcome and asserts full internal consistency for
#   whichever one occurred.
#
#   Phase 2 — wait for the capitulate response (`shutting_down: true`,
#   which per the code above means the flag write has already completed),
#   THEN kill -9 to interrupt the graceful self-shutdown itself instead of
#   letting it exit cleanly. This has one deterministic expected outcome:
#   the node must always come back fully abandoned and converged, exactly
#   as the graceful path would have.
#
# Gotcha found writing this: `docker kill` marks the container as
# intentionally stopped for restart-policy purposes — `restart:
# unless-stopped` does NOT auto-restart it (unlike a real crash/OOM kill),
# so both phases use the lib's `kill_and_restart_pr` helper, which kills
# and then explicitly `docker start`s it back up.
#
# Each phase runs against its own fresh cluster instance (torn down and
# rebuilt between them) so phase 2 always starts from a clean, still-armed
# split regardless of which way phase 1's race happened to land.
#
# Usage: ./scripts/interop-split-scenario-crash-capitulate.sh [--keep]

set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib/split-helpers.sh

KEEP=0
for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=1 ;;
        *) echo "unknown arg: $arg"; exit 2 ;;
    esac
done

CAP_URL="$WEB/api/split/capitulate"

# ─── Phase 1: kill as close as possible to the capitulate call ────────────

step "Phase 1: SIGKILL raced against the capitulate call itself"

setup_split
rival_h=$FORGED_HEIGHT
ours_h=$BASELINE
core_mine 5
rival_h=$((rival_h + 5))
wait_split_match "$rival_h" "$ours_h" 90 || fail "phase 1: monitor did not settle at rival=$rival_h ours=$ours_h"
[[ "$ARMED" == "True" ]] || fail "phase 1: armed='$ARMED' — expected True before attempting capitulation"
info "phase 1: armed at deficit $DEFICIT — firing capitulate and killing immediately"

curl -s --max-time 10 -X POST "$CAP_URL" \
    -H "Origin: $WEB" -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"confirm":"ABANDON-BIP110"}' >/tmp/split-crash-cap-phase1.json 2>&1 &
CAP_PID=$!
kill_and_restart_pr
wait "$CAP_PID" 2>/dev/null || true

wait_rpc "$PR_RPC" 90 || fail "phase 1: split-bitcoinpr did not come back after SIGKILL"
ABANDONED=$(pr getchainsplitinfo | jget "['abandoned']")

if [[ "$ABANDONED" == "True" ]]; then
    info "phase 1: the kill landed AFTER the flag write — verifying full, consistent convergence"
    wait_height "$PR_RPC" "$rival_h" 90 || fail "phase 1: abandoned=True but did not converge to height $rival_h"
    MODE=$(pr getchainsplitinfo | jget "['bip110']['mode']")
    [[ "$MODE" == "abandoned" ]] || fail "phase 1: abandoned=True but mode='$MODE' — expected 'abandoned'"
    PR_TIP=$(pr getbestblockhash | result_of)
    CORE_TIP=$(core getbestblockhash | result_of)
    [[ "$PR_TIP" == "$CORE_TIP" ]] || fail "phase 1: abandoned=True but tips disagree (pr=$PR_TIP core=$CORE_TIP)"
    info "phase 1 outcome: capitulation completed despite the kill — fully converged, fully consistent"
else
    info "phase 1: the kill landed BEFORE the flag write — verifying nothing changed"
    wait_split_match "$rival_h" "$ours_h" 90 || fail "phase 1: not abandoned but split view did not resurface at rival=$rival_h ours=$ours_h"
    [[ "$ARMED" == "True" ]] || fail "phase 1: not abandoned but armed='$ARMED' — expected True (unchanged)"
    MODE=$(echo "$SPLIT_JSON" | jget "['bip110']['mode']")
    [[ "$MODE" == "fixed" ]] || fail "phase 1: not abandoned but mode='$MODE' — expected 'fixed' (unchanged)"
    pr_h_check=$(pr getblockcount | result_of)
    [[ "$pr_h_check" == "$ours_h" ]] || fail "phase 1: not abandoned but our height $pr_h_check != $ours_h"
    info "phase 1 outcome: capitulation did not take effect — split still fully intact and enforced, exactly as if never called"
fi

# Fresh cluster for phase 2, regardless of which way phase 1 landed.
teardown_split 0

# ─── Phase 2: kill after the capitulate response returns ──────────────────

step "Phase 2: SIGKILL after the capitulate response returns (deterministic)"

setup_split
rival_h=$FORGED_HEIGHT
ours_h=$BASELINE
core_mine 5
rival_h=$((rival_h + 5))
wait_split_match "$rival_h" "$ours_h" 90 || fail "phase 2: monitor did not settle at rival=$rival_h ours=$ours_h"
[[ "$ARMED" == "True" ]] || fail "phase 2: armed='$ARMED' — expected True before attempting capitulation"
info "phase 2: armed at deficit $DEFICIT — capitulating and waiting for the response"

CAP_RESP=$(curl -s --max-time 15 -X POST "$CAP_URL" \
    -H "Origin: $WEB" -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"confirm":"ABANDON-BIP110"}')
SHUTTING=$(echo "$CAP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('shutting_down',''))" 2>/dev/null || true)
[[ "$SHUTTING" == "True" ]] || fail "phase 2: capitulate response: $CAP_RESP"
info "phase 2: response confirms the flag is already durable — killing now, before the graceful shutdown finishes"

kill_and_restart_pr

wait_rpc "$PR_RPC" 90 || fail "phase 2: split-bitcoinpr did not come back after the forced kill"
ABANDONED=$(pr getchainsplitinfo | jget "['abandoned']")
[[ "$ABANDONED" == "True" ]] || fail "phase 2: abandoned='$ABANDONED' — expected True (flag was durable before the kill)"
wait_height "$PR_RPC" "$rival_h" 90 || fail "phase 2: did not converge to height $rival_h after the forced restart"
MODE=$(pr getchainsplitinfo | jget "['bip110']['mode']")
[[ "$MODE" == "abandoned" ]] || fail "phase 2: mode='$MODE' — expected 'abandoned'"
PR_TIP=$(pr getbestblockhash | result_of)
CORE_TIP=$(core getbestblockhash | result_of)
[[ "$PR_TIP" == "$CORE_TIP" ]] || fail "phase 2: tips disagree after forced restart (pr=$PR_TIP core=$CORE_TIP)"
info "phase 2 outcome: interrupting the graceful shutdown changed nothing — still fully abandoned and converged"

step "PASS"
teardown_split "$KEEP"
exit 0

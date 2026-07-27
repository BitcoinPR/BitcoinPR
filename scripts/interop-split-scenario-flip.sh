#!/usr/bin/env bash
#
# BIP-110 split scenario: the lead shrinks and re-widens repeatedly.
#
# interop-split-test.sh and interop-split-scenario-dominant.sh both only
# ever grow the rival's lead. capitulation_armed is recomputed fresh from
# the live block/work deficit on every snapshot (bitcoinpr-core/src/
# splitmon.rs, snapshot_against) — it is NOT sticky — so a rival lead that
# widens past the +6 threshold, shrinks back under it as we mine our own
# valid chain, then widens again must arm, DISARM, and re-arm correctly
# each time. This drives exactly that, plus a restart while DISARMED (the
# base test only ever restarts while armed, so that persistence path is
# otherwise untested).
#
# IMPORTANT design constraint, learned the hard way: split-core is a STOCK
# Bitcoin Core node with zero BIP-110 awareness. The forged block is only
# invalid under bitcoinpr's own rule — to Core it's a perfectly valid,
# non-standard-but-consensus-legal block, so Core just runs plain
# longest-valid-chain. If our own mined height ever reaches or passes
# Core's, Core will legitimately reorg onto OUR chain and the split
# collapses (this actually happened when this script first mined "ours"
# past "rival" to force a negative deficit — Core adopted our chain and
# round C's mining silently extended the now-merged chain instead of the
# tainted one). So this scenario keeps `ours` strictly behind `rival` at
# every step: the "flip" is the deficit crossing the +6 threshold in both
# directions, never ours catching up in raw height.
#
# Deficit trajectory (rival.height - ours.height), starting at 1:
#   A: core+8  -> deficit  9  (armed)
#   B: pr+5    -> deficit  4  (disarm #1 — lead shrinks under threshold)
#   C: core+5  -> deficit  9  (re-arm #1)
#   D: pr+6    -> deficit  3  (disarm #2)
#   [restart split-bitcoinpr here, while disarmed but rival still ahead]
#   E: core+10 -> deficit 13  (re-arm #2, final)
#
# Usage: ./scripts/interop-split-scenario-flip.sh [--keep] [--capitulate]

set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib/split-helpers.sh

KEEP=0
CAPITULATE=0
for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=1 ;;
        --capitulate) CAPITULATE=1 ;;
        *) echo "unknown arg: $arg"; exit 2 ;;
    esac
done

setup_split

rival_h=$FORGED_HEIGHT
ours_h=$BASELINE

assert_round() {  # label expect_armed
    local label="$1" expect_armed="$2"
    (( rival_h > ours_h )) || fail "$label: test design invariant broken — rival ($rival_h) must stay ahead of ours ($ours_h) or Core will reorg onto our chain"
    wait_split_match "$rival_h" "$ours_h" 90 || fail "$label: monitor did not settle at rival=$rival_h ours=$ours_h"
    [[ "$FORK_H" == "$BASELINE" ]] || fail "$label: fork_height moved to $FORK_H — expected $BASELINE (a flip must never move the fork point)"
    (( DEFICIT == rival_h - ours_h )) || fail "$label: deficit $DEFICIT != $((rival_h - ours_h))"
    [[ "$ARMED" == "$expect_armed" ]] || fail "$label: armed='$ARMED' expected '$expect_armed' at deficit $DEFICIT"
    local pr_h_check core_h_check
    pr_h_check=$(pr getblockcount | result_of)
    core_h_check=$(core getblockcount | result_of)
    [[ "$pr_h_check" == "$ours_h" ]] || fail "$label: pr getblockcount $pr_h_check != $ours_h — node unresponsive or wedged"
    [[ "$core_h_check" == "$rival_h" ]] || fail "$label: core getblockcount $core_h_check != $rival_h — Core reorged (test design broken, or a real taint-gate bypass)"
    info "$label: rival=$rival_h ours=$ours_h deficit=$DEFICIT armed=$ARMED"
}

step "A. Core's lead widens past the threshold — arms"
core_mine 8; rival_h=$((rival_h + 8))
assert_round "round A" "True"

step "B. We mine our own valid chain and narrow the gap — disarms"
pr_mine 5; ours_h=$((ours_h + 5))
assert_round "round B" "False"

step "C. Core widens the lead again — re-arms"
core_mine 5; rival_h=$((rival_h + 5))
assert_round "round C" "True"

step "D. We narrow the gap a second time — disarms"
pr_mine 6; ours_h=$((ours_h + 6))
assert_round "round D" "False"

step "Restart split-bitcoinpr while DISARMED (untested by the base test)"
docker restart split-bitcoinpr >/dev/null
wait_rpc "$PR_RPC" 120 || fail "node did not come back after mid-flip restart"
# No new blocks are mined across the restart — the picture must come back
# exactly as it was, disarmed, from persisted rival tips alone.
assert_round "post-restart" "False"
info "disarmed split state survived a restart correctly (no false re-arm)"

step "E. Core makes a final decisive push — re-arms for good"
core_mine 10; rival_h=$((rival_h + 10))
assert_round "round E" "True"

info "PASS: capitulation armed/disarmed/re-armed in step with the live deficit across 5 lead changes"

if (( CAPITULATE )); then
    capitulate_and_converge
fi

step "PASS"
teardown_split "$KEEP"
exit 0

#!/usr/bin/env bash
#
# BIP-110 split scenario: prolonged stalemate — neither side pulls ahead.
#
# Long-run soak: 17 repeats of a 6-round mining cycle (102 rounds total)
# that nets to zero, keeping the rival/ours deficit oscillating in a narrow
# band ([1, 3]) around the post-fork baseline and never anywhere near the
# +/-6 capitulation threshold. This is the "long period of uncertainty"
# case — nothing here should ever arm, the fork point must never move, and
# the node must stay fully responsive at every single round, not just at
# checkpoints. A mid-soak restart proves the persisted-rival-tip path holds
# up under a contested-but-not-armed state, and a final decisive breakout +
# catch-up at the end proves the monitor's block/work arithmetic hasn't
# drifted after 100+ rounds of small updates.
#
# IMPORTANT design constraint (see interop-split-scenario-flip.sh for the
# full story): split-core is a stock Bitcoin Core node with zero BIP-110
# awareness, so if our own mined height ever reaches or passes Core's,
# Core legitimately reorgs onto our (longer, and by ITS rules perfectly
# valid) chain and the split collapses. Every round below keeps `ours`
# strictly behind `rival` — deficit never touches 0.
#
# Cycle (core_inc, pr_inc) -> deficit delta:
#   (2,0)->+2  (0,1)->-1  (1,0)->+1  (0,2)->-2  (2,0)->+2  (0,2)->-2
# Net 0 per cycle; deficit returns to exactly the baseline (1) at every
# cycle boundary — a clean drift check run 17 times over.
#
# Usage: ./scripts/interop-split-scenario-stalemate.sh [--keep] [--cycles N]
#   --keep       leave the cluster running after a pass (implied on failure)
#   --cycles N   override the number of 6-round cycles (default 17, ~102 rounds)

set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib/split-helpers.sh

KEEP=0
NUM_CYCLES=17
while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep) KEEP=1; shift ;;
        --cycles) NUM_CYCLES="$2"; shift 2 ;;
        *) echo "unknown arg: $1"; exit 2 ;;
    esac
done
RESTART_AFTER_CYCLE=$((NUM_CYCLES / 2))
(( RESTART_AFTER_CYCLE > 0 )) || RESTART_AFTER_CYCLE=1

setup_split

rival_h=$FORGED_HEIGHT
ours_h=$BASELINE
BASELINE_DEFICIT=$((rival_h - ours_h))   # 1

CORE_STEP=(2 0 1 0 2 0)
PR_STEP=(0 1 0 2 0 2)

step "Stalemate soak — $NUM_CYCLES cycles x ${#CORE_STEP[@]} rounds (~$((NUM_CYCLES * ${#CORE_STEP[@]})) rounds total)"

round_total=0
for (( cyc=1; cyc<=NUM_CYCLES; cyc++ )); do
    for s in "${!CORE_STEP[@]}"; do
        round_total=$((round_total + 1))
        c_inc=${CORE_STEP[$s]}
        p_inc=${PR_STEP[$s]}
        (( c_inc > 0 )) && core_mine "$c_inc"
        (( p_inc > 0 )) && pr_mine "$p_inc"
        rival_h=$((rival_h + c_inc))
        ours_h=$((ours_h + p_inc))
        (( rival_h > ours_h )) || fail "round $round_total: test design invariant broken — rival ($rival_h) must stay ahead of ours ($ours_h) or Core will reorg onto our chain"

        # Cheap per-round liveness probe (no monitor-tick wait): both nodes'
        # own chain heights must reflect what we just mined, every single
        # round, across the whole soak — this is the actual "stays
        # responsive under prolonged uncertainty" assertion.
        pr_h_check=$(pr getblockcount | result_of)
        core_h_check=$(core getblockcount | result_of)
        [[ "$pr_h_check" == "$ours_h" ]] || fail "round $round_total: pr getblockcount $pr_h_check != $ours_h — node unresponsive or wedged mid-soak"
        [[ "$core_h_check" == "$rival_h" ]] || fail "round $round_total: core getblockcount $core_h_check != $rival_h"
    done

    # Cycle boundary: let the monitor's (lagged) view catch up and check
    # the full picture — this is where drift or a spurious arm would show.
    wait_split_match "$rival_h" "$ours_h" 60 || fail "cycle $cyc: monitor did not settle at rival=$rival_h ours=$ours_h"
    [[ "$FORK_H" == "$BASELINE" ]] || fail "cycle $cyc: fork_height moved to $FORK_H — expected $BASELINE"
    (( DEFICIT == BASELINE_DEFICIT )) || fail "cycle $cyc: deficit $DEFICIT != baseline $BASELINE_DEFICIT — arithmetic drift after $round_total rounds"
    [[ "$ARMED" == "False" ]] || fail "cycle $cyc: armed='$ARMED' — must never arm during a bounded stalemate"
    info "cycle $cyc/$NUM_CYCLES ($round_total rounds so far): deficit back to baseline $DEFICIT, armed=$ARMED, fork stable"

    if (( cyc == RESTART_AFTER_CYCLE )); then
        step "Mid-soak restart at cycle $cyc (contested but never armed)"
        docker restart split-bitcoinpr >/dev/null
        wait_rpc "$PR_RPC" 120 || fail "node did not come back after mid-soak restart"
        wait_split_match "$rival_h" "$ours_h" 60 || fail "post-restart: split view did not resurface at rival=$rival_h ours=$ours_h"
        [[ "$FORK_H" == "$BASELINE" ]] || fail "post-restart: fork_height $FORK_H != $BASELINE"
        (( DEFICIT == BASELINE_DEFICIT )) || fail "post-restart: deficit $DEFICIT != baseline $BASELINE_DEFICIT"
        [[ "$ARMED" == "False" ]] || fail "post-restart: armed='$ARMED' — expected False"
        info "mid-soak restart: contested-but-unarmed state survived correctly"
    fi
done

info "PASS: $round_total rounds, deficit never left the baseline band, capitulation never armed, no wedge"

step "Decisive breakout after the soak — proves arming still works after $round_total rounds"
core_mine 10
rival_h=$((rival_h + 10))
wait_split_match "$rival_h" "$ours_h" 90 || fail "breakout: monitor did not settle at rival=$rival_h ours=$ours_h"
[[ "$ARMED" == "True" ]] || fail "breakout: armed='$ARMED' — expected True at deficit $DEFICIT"
info "breakout: deficit=$DEFICIT armed=$ARMED — arming still correct post-soak"

step "Catch-up after the soak — proves disarming still works after $round_total rounds"
# Narrow the gap well under the threshold WITHOUT letting ours reach rival
# (see the design-constraint note at the top of this file).
catchup=$((DEFICIT - 3))
(( catchup > 0 && catchup < DEFICIT )) || fail "catch-up: bad catchup amount $catchup for deficit $DEFICIT"
pr_mine "$catchup"
ours_h=$((ours_h + catchup))
(( rival_h > ours_h )) || fail "catch-up: test design invariant broken — rival ($rival_h) must stay ahead of ours ($ours_h)"
wait_split_match "$rival_h" "$ours_h" 90 || fail "catch-up: monitor did not settle at rival=$rival_h ours=$ours_h"
[[ "$ARMED" == "False" ]] || fail "catch-up: armed='$ARMED' — expected False at deficit $DEFICIT"
(( DEFICIT == 3 )) || fail "catch-up: expected deficit 3, got $DEFICIT"
info "catch-up: deficit=$DEFICIT armed=$ARMED — disarming still correct post-soak"

step "PASS"
teardown_split "$KEEP"
exit 0

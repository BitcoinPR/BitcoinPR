#!/usr/bin/env bash
#
# BIP-110 split scenario: sustained rival dominance.
#
# Unlike interop-split-test.sh (which grows the rival lead to exactly +6 and
# immediately capitulates), this drives Core's lead out much further and in
# growing increments while our node keeps mining its own (losing) chain in
# parallel. It asserts the invariant the base test never exercises: once
# capitulation arms, it STAYS armed as a dominant rival lead only grows —
# it must never spuriously flap back to unarmed — and the node stays fully
# responsive (RPC live, still mining) the whole time it's buried under a
# widening deficit.
#
# Round schedule (rival vs. ours increments per round): 3/1, 4/1, 6/1, 8/1,
# 10/1, 12/1 — deficit grows 3, 6, 11, 18, 27, 38. Crosses the +6 threshold
# at round 2 and never comes back down.
#
# Usage: ./scripts/interop-split-scenario-dominant.sh [--keep] [--capitulate]
#   --keep         leave the cluster running after a pass (implied on failure)
#   --capitulate   run the abandon-minority-chain flow at the end, proving
#                  convergence still works after a much larger deficit than
#                  the base test ever reaches

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

# rival_h / ours_h track the EXPECTED heights (we control every block mined,
# so we can assert exact convergence each round rather than just polling
# until something looks plausible).
rival_h=$FORGED_HEIGHT
ours_h=$BASELINE
prev_deficit=1
armed_seen=0

CORE_INCS=(3 4 6 8 10 12)
PR_INCS=(1 1 1 1 1 1)

step "Sustained dominance — ${#CORE_INCS[@]} rounds of a widening rival lead"

for i in "${!CORE_INCS[@]}"; do
    round=$((i + 1))
    c_inc=${CORE_INCS[$i]}
    p_inc=${PR_INCS[$i]}

    core_mine "$c_inc"
    pr_mine "$p_inc"
    rival_h=$((rival_h + c_inc))
    ours_h=$((ours_h + p_inc))

    wait_split_match "$rival_h" "$ours_h" 90 || fail "round $round: monitor did not settle at rival=$rival_h ours=$ours_h"

    [[ "$FORK_H" == "$BASELINE" ]] || fail "round $round: fork_height moved to $FORK_H — expected $BASELINE"
    (( DEFICIT == rival_h - ours_h )) || fail "round $round: deficit $DEFICIT != $((rival_h - ours_h))"
    (( DEFICIT > prev_deficit )) || fail "round $round: deficit $DEFICIT did not grow past previous $prev_deficit"

    if (( DEFICIT >= 6 )); then
        [[ "$ARMED" == "True" ]] || fail "round $round: deficit $DEFICIT >= 6 but armed=$ARMED (must never flap off once dominance is established)"
        armed_seen=1
    else
        [[ "$ARMED" == "False" ]] || fail "round $round: deficit $DEFICIT < 6 but armed=$ARMED"
    fi

    # Node must stay fully responsive under a growing deficit — not just
    # RPC-alive, but still willing to mine its own (losing) chain.
    pr_h_check=$(pr getblockcount | result_of)
    [[ "$pr_h_check" == "$ours_h" ]] || fail "round $round: pr getblockcount $pr_h_check != $ours_h — node unresponsive or wedged"

    info "round $round: rival=$rival_h ours=$ours_h deficit=$DEFICIT armed=$ARMED"
    prev_deficit=$DEFICIT
done

(( armed_seen )) || fail "capitulation never armed across the whole run"
info "PASS: deficit grew monotonically ($prev_deficit final), capitulation armed and stayed armed, node stayed responsive"

if (( CAPITULATE )); then
    capitulate_and_converge
fi

step "PASS"
teardown_split "$KEEP"
exit 0

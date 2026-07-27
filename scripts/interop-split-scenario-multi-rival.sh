#!/usr/bin/env bash
#
# BIP-110 split scenario: two independent tainted branches competing.
#
# Every other split scenario tracks exactly one rival branch that only ever
# grows. SplitMonitor::snapshot_against actually walks ALL tracked rival
# tips and reports whichever currently has the most work (bitcoinpr-core/
# src/splitmon.rs) — nothing in the test suite exercises more than one
# concurrent tainted branch, or the monitor switching which one it reports
# as "the" rival as their relative depths change. This does both, using
# Core's own `invalidateblock`/`reconsiderblock` to flip between two
# independently-forged invalid branches (A and B — same fork point,
# different OP_RETURN payload so they have different block hashes):
#
#   1. Branch A forms and grows to height 121 (5 blocks past the fork).
#   2. Core invalidates its own branch-A tip and forges an UNRELATED
#      branch B from the same fork point, growing it to height 123 (8
#      blocks past the fork — deeper than A). The monitor must now report
#      B as the live rival (more work) while still keeping A's old tip
#      tracked (for the status page) rather than discarding it.
#   3. Core invalidates branch B and reconsiders branch A, then extends A
#      to height 126 (11 blocks past the fork — deeper than B again). The
#      monitor must switch back to reporting A, including A's OWN
#      first-invalid marker, not B's.
#
# split-bitcoinpr's own chain never moves in this scenario (deficit stays
# strongly positive throughout) — this is purely about tracking two rival
# branches on the Core side, not about our own mining.
#
# Usage: ./scripts/interop-split-scenario-multi-rival.sh [--keep]

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

# Poll `core getblockcount` until it EQUALS (not just >=) target — needed
# for invalidateblock rollbacks, where the height goes DOWN.
wait_core_height_exact() {  # target timeout_s
    local target="$1" timeout="${2:-30}" waited=0 h
    while (( waited < timeout )); do
        h=$(core getblockcount | result_of)
        [[ "$h" == "$target" ]] && return 0
        sleep 2; waited=$((waited + 2))
    done
    return 1
}

setup_split

# ─── Branch A: the split established by setup_split, grown a bit ─────────

step "Branch A: grow the initial forged branch to a known depth"
FORGE_A_HASH=$FORGED_HASH
FORGE_A_HEIGHT=$FORGED_HEIGHT
core_mine 5
A_TIP_HEIGHT=$((FORGE_A_HEIGHT + 5))
wait_split_match "$A_TIP_HEIGHT" "$BASELINE" 90 || fail "branch A: monitor did not settle at rival=$A_TIP_HEIGHT"
[[ "$ARMED" == "True" ]] || fail "branch A: armed='$ARMED' — expected True at deficit $DEFICIT"
A_TIP_HASH=$(core getbestblockhash | result_of)
info "branch A at height $A_TIP_HEIGHT (tip $A_TIP_HASH), forged block $FORGE_A_HEIGHT ($FORGE_A_HASH)"

# ─── Branch B: an independent second invalid branch from the same fork ───

step "Branch B: invalidate A's tip on Core and forge a distinct second branch"
core invalidateblock "[\"$FORGE_A_HASH\"]" >/dev/null
wait_core_height_exact "$BASELINE" 30 || fail "Core did not roll back to $BASELINE after invalidating branch A"
info "Core rolled back to $BASELINE — branch A is now inactive on Core (but still stored on split-bitcoinpr)"

forge_invalid_block "bb" "$BASELINE"
FORGE_B_HASH=$FORGED_HASH
FORGE_B_HEIGHT=$FORGED_HEIGHT
[[ "$FORGE_B_HASH" != "$FORGE_A_HASH" ]] || fail "branch B forged the same hash as branch A — payload didn't differentiate"

core_mine 7
B_TIP_HEIGHT=$((FORGE_B_HEIGHT + 7))
wait_split_match "$B_TIP_HEIGHT" "$BASELINE" 90 || fail "branch B: monitor did not settle at rival=$B_TIP_HEIGHT"
[[ "$FORK_H" == "$BASELINE" ]] || fail "branch B: fork_height $FORK_H != $BASELINE"
[[ "$ARMED" == "True" ]] || fail "branch B: armed='$ARMED' — expected True at deficit $DEFICIT"
inv_hash=$(echo "$SPLIT_JSON" | jget "['split']['rival_first_invalid']['hash']")
inv_height=$(echo "$SPLIT_JSON" | jget "['split']['rival_first_invalid']['height']")
[[ "$inv_hash" == "$FORGE_B_HASH" ]] || fail "branch B should be the reported rival (more work) — first_invalid hash '$inv_hash' != B's '$FORGE_B_HASH'"
info "monitor correctly switched to branch B (height $B_TIP_HEIGHT, own invalid marker $inv_height/$inv_hash) — deeper than A's frozen tip at $A_TIP_HEIGHT"

# ─── Flip back: branch A reclaims the depth lead ──────────────────────────

step "Flip back: invalidate B, reconsider A, extend A past B's depth"
core invalidateblock "[\"$FORGE_B_HASH\"]" >/dev/null
wait_core_height_exact "$BASELINE" 30 || fail "Core did not roll back to $BASELINE after invalidating branch B"
core reconsiderblock "[\"$FORGE_A_HASH\"]" >/dev/null
wait_core_height_exact "$A_TIP_HEIGHT" 30 || fail "Core did not reactivate branch A up to $A_TIP_HEIGHT after reconsiderblock"
core_reactivated_tip=$(core getbestblockhash | result_of)
[[ "$core_reactivated_tip" == "$A_TIP_HASH" ]] || fail "reconsiderblock reactivated a different tip than branch A's original ($core_reactivated_tip != $A_TIP_HASH)"
info "Core reactivated branch A exactly as it left it (height $A_TIP_HEIGHT, tip $A_TIP_HASH)"

core_mine 5
A_TIP_HEIGHT=$((A_TIP_HEIGHT + 5))
wait_split_match "$A_TIP_HEIGHT" "$BASELINE" 90 || fail "branch A re-extension: monitor did not settle at rival=$A_TIP_HEIGHT"
[[ "$FORK_H" == "$BASELINE" ]] || fail "branch A re-extension: fork_height $FORK_H != $BASELINE"
[[ "$ARMED" == "True" ]] || fail "branch A re-extension: armed='$ARMED' — expected True at deficit $DEFICIT"
inv_hash=$(echo "$SPLIT_JSON" | jget "['split']['rival_first_invalid']['hash']")
inv_height=$(echo "$SPLIT_JSON" | jget "['split']['rival_first_invalid']['height']")
[[ "$inv_hash" == "$FORGE_A_HASH" ]] || fail "branch A should be the reported rival again (more work) — first_invalid hash '$inv_hash' != A's '$FORGE_A_HASH'"
(( A_TIP_HEIGHT > B_TIP_HEIGHT )) || fail "test design invariant broken — A ($A_TIP_HEIGHT) must end up deeper than B ($B_TIP_HEIGHT)"
info "monitor correctly switched back to branch A (height $A_TIP_HEIGHT, own invalid marker $inv_height/$inv_hash) — now deeper than B's frozen tip at $B_TIP_HEIGHT"

# ─── Our own chain was never touched by any of this ───────────────────────

step "Confirm our own validated chain was untouched throughout"
pr_h_check=$(pr getblockcount | result_of)
[[ "$pr_h_check" == "$BASELINE" ]] || fail "our own validated height $pr_h_check != $BASELINE — Core's internal chain gymnastics must never affect our chain"
info "our own chain stayed at $BASELINE throughout — taint gate held through both branches and both flips"

step "PASS"
teardown_split "$KEEP"
exit 0
